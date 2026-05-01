"""Flask application factory for Knuckles."""

from typing import Any

from flask import Flask, jsonify
from flask.wrappers import Response
from werkzeug.exceptions import HTTPException

from knuckles.api.v1 import api_v1
from knuckles.core.config import get_settings
from knuckles.core.database import init_db
from knuckles.core.exceptions import AppError
from knuckles.core.jwt import get_jwks
from knuckles.core.logging import get_logger, setup_logging
from knuckles.core.observability import (
    get_request_id,
    init_request_correlation,
    request_context,
)

# Browser caches and consuming-app JWKS clients should not refetch the
# key set on every token verification — but should refetch frequently
# enough that a key-rotation rolls out within minutes, not days. Ten
# minutes is the common-practice midpoint.
_JWKS_CACHE_MAX_AGE_SECONDS = 600


def create_app() -> Flask:
    """Create and configure the Knuckles Flask app.

    Returns:
        A fully configured ``Flask`` application instance.
    """
    settings = get_settings()

    setup_logging(debug=settings.debug)

    app = Flask(__name__)
    app.config["DEBUG"] = settings.debug

    init_db(app)
    init_request_correlation(app)
    _register_error_handlers(app)
    app.after_request(_add_cors_headers)
    app.register_blueprint(api_v1)

    @app.route("/health")
    def health() -> tuple[dict[str, str], int]:
        """Health check endpoint for load balancers and uptime monitors.

        Returns:
            Tuple of JSON response body and HTTP 200 status code.
        """
        return {"status": "ok"}, 200

    @app.route("/.well-known/jwks.json")
    @app.route("/v1/auth/jwks")
    def jwks() -> Response:
        """Publish Knuckles' current signing public keys as a JWKS.

        Served at both ``/.well-known/jwks.json`` (the standard
        discovery path) and ``/v1/auth/jwks`` (versioned alias for
        callers that want everything under ``/v1``). Carries a
        ``Cache-Control: public, max-age=...`` header so consuming-app
        JWKS clients and intermediate caches share the work.

        Returns:
            JSON ``Response`` carrying the JWKS body, HTTP 200, and a
            cache-control header.
        """
        response = jsonify(get_jwks())
        response.headers["Cache-Control"] = (
            f"public, max-age={_JWKS_CACHE_MAX_AGE_SECONDS}"
        )
        return response

    @app.route("/.well-known/openid-configuration")
    def openid_configuration() -> Response:
        """Publish a partial OIDC discovery document.

        Knuckles is not a full OIDC provider — it has no
        ``/authorize`` endpoint of its own, the consuming app drives
        the ceremony — but exposing ``issuer``, ``jwks_uri``, and the
        signing-algorithm advertisement lets standard JWT-validation
        libraries auto-configure against Knuckles with no extra code
        on the consumer's part.

        Returns:
            JSON ``Response`` with the discovery body and HTTP 200.
        """
        settings = get_settings()
        body = {
            "issuer": settings.knuckles_base_url,
            "jwks_uri": f"{settings.knuckles_base_url}/.well-known/jwks.json",
            "id_token_signing_alg_values_supported": ["RS256"],
            "response_types_supported": ["token"],
            "subject_types_supported": ["public"],
            "token_endpoint_auth_methods_supported": ["client_secret_post"],
        }
        response = jsonify(body)
        response.headers["Cache-Control"] = (
            f"public, max-age={_JWKS_CACHE_MAX_AGE_SECONDS}"
        )
        return response

    return app


def _register_error_handlers(app: Flask) -> None:
    """Register JSON error handlers on the app.

    All three handlers attach the request id (from
    :func:`knuckles.core.observability.get_request_id`) to the response
    body under ``meta.request_id`` and log a structured line so
    operators can grep server logs for the same id a customer quotes.

    Args:
        app: The Flask application instance.
    """
    error_log = get_logger("errors")

    @app.errorhandler(AppError)
    def handle_app_error(error: AppError) -> tuple[dict[str, Any], int]:
        """Log + return a standardized JSON body for a known ``AppError``.

        Every ``AppError`` is logged at WARNING with full request
        context. This is the primary signal for "something failed in a
        way the consuming app saw, here's why."

        Args:
            error: The raised ``AppError`` instance.

        Returns:
            Tuple of JSON error response and the error's HTTP status.
        """
        ctx = request_context()
        error_log.warning(
            "%s [%d] %s | %s",
            error.code,
            error.status_code,
            error.message,
            " ".join(f"{k}={v!r}" for k, v in ctx.items()),
        )
        return _error_envelope(error.code, error.message), error.status_code

    @app.errorhandler(HTTPException)
    def handle_http_error(error: HTTPException) -> tuple[dict[str, Any], int]:
        """Log + return a standardized JSON body for Werkzeug exceptions.

        Args:
            error: The raised ``HTTPException``.

        Returns:
            Tuple of JSON error response and the exception's HTTP code.
        """
        code = error.name.upper().replace(" ", "_") if error.name else "HTTP_ERROR"
        message = error.description or str(error)
        ctx = request_context()
        error_log.warning(
            "%s [%d] %s | %s",
            code,
            error.code or 500,
            message,
            " ".join(f"{k}={v!r}" for k, v in ctx.items()),
        )
        return _error_envelope(code, message), error.code or 500

    @app.errorhandler(Exception)
    def handle_unexpected_error(error: Exception) -> tuple[dict[str, Any], int]:
        """Log a stack trace and return an opaque 500 response.

        The customer app cannot debug an internal exception (we don't
        expose its details for security reasons), but it CAN report the
        request id and the operator finds the full stack trace in the
        logs by grepping for that id.

        Args:
            error: The unhandled exception.

        Returns:
            Tuple of generic-500 JSON body and HTTP 500.
        """
        ctx = request_context()
        error_log.exception(
            "INTERNAL_SERVER_ERROR [500] %s | %s",
            error,
            " ".join(f"{k}={v!r}" for k, v in ctx.items()),
        )
        return (
            _error_envelope(
                "INTERNAL_SERVER_ERROR",
                "An unexpected error occurred. Quote the request_id when "
                "reporting this issue.",
            ),
            500,
        )


def _error_envelope(code: str, message: str) -> dict[str, Any]:
    """Build the standard JSON error response with request-id metadata.

    Args:
        code: Machine-readable error code.
        message: Human-readable error message.

    Returns:
        A dict shaped ``{"error": {...}, "meta": {"request_id": ...}}``
        ready to ``jsonify``.
    """
    body: dict[str, Any] = {"error": {"code": code, "message": message}}
    rid = get_request_id()
    if rid:
        body["meta"] = {"request_id": rid}
    return body


def _add_cors_headers(response):  # type: ignore[no-untyped-def]
    """Attach CORS headers to every response.

    In permissive mode (``KNUCKLES_STRICT_CORS=false``, the default)
    we emit ``Allow-Origin: *``. In strict mode we echo the request's
    ``Origin`` header only when it appears in some registered
    ``app_clients.allowed_origins`` list, otherwise we omit the header
    entirely (browsers will then refuse the response).

    Args:
        response: The Flask response object.

    Returns:
        The response with CORS headers added.
    """
    from flask import request

    from knuckles.core.config import get_settings
    from knuckles.core.cors import is_origin_allowed

    response.headers["Access-Control-Allow-Headers"] = (
        "Content-Type, Authorization, X-Client-Id, X-Client-Secret"
    )
    response.headers["Access-Control-Allow-Methods"] = (
        "GET, POST, PUT, PATCH, DELETE, OPTIONS"
    )

    if not get_settings().knuckles_strict_cors:
        response.headers["Access-Control-Allow-Origin"] = "*"
        return response

    origin = request.headers.get("Origin", "").strip()
    if origin and is_origin_allowed(origin):
        response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
    return response
