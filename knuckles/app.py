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
from knuckles.core.logging import setup_logging

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

    Args:
        app: The Flask application instance.
    """

    @app.errorhandler(AppError)
    def handle_app_error(error: AppError) -> tuple[dict[str, Any], int]:
        """Return a standardized JSON body for a known ``AppError``.

        Args:
            error: The raised ``AppError`` instance.

        Returns:
            Tuple of JSON error response and the error's HTTP status.
        """
        return {
            "error": {"code": error.code, "message": error.message},
        }, error.status_code

    @app.errorhandler(HTTPException)
    def handle_http_error(error: HTTPException) -> tuple[dict[str, Any], int]:
        """Return a standardized JSON body for Werkzeug HTTP exceptions.

        Args:
            error: The raised ``HTTPException``.

        Returns:
            Tuple of JSON error response and the exception's HTTP code.
        """
        return {
            "error": {
                "code": error.name.upper().replace(" ", "_"),
                "message": error.description or str(error),
            }
        }, error.code or 500

    @app.errorhandler(Exception)
    def handle_unexpected_error(error: Exception) -> tuple[dict[str, Any], int]:
        """Log and generically respond to any unhandled exception.

        Args:
            error: The unhandled exception.

        Returns:
            Tuple of generic-500 JSON body and HTTP 500.
        """
        app.logger.exception("Unhandled exception: %s", error)
        return {
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected error occurred.",
            }
        }, 500


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
