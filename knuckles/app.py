"""Flask application factory for Knuckles."""

from typing import Any

from flask import Flask
from werkzeug.exceptions import HTTPException

from knuckles.api.v1 import api_v1
from knuckles.core.config import get_settings
from knuckles.core.database import init_db
from knuckles.core.exceptions import AppError
from knuckles.core.jwt import get_jwks
from knuckles.core.logging import setup_logging


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
    def jwks() -> tuple[dict[str, Any], int]:
        """Publish Knuckles' current signing public keys as a JWKS.

        Returns:
            Tuple of JWKS JSON body and HTTP 200. Consuming apps fetch
            this once and validate RS256 access tokens locally against
            the returned keys.
        """
        return get_jwks(), 200

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
    """Attach permissive CORS headers to every response.

    Consuming apps are browser-based (Greenroom's Next.js frontend is
    the first), so cross-origin access to Knuckles is required.

    Args:
        response: The Flask response object.

    Returns:
        The response with CORS headers added.
    """
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = (
        "Content-Type, Authorization, X-Client-Id, X-Client-Secret"
    )
    response.headers["Access-Control-Allow-Methods"] = (
        "GET, POST, PUT, PATCH, DELETE, OPTIONS"
    )
    return response
