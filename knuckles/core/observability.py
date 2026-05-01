"""Request-scoped observability primitives: correlation IDs and a
``log_and_raise`` helper for service-layer error sites.

The shape:

* Every HTTP request gets a request id — either echoed from the
  caller's ``X-Request-Id`` header (so a customer app's request id
  flows through cleanly) or freshly minted as a UUID4. The id lives
  on ``flask.g.request_id`` for the duration of the request.
* Every response carries the id back as ``X-Request-Id`` so the
  caller can correlate.
* The global error handler logs the request id alongside every
  ``AppError`` it sees.

This is the load-bearing primitive for "the customer can quote a
request id and the operator can grep for it." Without it, triage
across a customer/operator boundary requires guessing.
"""

from __future__ import annotations

import uuid
from typing import TYPE_CHECKING, Any, NoReturn

from flask import Flask, Response, g, request

if TYPE_CHECKING:
    import logging

_REQUEST_ID_HEADER = "X-Request-Id"


def init_request_correlation(app: Flask) -> None:
    """Register before/after request hooks that maintain a request id.

    Args:
        app: The Flask application instance to wire the hooks onto.
    """

    @app.before_request
    def _set_request_id() -> None:
        """Set ``flask.g.request_id`` from the header or a fresh UUID."""
        incoming = request.headers.get(_REQUEST_ID_HEADER, "").strip()
        # Bound the accepted incoming id so a hostile caller can't push a
        # 1MB string into every log line.
        if incoming and len(incoming) <= 128:
            g.request_id = incoming
        else:
            g.request_id = str(uuid.uuid4())

    @app.after_request
    def _emit_request_id(response: Response) -> Response:
        """Echo the request id on the response so the caller can correlate.

        Args:
            response: The outgoing Flask response.

        Returns:
            The same response with the ``X-Request-Id`` header set.
        """
        rid = getattr(g, "request_id", None)
        if rid:
            response.headers[_REQUEST_ID_HEADER] = rid
        return response


def get_request_id() -> str | None:
    """Return the current request id, or ``None`` outside a request.

    Returns:
        The request id string, or ``None`` if called outside a Flask
        request context.
    """
    try:
        return getattr(g, "request_id", None)
    except RuntimeError:
        # Working outside of a request context (e.g., a CLI script).
        return None


def request_context() -> dict[str, Any]:
    """Return a dict of request-scoped fields safe to attach to log lines.

    Includes the request id, the path/method, and the resolved
    ``app_client_id`` and ``user_id`` if any decorator has populated
    them on ``flask.g`` already.

    Returns:
        A dict suitable to pass as ``extra=...`` to a logger call.
    """
    try:
        ctx: dict[str, Any] = {
            "request_id": getattr(g, "request_id", None),
            "method": request.method,
            "path": request.path,
        }
        client = getattr(g, "app_client", None)
        if client is not None:
            ctx["app_client_id"] = getattr(client, "client_id", None)
        user_id = getattr(g, "user_id", None)
        if user_id is not None:
            ctx["user_id"] = str(user_id)
        return {k: v for k, v in ctx.items() if v is not None}
    except RuntimeError:
        return {}


def log_and_raise(
    exception: Exception,
    *,
    logger: logging.Logger,
    detail: str | None = None,
    **log_fields: Any,
) -> NoReturn:
    """Log a raised ``AppError`` (or any exception) then re-raise it.

    The call site looks like::

        log_and_raise(
            AppError(code=GOOGLE_AUTH_FAILED, message="...", status_code=400),
            logger=logger,
            detail="invalid_grant",
            redirect_uri=redirect_uri,
        )

    The log line carries the error code, the human message, request
    context, and any structured fields the caller passes. The
    exception then propagates as normal — the global error handler
    serializes it for the wire.

    Args:
        exception: The exception instance to raise.
        logger: The logger to emit the diagnostic line on.
        detail: Optional short string describing the underlying cause
            (e.g. an upstream provider's machine-readable error code).
        **log_fields: Arbitrary extra fields appended to the log entry
            (e.g. ``redirect_uri``, ``provider_status``).

    Raises:
        Exception: Always re-raises ``exception`` after logging.
    """
    code = getattr(exception, "code", exception.__class__.__name__)
    message = getattr(exception, "message", str(exception))
    fields = {**request_context(), **log_fields}
    if detail:
        fields["detail"] = detail
    field_str = " ".join(f"{k}={v!r}" for k, v in fields.items())
    logger.warning(
        "raise %s: %s | %s",
        code,
        message,
        field_str,
    )
    raise exception
