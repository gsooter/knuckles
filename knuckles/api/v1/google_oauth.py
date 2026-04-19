"""Google OAuth HTTP routes.

Two endpoints, both behind app-client auth:

* ``POST /v1/auth/google/start`` — accepts a ``redirect_url`` and
  returns the Google consent URL plus a state JWT the frontend must
  echo back.
* ``POST /v1/auth/google/complete`` — accepts ``{code, state}`` from
  the Google redirect, runs the ceremony, and returns an access+refresh
  pair shaped identically to ``/v1/token/refresh``.
"""

from __future__ import annotations

from typing import Any

from flask import jsonify, request
from flask.wrappers import Response

from knuckles.api.v1 import api_v1
from knuckles.core import database
from knuckles.core.app_client_auth import get_current_app_client, require_app_client
from knuckles.core.exceptions import ValidationError
from knuckles.services import google_oauth


def _require_string_field(field: str) -> str:
    """Pull a non-empty string field from the JSON body or raise.

    Args:
        field: The body key to require.

    Returns:
        The non-empty string value of ``field``.

    Raises:
        ValidationError: If the body is missing or the field is absent
            or not a non-empty string.
    """
    body = request.get_json(silent=True) or {}
    value = body.get(field)
    if not isinstance(value, str) or not value:
        raise ValidationError(f"'{field}' is required.")
    return value


@api_v1.post("/auth/google/start")
@require_app_client
def google_start_route() -> tuple[Response, int]:
    """Return the Google consent URL and the matching state JWT.

    Returns:
        Tuple of JSON body (``authorize_url``, ``state``) and HTTP 200.

    Raises:
        ValidationError: If the body is missing ``redirect_url``.
    """
    redirect_url = _require_string_field("redirect_url")
    app_client = get_current_app_client()

    issued = google_oauth.build_authorize_url(
        redirect_uri=redirect_url,
        app_client_id=app_client.client_id,
    )
    body: dict[str, Any] = {
        "data": {
            "authorize_url": issued.authorize_url,
            "state": issued.state,
        }
    }
    return jsonify(body), 200


@api_v1.post("/auth/google/complete")
@require_app_client
def google_complete_route() -> tuple[Response, int]:
    """Finalize the Google OAuth flow and mint a Knuckles session.

    Returns:
        Tuple of JSON body and HTTP 200. Body shape mirrors
        ``/v1/token/refresh``.

    Raises:
        ValidationError: If the body is missing ``code`` or ``state``.
        AppError: Propagated from :func:`google_oauth.complete` with
            code ``GOOGLE_AUTH_FAILED`` for any state/exchange/profile
            failure.
    """
    code = _require_string_field("code")
    state = _require_string_field("state")
    app_client = get_current_app_client()
    session = database.get_db()

    pair = google_oauth.complete(
        session,
        code=code,
        state=state,
        app_client_id=app_client.client_id,
    )
    body: dict[str, Any] = {
        "data": {
            "access_token": pair.access_token,
            "access_token_expires_at": pair.access_token_expires_at.isoformat(),
            "refresh_token": pair.refresh_token,
            "refresh_token_expires_at": pair.refresh_token_expires_at.isoformat(),
            "token_type": "Bearer",
        }
    }
    return jsonify(body), 200
