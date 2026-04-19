"""Apple Sign-In HTTP routes.

Two endpoints, both behind app-client auth:

* ``POST /v1/auth/apple/start`` — accepts a ``redirect_url`` and
  returns Apple's consent URL plus a state JWT the frontend must
  echo back. The consent URL uses ``response_mode=form_post`` so
  Apple POSTs the code, state, and (first time) ``user`` payload
  back to the redirect URL.
* ``POST /v1/auth/apple/complete`` — accepts ``{code, state}`` plus
  an optional ``user`` payload (only present on the first sign-in
  for a given Apple ID), runs the ceremony, and returns an
  access+refresh pair shaped identically to ``/v1/token/refresh``.
"""

from __future__ import annotations

from typing import Any

from flask import jsonify, request
from flask.wrappers import Response

from knuckles.api.v1 import api_v1
from knuckles.core import database
from knuckles.core.app_client_auth import get_current_app_client, require_app_client
from knuckles.core.exceptions import ValidationError
from knuckles.services import apple_oauth


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


@api_v1.post("/auth/apple/start")
@require_app_client
def apple_start_route() -> tuple[Response, int]:
    """Return Apple's consent URL and the matching state JWT.

    Returns:
        Tuple of JSON body (``authorize_url``, ``state``) and HTTP 200.

    Raises:
        ValidationError: If the body is missing ``redirect_url``.
    """
    redirect_url = _require_string_field("redirect_url")
    app_client = get_current_app_client()

    issued = apple_oauth.build_authorize_url(
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


@api_v1.post("/auth/apple/complete")
@require_app_client
def apple_complete_route() -> tuple[Response, int]:
    """Finalize the Apple Sign-In flow and mint a Knuckles session.

    Accepts an optional ``user`` field in the JSON body. Apple only
    POSTs that payload on the first sign-in for a given Apple ID, so
    the frontend should pass it through verbatim when present.

    Returns:
        Tuple of JSON body and HTTP 200. Body shape mirrors
        ``/v1/token/refresh``.

    Raises:
        ValidationError: If the body is missing ``code`` or ``state``.
        AppError: Propagated from :func:`apple_oauth.complete` with
            code ``APPLE_AUTH_FAILED`` for any state, exchange, or
            id_token failure.
    """
    code = _require_string_field("code")
    state = _require_string_field("state")
    body = request.get_json(silent=True) or {}
    user_data = body.get("user")
    if user_data is not None and not isinstance(user_data, dict):
        raise ValidationError("'user' must be an object when provided.")

    app_client = get_current_app_client()
    session = database.get_db()

    pair = apple_oauth.complete(
        session,
        code=code,
        state=state,
        app_client_id=app_client.client_id,
        user_data=user_data,
    )
    response_body: dict[str, Any] = {
        "data": {
            "access_token": pair.access_token,
            "access_token_expires_at": pair.access_token_expires_at.isoformat(),
            "refresh_token": pair.refresh_token,
            "refresh_token_expires_at": pair.refresh_token_expires_at.isoformat(),
            "token_type": "Bearer",
        }
    }
    return jsonify(response_body), 200
