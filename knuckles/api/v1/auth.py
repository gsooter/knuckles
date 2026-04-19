"""Auth routes exposed by Knuckles to its consuming app-clients.

Three endpoints land here for P2:

* ``POST /v1/token/refresh`` — rotate a refresh token into a new
  access+refresh pair. Requires app-client auth + a body with the
  presented ``refresh_token``.
* ``POST /v1/logout`` — revoke a refresh token (idempotent on unknown
  values). Requires app-client auth + the token in the body.
* ``GET /v1/me`` — return the authenticated user's profile. Requires
  both app-client auth (so we know who is calling) and a valid
  bearer access token (so we know which user).

Every route is a thin adapter: it validates the request, calls a
service, and returns a shaped JSON body. No business logic runs here.
"""

from __future__ import annotations

from typing import Any

from flask import jsonify, request
from flask.wrappers import Response

from knuckles.api.v1 import api_v1
from knuckles.core import database
from knuckles.core.app_client_auth import get_current_app_client, require_app_client
from knuckles.core.auth import get_current_user_id, get_token_claims, require_auth
from knuckles.core.exceptions import USER_NOT_FOUND, NotFoundError, ValidationError
from knuckles.data.repositories import auth as repo
from knuckles.services import tokens


def _require_refresh_token_field() -> str:
    """Extract the ``refresh_token`` field from the JSON body.

    Returns:
        The refresh-token plaintext from the request body.

    Raises:
        ValidationError: If the body is missing or the field is absent.
    """
    body = request.get_json(silent=True) or {}
    refresh_token = body.get("refresh_token")
    if not isinstance(refresh_token, str) or not refresh_token:
        raise ValidationError("'refresh_token' is required.")
    return refresh_token


@api_v1.post("/token/refresh")
@require_app_client
def refresh_token_route() -> tuple[Response, int]:
    """Rotate a refresh token into a new access+refresh pair.

    Returns:
        Tuple of JSON body and HTTP 200.

    Raises:
        ValidationError: If the request body is missing the token.
        AppError: Propagated from :func:`tokens.rotate_refresh_token`
            when the token is invalid, expired, reused, or belongs to
            a different client.
    """
    refresh_token = _require_refresh_token_field()
    app_client = get_current_app_client()
    session = database.get_db()

    pair = tokens.rotate_refresh_token(
        session,
        refresh_token=refresh_token,
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


@api_v1.post("/logout")
@require_app_client
def logout_route() -> tuple[Response, int]:
    """Revoke a refresh token for the calling app-client.

    Returns:
        Tuple of an empty JSON response and HTTP 204 — idempotent on
        unknown tokens so the client never has to branch on logout.

    Raises:
        ValidationError: If the request body is missing the token.
    """
    refresh_token = _require_refresh_token_field()
    app_client = get_current_app_client()
    session = database.get_db()

    tokens.revoke_refresh_token(
        session,
        refresh_token=refresh_token,
        app_client_id=app_client.client_id,
    )
    return jsonify({}), 204


@api_v1.get("/me")
@require_app_client
@require_auth
def me_route() -> tuple[Response, int]:
    """Return the authenticated user's profile.

    Returns:
        Tuple of JSON body and HTTP 200 carrying id, email, display
        name, avatar URL, and the JWT audience claim the caller used.

    Raises:
        AppError: With code ``USER_NOT_FOUND`` if the token's subject
            no longer exists (e.g., the user was deleted mid-session).
    """
    user_id = get_current_user_id()
    session = database.get_db()
    user = repo.get_user_by_id(session, user_id)
    if user is None:
        raise NotFoundError(code=USER_NOT_FOUND, message="User not found.")

    claims = get_token_claims()
    body: dict[str, Any] = {
        "data": {
            "id": str(user.id),
            "email": user.email,
            "display_name": user.display_name,
            "avatar_url": user.avatar_url,
            "app_client_id": claims.get("aud"),
        }
    }
    return jsonify(body), 200
