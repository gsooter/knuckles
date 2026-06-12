"""Session-visibility routes for the signed-in user.

Two endpoints:

* ``GET /v1/sessions`` — list the user's active refresh tokens with
  the calling app client. Rotation replaces rows, so the ids change
  on every ``/v1/token/refresh`` — this is a point-in-time view, not
  a stable session registry.
* ``DELETE /v1/sessions/<session_id>`` — revoke one session by id,
  scoped to the calling user and tenant.

Both routes are dual-auth (client headers + bearer) and pin the token
audience to the calling client, exactly like ``GET /v1/me``.

Every route is a thin adapter: it validates the request, calls a
service, and returns a shaped JSON body. No business logic runs here.
"""

from __future__ import annotations

import uuid
from typing import Any

from flask import jsonify
from flask.wrappers import Response

from knuckles.api.v1 import api_v1
from knuckles.core import database
from knuckles.core.app_client_auth import get_current_app_client, require_app_client
from knuckles.core.auth import (
    assert_token_audience,
    get_current_user_id,
    require_auth,
)
from knuckles.core.exceptions import SESSION_NOT_FOUND, NotFoundError
from knuckles.services import tokens


@api_v1.get("/sessions")
@require_app_client
@require_auth
def list_sessions_route() -> tuple[Response, int]:
    """List the authenticated user's active sessions with this app.

    Returns:
        Tuple of JSON body and HTTP 200. Each item carries ``id``,
        ``created_at``, and ``expires_at``. Because refresh-token
        rotation replaces rows, the ids change on every refresh —
        consumers must treat the list as a point-in-time view.

    Raises:
        UnauthorizedError: With code ``INVALID_TOKEN`` when the bearer
            token was minted for a different app client.
    """
    app_client = get_current_app_client()
    assert_token_audience(app_client.client_id)
    session = database.get_db()
    rows = tokens.list_sessions(
        session,
        user_id=get_current_user_id(),
        app_client_id=app_client.client_id,
    )
    body: dict[str, Any] = {
        "data": [
            {
                "id": str(row.id),
                "created_at": row.created_at.isoformat(),
                "expires_at": row.expires_at.isoformat(),
            }
            for row in rows
        ]
    }
    return jsonify(body), 200


@api_v1.delete("/sessions/<session_id>")
@require_app_client
@require_auth
def revoke_session_route(session_id: str) -> tuple[Response, int]:
    """Revoke one of the authenticated user's sessions by id.

    Args:
        session_id: ``refresh_tokens.id`` from the URL. A value that
            does not parse as a UUID is treated as an unknown session
            (404), never a server error.

    Returns:
        Tuple of an empty JSON body and HTTP 204.

    Raises:
        NotFoundError: With code ``SESSION_NOT_FOUND`` when the id is
            malformed, unknown, owned by another user or tenant, or
            already consumed/expired.
        UnauthorizedError: With code ``INVALID_TOKEN`` when the bearer
            token was minted for a different app client.
    """
    app_client = get_current_app_client()
    assert_token_audience(app_client.client_id)
    try:
        parsed_id = uuid.UUID(session_id)
    except ValueError as exc:
        raise NotFoundError(
            code=SESSION_NOT_FOUND, message="Session not found."
        ) from exc

    session = database.get_db()
    tokens.revoke_session(
        session,
        user_id=get_current_user_id(),
        app_client_id=app_client.client_id,
        session_id=parsed_id,
    )
    return jsonify({}), 204
