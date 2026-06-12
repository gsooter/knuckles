"""HTTP-layer tests for ``GET /v1/sessions`` and ``DELETE /v1/sessions/<id>``.

Session visibility is a point-in-time view over the user's active
refresh tokens, scoped to the calling app client. Rotation replaces
rows, so ids change on every refresh — tests therefore always resolve
the row id immediately before asserting on it.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import UTC, datetime, timedelta

from flask.testing import FlaskClient
from sqlalchemy.orm import Session

from knuckles.core.jwt import issue_access_token
from knuckles.data.models import RefreshToken, User
from knuckles.data.repositories import auth as repo
from knuckles.services import tokens


def _bearer_for(user_id: str, app_client_id: str) -> dict[str, str]:
    """Build an ``Authorization: Bearer`` header for a user.

    Args:
        user_id: UUID string to embed as ``sub``.
        app_client_id: ``aud`` claim to embed.

    Returns:
        Header dict suitable for the test client.
    """
    token = issue_access_token(user_id=user_id, app_client_id=app_client_id)
    return {"Authorization": f"Bearer {token}"}


def _client_headers(creds: tuple[str, str]) -> dict[str, str]:
    """Build ``X-Client-*`` headers from the ``app_client_creds`` fixture.

    Args:
        creds: Tuple of (client_id, plaintext secret).

    Returns:
        Header dict carrying the app-client credentials.
    """
    client_id, secret = creds
    return {"X-Client-Id": client_id, "X-Client-Secret": secret}


def _dual_headers(creds: tuple[str, str], user_id: str) -> dict[str, str]:
    """Combine client headers and a bearer token pinned to the same tenant.

    Args:
        creds: Tuple of (client_id, plaintext secret).
        user_id: UUID string of the bearer user.

    Returns:
        Header dict with both auth mechanisms.
    """
    return {**_client_headers(creds), **_bearer_for(user_id, creds[0])}


def _register_second_client(db_session: Session) -> tuple[str, str]:
    """Register a second app client to model tenant B.

    Args:
        db_session: Active SQLAlchemy session.

    Returns:
        Tuple of (client_id, plaintext secret) for the second tenant.
    """
    client_id = "other-app"
    secret = "other-secret"
    repo.create_app_client(
        db_session,
        client_id=client_id,
        app_name="Other App",
        client_secret_hash=hashlib.sha256(secret.encode("ascii")).hexdigest(),
        allowed_origins=["http://localhost:4000"],
    )
    return client_id, secret


def _row_for_pair(db_session: Session, refresh_token: str) -> RefreshToken:
    """Resolve the ``refresh_tokens`` row backing an issued pair.

    Args:
        db_session: Active SQLAlchemy session.
        refresh_token: The opaque refresh-token plaintext.

    Returns:
        The matching ``RefreshToken`` row.
    """
    token_hash = hashlib.sha256(refresh_token.encode("ascii")).hexdigest()
    row = repo.get_refresh_token_by_hash(db_session, token_hash)
    assert row is not None
    return row


def _make_user(db_session: Session, email: str = "user@example.com") -> User:
    """Create a user row for route tests.

    Args:
        db_session: Active SQLAlchemy session.
        email: Email address for the new user.

    Returns:
        The created ``User``.
    """
    return repo.create_user(db_session, email=email)


# ---------------------------------------------------------------------------
# GET /v1/sessions
# ---------------------------------------------------------------------------


def test_list_sessions_returns_active_rows_only(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """Used and expired refresh tokens never show up in the list."""
    client_id, _ = app_client_creds
    user = _make_user(db_session)
    active = tokens.issue_session(db_session, user_id=user.id, app_client_id=client_id)
    used = tokens.issue_session(db_session, user_id=user.id, app_client_id=client_id)
    repo.mark_refresh_token_used(
        db_session, _row_for_pair(db_session, used.refresh_token)
    )
    repo.create_refresh_token(
        db_session,
        user_id=user.id,
        app_client_id=client_id,
        token_hash="expired-hash",
        expires_at=datetime.now(tz=UTC) - timedelta(days=1),
    )

    response = client.get(
        "/v1/sessions", headers=_dual_headers(app_client_creds, str(user.id))
    )
    assert response.status_code == 200
    data = response.get_json()["data"]
    assert len(data) == 1
    expected = _row_for_pair(db_session, active.refresh_token)
    assert data[0]["id"] == str(expected.id)
    assert set(data[0].keys()) == {"id", "created_at", "expires_at"}
    assert data[0]["created_at"]
    assert data[0]["expires_at"]


def test_list_sessions_scoped_to_calling_tenant(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """Sessions issued under another app client do not appear."""
    other_id, _ = _register_second_client(db_session)
    client_id, _ = app_client_creds
    user = _make_user(db_session)
    mine = tokens.issue_session(db_session, user_id=user.id, app_client_id=client_id)
    tokens.issue_session(db_session, user_id=user.id, app_client_id=other_id)

    response = client.get(
        "/v1/sessions", headers=_dual_headers(app_client_creds, str(user.id))
    )
    assert response.status_code == 200
    data = response.get_json()["data"]
    assert [item["id"] for item in data] == [
        str(_row_for_pair(db_session, mine.refresh_token).id)
    ]


def test_list_sessions_rejects_cross_tenant_token(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """Tenant B's client credentials cannot list with tenant A's token."""
    other_creds = _register_second_client(db_session)
    user = _make_user(db_session)
    headers = {
        **_client_headers(other_creds),
        **_bearer_for(str(user.id), app_client_creds[0]),
    }
    response = client.get("/v1/sessions", headers=headers)
    assert response.status_code == 401
    assert response.get_json()["error"]["code"] == "INVALID_TOKEN"


# ---------------------------------------------------------------------------
# DELETE /v1/sessions/<id>
# ---------------------------------------------------------------------------


def test_revoke_session_marks_row_used(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """Revoking an owned active session returns 204 and consumes the row."""
    client_id, _ = app_client_creds
    user = _make_user(db_session)
    pair = tokens.issue_session(db_session, user_id=user.id, app_client_id=client_id)
    row = _row_for_pair(db_session, pair.refresh_token)

    response = client.delete(
        f"/v1/sessions/{row.id}",
        headers=_dual_headers(app_client_creds, str(user.id)),
    )
    assert response.status_code == 204
    assert row.used_at is not None


def test_revoke_session_unknown_id_returns_404(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """A well-formed UUID with no matching row is SESSION_NOT_FOUND."""
    user = _make_user(db_session)
    response = client.delete(
        f"/v1/sessions/{uuid.uuid4()}",
        headers=_dual_headers(app_client_creds, str(user.id)),
    )
    assert response.status_code == 404
    assert response.get_json()["error"]["code"] == "SESSION_NOT_FOUND"


def test_revoke_session_malformed_id_returns_404(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """A non-UUID path segment is a clean 404, never a 500."""
    user = _make_user(db_session)
    response = client.delete(
        "/v1/sessions/not-a-uuid",
        headers=_dual_headers(app_client_creds, str(user.id)),
    )
    assert response.status_code == 404
    assert response.get_json()["error"]["code"] == "SESSION_NOT_FOUND"


def test_revoke_session_cannot_touch_other_users_session(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """Ownership scoping: another user's session id yields 404."""
    client_id, _ = app_client_creds
    user = _make_user(db_session)
    other = _make_user(db_session, email="other@example.com")
    pair = tokens.issue_session(db_session, user_id=other.id, app_client_id=client_id)
    row = _row_for_pair(db_session, pair.refresh_token)

    response = client.delete(
        f"/v1/sessions/{row.id}",
        headers=_dual_headers(app_client_creds, str(user.id)),
    )
    assert response.status_code == 404
    assert response.get_json()["error"]["code"] == "SESSION_NOT_FOUND"
    assert row.used_at is None


def test_revoke_session_cannot_touch_other_tenants_session(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """Tenant scoping: the same user's session under tenant B yields 404."""
    other_id, _ = _register_second_client(db_session)
    user = _make_user(db_session)
    pair = tokens.issue_session(db_session, user_id=user.id, app_client_id=other_id)
    row = _row_for_pair(db_session, pair.refresh_token)

    response = client.delete(
        f"/v1/sessions/{row.id}",
        headers=_dual_headers(app_client_creds, str(user.id)),
    )
    assert response.status_code == 404
    assert row.used_at is None


def test_revoke_session_already_used_returns_404(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """An already-consumed session is not revokable again."""
    client_id, _ = app_client_creds
    user = _make_user(db_session)
    pair = tokens.issue_session(db_session, user_id=user.id, app_client_id=client_id)
    row = _row_for_pair(db_session, pair.refresh_token)
    repo.mark_refresh_token_used(db_session, row)

    response = client.delete(
        f"/v1/sessions/{row.id}",
        headers=_dual_headers(app_client_creds, str(user.id)),
    )
    assert response.status_code == 404
    assert response.get_json()["error"]["code"] == "SESSION_NOT_FOUND"
