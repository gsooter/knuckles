"""Tests for the Knuckles ``/v1/token/refresh``, ``/v1/logout``, ``/v1/me`` routes.

These are the first P2 HTTP-layer endpoints. They all require app-client
authentication via ``X-Client-Id`` + ``X-Client-Secret``; ``/v1/me`` also
requires a valid access token via ``Authorization: Bearer``.
"""

from __future__ import annotations

import hashlib

from flask.testing import FlaskClient
from sqlalchemy.orm import Session

from knuckles.data.models import RefreshToken
from knuckles.data.repositories import auth as repo
from knuckles.services import tokens


def _issue_pair(
    db_session: Session, *, email: str, client_id: str
) -> tuple[str, str, str]:
    """Create a user and issue a matched access+refresh pair.

    Args:
        db_session: SQLite-backed session fixture.
        email: Email address for the new user.
        client_id: App-client the pair is issued for.

    Returns:
        Tuple of (user_id, access_token, refresh_token).
    """
    user = repo.create_user(db_session, email=email)
    pair = tokens.issue_session(
        db_session, user_id=user.id, app_client_id=client_id, email=email
    )
    return str(user.id), pair.access_token, pair.refresh_token


def test_refresh_rotates_token_pair(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """Valid refresh-token rotates into a new access+refresh pair."""
    client_id, secret = app_client_creds
    _, _, refresh = _issue_pair(db_session, email="a@example.com", client_id=client_id)

    response = client.post(
        "/v1/token/refresh",
        json={"refresh_token": refresh},
        headers={"X-Client-Id": client_id, "X-Client-Secret": secret},
    )

    assert response.status_code == 200
    body = response.get_json()
    assert "access_token" in body["data"]
    assert "refresh_token" in body["data"]
    assert body["data"]["access_token"]
    assert body["data"]["refresh_token"] != refresh


def test_refresh_rejects_unknown_token(
    client: FlaskClient, app_client_creds: tuple[str, str]
) -> None:
    """An unknown refresh token produces HTTP 401 + ``REFRESH_TOKEN_INVALID``."""
    client_id, secret = app_client_creds

    response = client.post(
        "/v1/token/refresh",
        json={"refresh_token": "not-real"},
        headers={"X-Client-Id": client_id, "X-Client-Secret": secret},
    )
    assert response.status_code == 401
    assert response.get_json()["error"]["code"] == "REFRESH_TOKEN_INVALID"


def test_refresh_requires_app_client_auth(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """Missing X-Client-* headers yield ``INVALID_CLIENT``."""
    client_id, _ = app_client_creds
    _, _, refresh = _issue_pair(db_session, email="a@example.com", client_id=client_id)

    response = client.post(
        "/v1/token/refresh",
        json={"refresh_token": refresh},
    )
    assert response.status_code == 401
    assert response.get_json()["error"]["code"] == "INVALID_CLIENT"


def test_refresh_rejects_missing_body_field(
    client: FlaskClient, app_client_creds: tuple[str, str]
) -> None:
    """A body without ``refresh_token`` is a ``VALIDATION_ERROR``."""
    client_id, secret = app_client_creds

    response = client.post(
        "/v1/token/refresh",
        json={},
        headers={"X-Client-Id": client_id, "X-Client-Secret": secret},
    )
    assert response.status_code == 422
    assert response.get_json()["error"]["code"] == "VALIDATION_ERROR"


def test_logout_marks_refresh_token_used(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """``/v1/logout`` marks the given refresh token consumed."""
    client_id, secret = app_client_creds
    _, _, refresh = _issue_pair(db_session, email="a@example.com", client_id=client_id)

    response = client.post(
        "/v1/logout",
        json={"refresh_token": refresh},
        headers={"X-Client-Id": client_id, "X-Client-Secret": secret},
    )
    assert response.status_code == 204

    token_hash = hashlib.sha256(refresh.encode("ascii")).hexdigest()
    row = db_session.query(RefreshToken).filter_by(token_hash=token_hash).one()
    assert row.used_at is not None


def test_logout_is_idempotent_on_unknown_token(
    client: FlaskClient, app_client_creds: tuple[str, str]
) -> None:
    """Calling ``/v1/logout`` with an unknown token still returns 204."""
    client_id, secret = app_client_creds

    response = client.post(
        "/v1/logout",
        json={"refresh_token": "anything"},
        headers={"X-Client-Id": client_id, "X-Client-Secret": secret},
    )
    assert response.status_code == 204


def test_me_returns_user_profile(
    client: FlaskClient,
    db_session: Session,
    app_client_creds: tuple[str, str],
) -> None:
    """``GET /v1/me`` with a valid access token returns the user's profile."""
    client_id, secret = app_client_creds
    user_id, access, _ = _issue_pair(
        db_session, email="me@example.com", client_id=client_id
    )

    response = client.get(
        "/v1/me",
        headers={
            "Authorization": f"Bearer {access}",
            "X-Client-Id": client_id,
            "X-Client-Secret": secret,
        },
    )

    assert response.status_code == 200
    body = response.get_json()
    assert body["data"]["id"] == user_id
    assert body["data"]["email"] == "me@example.com"


def test_me_requires_bearer_token(
    client: FlaskClient, app_client_creds: tuple[str, str]
) -> None:
    """``GET /v1/me`` without a bearer token yields HTTP 401."""
    client_id, secret = app_client_creds
    response = client.get(
        "/v1/me",
        headers={"X-Client-Id": client_id, "X-Client-Secret": secret},
    )
    assert response.status_code == 401
    assert response.get_json()["error"]["code"] == "INVALID_TOKEN"
