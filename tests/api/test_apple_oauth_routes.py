"""Tests for the Apple Sign-In HTTP routes.

The routes are thin adapters over :mod:`knuckles.services.apple_oauth`.
These tests cover: app-client auth enforcement, request-body validation
(including the optional ``user`` payload), the happy path through both
endpoints, and the service-level error mapped to ``APPLE_AUTH_FAILED``.
"""

from __future__ import annotations

from typing import Any

import pytest
from flask.testing import FlaskClient

from knuckles.services import apple_oauth


def _stub_apple(
    monkeypatch: pytest.MonkeyPatch,
    *,
    profile: dict[str, Any] | None = None,
    tokens: dict[str, Any] | None = None,
) -> None:
    """Replace Apple's HTTP/JWT helpers with predictable in-memory fakes.

    Args:
        monkeypatch: pytest's monkeypatch helper.
        profile: id_token claims to return from ``_verify_id_token``.
        tokens: Token payload to return from ``_post_token``.
    """
    monkeypatch.setattr(
        apple_oauth,
        "_mint_client_secret",
        lambda: "fake-client-secret",
    )
    monkeypatch.setattr(
        apple_oauth,
        "_post_token",
        lambda code, redirect_uri, client_secret: tokens
        or {
            "access_token": "apple-access",
            "refresh_token": "apple-refresh",
            "expires_in": 3600,
            "id_token": "fake-id-token",
        },
    )
    monkeypatch.setattr(
        apple_oauth,
        "_verify_id_token",
        lambda id_token: profile
        or {
            "sub": "apple-sub-123",
            "email": "user@example.com",
            "email_verified": "true",
            "is_private_email": "false",
        },
    )


def _auth_headers(creds: tuple[str, str]) -> dict[str, str]:
    """Build the X-Client-Id / X-Client-Secret header pair.

    Args:
        creds: ``(client_id, client_secret)`` from the
            ``app_client_creds`` fixture.

    Returns:
        Header dict for the test client's ``headers`` kwarg.
    """
    client_id, secret = creds
    return {"X-Client-Id": client_id, "X-Client-Secret": secret}


def test_apple_start_requires_app_client_auth(client: FlaskClient) -> None:
    """Calling /start without app-client headers yields 401."""
    response = client.post(
        "/v1/auth/apple/start",
        json={"redirect_url": "http://localhost:3000/auth/apple/callback"},
    )
    assert response.status_code == 401


def test_apple_start_validates_redirect_url(
    client: FlaskClient, app_client_creds: tuple[str, str]
) -> None:
    """Missing ``redirect_url`` yields 422 ``VALIDATION_ERROR``."""
    response = client.post(
        "/v1/auth/apple/start",
        json={},
        headers=_auth_headers(app_client_creds),
    )
    assert response.status_code == 422
    assert response.get_json()["error"]["code"] == "VALIDATION_ERROR"


def test_apple_start_returns_url_and_state(
    client: FlaskClient, app_client_creds: tuple[str, str]
) -> None:
    """Happy path: 200 with authorize_url and state in the body."""
    response = client.post(
        "/v1/auth/apple/start",
        json={"redirect_url": "http://localhost:3000/auth/apple/callback"},
        headers=_auth_headers(app_client_creds),
    )
    assert response.status_code == 200
    data = response.get_json()["data"]
    assert data["authorize_url"].startswith("https://appleid.apple.com/auth/authorize?")
    assert "response_mode=form_post" in data["authorize_url"]
    assert data["state"]


def test_apple_complete_returns_token_pair(
    client: FlaskClient,
    app_client_creds: tuple[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: start a flow, then complete it for a TokenPair."""
    _stub_apple(monkeypatch)

    start = client.post(
        "/v1/auth/apple/start",
        json={"redirect_url": "http://localhost:3000/auth/apple/callback"},
        headers=_auth_headers(app_client_creds),
    )
    state = start.get_json()["data"]["state"]

    response = client.post(
        "/v1/auth/apple/complete",
        json={
            "code": "abc",
            "state": state,
            "user": {"name": {"firstName": "User", "lastName": "Example"}},
        },
        headers=_auth_headers(app_client_creds),
    )
    assert response.status_code == 200
    data = response.get_json()["data"]
    assert data["access_token"]
    assert data["refresh_token"]
    assert data["token_type"] == "Bearer"


def test_apple_complete_validates_required_fields(
    client: FlaskClient, app_client_creds: tuple[str, str]
) -> None:
    """Missing ``code`` or ``state`` yields 422 ``VALIDATION_ERROR``."""
    response = client.post(
        "/v1/auth/apple/complete",
        json={"code": "abc"},
        headers=_auth_headers(app_client_creds),
    )
    assert response.status_code == 422
    assert response.get_json()["error"]["code"] == "VALIDATION_ERROR"


def test_apple_complete_rejects_non_object_user(
    client: FlaskClient,
    app_client_creds: tuple[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A non-object ``user`` payload yields 422 ``VALIDATION_ERROR``."""
    _stub_apple(monkeypatch)
    start = client.post(
        "/v1/auth/apple/start",
        json={"redirect_url": "http://localhost:3000/auth/apple/callback"},
        headers=_auth_headers(app_client_creds),
    )
    state = start.get_json()["data"]["state"]

    response = client.post(
        "/v1/auth/apple/complete",
        json={"code": "abc", "state": state, "user": "not-an-object"},
        headers=_auth_headers(app_client_creds),
    )
    assert response.status_code == 422
    assert response.get_json()["error"]["code"] == "VALIDATION_ERROR"


def test_apple_complete_rejects_invalid_state(
    client: FlaskClient,
    app_client_creds: tuple[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A forged state JWT yields 400 ``APPLE_AUTH_FAILED``."""
    _stub_apple(monkeypatch)
    response = client.post(
        "/v1/auth/apple/complete",
        json={"code": "abc", "state": "garbage"},
        headers=_auth_headers(app_client_creds),
    )
    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "APPLE_AUTH_FAILED"
