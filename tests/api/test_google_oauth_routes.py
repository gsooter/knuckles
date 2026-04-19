"""Tests for the Google OAuth HTTP routes.

The routes are thin adapters over :mod:`knuckles.services.google_oauth`.
These tests cover: app-client auth enforcement, request-body validation,
the happy path through both endpoints (start → complete → token pair),
and the service-level error mapped to ``GOOGLE_AUTH_FAILED``.
"""

from __future__ import annotations

from typing import Any

import pytest
from flask.testing import FlaskClient

from knuckles.services import google_oauth


def _stub_google(
    monkeypatch: pytest.MonkeyPatch,
    *,
    profile: dict[str, Any] | None = None,
    tokens: dict[str, Any] | None = None,
) -> None:
    """Replace Google's HTTP helpers with predictable in-memory fakes.

    Args:
        monkeypatch: pytest's monkeypatch helper.
        profile: Userinfo payload to return from ``_get_profile``.
        tokens: Token payload to return from ``_post_token``.
    """
    monkeypatch.setattr(
        google_oauth,
        "_post_token",
        lambda code, redirect_uri: tokens
        or {
            "access_token": "google-access",
            "refresh_token": "google-refresh",
            "expires_in": 3600,
        },
    )
    monkeypatch.setattr(
        google_oauth,
        "_get_profile",
        lambda access_token: profile
        or {
            "sub": "google-sub-123",
            "email": "user@example.com",
            "email_verified": True,
            "name": "User Example",
            "picture": None,
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


def test_google_start_requires_app_client_auth(client: FlaskClient) -> None:
    """Calling /start without app-client headers yields 401."""
    response = client.post(
        "/v1/auth/google/start",
        json={"redirect_url": "http://localhost:3000/auth/google/callback"},
    )
    assert response.status_code == 401


def test_google_start_validates_redirect_url(
    client: FlaskClient, app_client_creds: tuple[str, str]
) -> None:
    """Missing ``redirect_url`` yields 422 ``VALIDATION_ERROR``."""
    response = client.post(
        "/v1/auth/google/start",
        json={},
        headers=_auth_headers(app_client_creds),
    )
    assert response.status_code == 422
    assert response.get_json()["error"]["code"] == "VALIDATION_ERROR"


def test_google_start_returns_url_and_state(
    client: FlaskClient, app_client_creds: tuple[str, str]
) -> None:
    """Happy path: 200 with authorize_url and state in the body."""
    response = client.post(
        "/v1/auth/google/start",
        json={"redirect_url": "http://localhost:3000/auth/google/callback"},
        headers=_auth_headers(app_client_creds),
    )
    assert response.status_code == 200
    data = response.get_json()["data"]
    assert data["authorize_url"].startswith(
        "https://accounts.google.com/o/oauth2/v2/auth?"
    )
    assert data["state"]


def test_google_complete_returns_token_pair(
    client: FlaskClient,
    app_client_creds: tuple[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: start a flow, then complete it for a TokenPair."""
    _stub_google(monkeypatch)

    start = client.post(
        "/v1/auth/google/start",
        json={"redirect_url": "http://localhost:3000/auth/google/callback"},
        headers=_auth_headers(app_client_creds),
    )
    state = start.get_json()["data"]["state"]

    response = client.post(
        "/v1/auth/google/complete",
        json={"code": "abc", "state": state},
        headers=_auth_headers(app_client_creds),
    )
    assert response.status_code == 200
    data = response.get_json()["data"]
    assert data["access_token"]
    assert data["refresh_token"]
    assert data["token_type"] == "Bearer"


def test_google_complete_validates_required_fields(
    client: FlaskClient, app_client_creds: tuple[str, str]
) -> None:
    """Missing ``code`` or ``state`` yields 422 ``VALIDATION_ERROR``."""
    response = client.post(
        "/v1/auth/google/complete",
        json={"code": "abc"},
        headers=_auth_headers(app_client_creds),
    )
    assert response.status_code == 422
    assert response.get_json()["error"]["code"] == "VALIDATION_ERROR"


def test_google_complete_rejects_invalid_state(
    client: FlaskClient,
    app_client_creds: tuple[str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A forged state JWT yields 400 ``GOOGLE_AUTH_FAILED``."""
    _stub_google(monkeypatch)
    response = client.post(
        "/v1/auth/google/complete",
        json={"code": "abc", "state": "garbage"},
        headers=_auth_headers(app_client_creds),
    )
    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "GOOGLE_AUTH_FAILED"
