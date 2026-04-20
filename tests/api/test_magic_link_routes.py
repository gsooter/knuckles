"""Tests for the magic-link HTTP routes.

The routes are thin adapters over :mod:`knuckles.services.magic_link`.
These tests exercise: app-client auth enforcement, request-body
validation, the happy path (start → verify → JWT pair), and the three
service-level error codes mapped to JSON error envelopes.
"""

from __future__ import annotations

import re
from collections.abc import Iterator

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy.orm import Session

import knuckles.api.v1.magic_link as magic_link_route_mod
import knuckles.core.app_client_auth as app_client_auth_mod
import knuckles.core.database as database_mod
from knuckles.app import create_app


class _FakeEmailSender:
    """Test double recording each magic-link send.

    Attributes:
        sent: List of ``(to, subject, body, from_name)`` tuples in send
            order.
    """

    def __init__(self) -> None:
        """Initialize an empty send log."""
        self.sent: list[tuple[str, str, str, str | None]] = []

    def send(
        self,
        *,
        to: str,
        subject: str,
        body: str,
        from_name: str | None = None,
    ) -> None:
        """Record a magic-link send instead of hitting Resend.

        Args:
            to: Recipient email address.
            subject: Email subject line.
            body: HTML email body.
            from_name: Optional display name for the ``From`` header.
        """
        self.sent.append((to, subject, body, from_name))


@pytest.fixture()
def email_sender() -> _FakeEmailSender:
    """Return a fresh fake email sender for each test.

    Returns:
        A new :class:`_FakeEmailSender`.
    """
    return _FakeEmailSender()


@pytest.fixture()
def app(
    db_session: Session,
    monkeypatch: pytest.MonkeyPatch,
    email_sender: _FakeEmailSender,
) -> Iterator[Flask]:
    """Build the Knuckles Flask app with ``get_db`` and email injected.

    Overrides the conftest ``app`` fixture so the magic-link routes pull
    the recording fake instead of constructing a Resend client.

    Args:
        db_session: The SQLite-backed SQLAlchemy session fixture.
        monkeypatch: pytest's monkeypatch helper.
        email_sender: The fake email sender to inject.

    Yields:
        The fully-configured Flask app ready for a test client.
    """
    monkeypatch.setattr(database_mod, "get_db", lambda: db_session)
    monkeypatch.setattr(app_client_auth_mod.database, "get_db", lambda: db_session)
    monkeypatch.setattr(
        magic_link_route_mod, "get_default_sender", lambda: email_sender
    )
    yield create_app()


@pytest.fixture()
def client(app: Flask) -> FlaskClient:
    """Return a Flask test client bound to the test app.

    Args:
        app: The Flask app fixture.

    Returns:
        An active ``FlaskClient``.
    """
    return app.test_client()


def _auth_headers(creds: tuple[str, str]) -> dict[str, str]:
    """Build the X-Client-Id / X-Client-Secret header pair.

    Args:
        creds: ``(client_id, client_secret)`` tuple from the
            ``app_client_creds`` fixture.

    Returns:
        Header dict suitable for the ``headers`` kwarg of test client
        requests.
    """
    client_id, secret = creds
    return {"X-Client-Id": client_id, "X-Client-Secret": secret}


def _extract_token(body: str) -> str:
    """Pull the raw magic-link token out of a captured email body.

    Args:
        body: The HTML email body recorded by :class:`_FakeEmailSender`.

    Returns:
        The raw URL-safe token from the first ``token=`` query parameter.
    """
    match = re.search(r"token=([A-Za-z0-9_-]+)", body)
    assert match is not None, "no token in email body"
    return match.group(1)


def test_start_magic_link_requires_app_client_auth(client: FlaskClient) -> None:
    """Calling /start without app-client headers yields 401."""
    response = client.post(
        "/v1/auth/magic-link/start",
        json={
            "email": "user@example.com",
            "redirect_url": "http://localhost:3000/auth/verify",
        },
    )
    assert response.status_code == 401


def test_start_magic_link_validates_required_fields(
    client: FlaskClient, app_client_creds: tuple[str, str]
) -> None:
    """Missing ``email`` or ``redirect_url`` yields 422 ``VALIDATION_ERROR``."""
    response = client.post(
        "/v1/auth/magic-link/start",
        json={"email": "user@example.com"},
        headers=_auth_headers(app_client_creds),
    )
    assert response.status_code == 422
    payload = response.get_json()
    assert payload["error"]["code"] == "VALIDATION_ERROR"


def test_start_magic_link_sends_email_and_returns_202(
    client: FlaskClient,
    app_client_creds: tuple[str, str],
    email_sender: _FakeEmailSender,
) -> None:
    """Happy path: 202 Accepted and one email recorded."""
    response = client.post(
        "/v1/auth/magic-link/start",
        json={
            "email": "user@example.com",
            "redirect_url": "http://localhost:3000/auth/verify",
        },
        headers=_auth_headers(app_client_creds),
    )
    assert response.status_code == 202
    assert len(email_sender.sent) == 1
    to, _subject, body, _from_name = email_sender.sent[0]
    assert to == "user@example.com"
    assert "http://localhost:3000/auth/verify?token=" in body


def test_verify_magic_link_returns_token_pair(
    client: FlaskClient,
    app_client_creds: tuple[str, str],
    email_sender: _FakeEmailSender,
) -> None:
    """Verifying a valid token yields an access+refresh pair and 200."""
    client.post(
        "/v1/auth/magic-link/start",
        json={
            "email": "user@example.com",
            "redirect_url": "http://localhost:3000/auth/verify",
        },
        headers=_auth_headers(app_client_creds),
    )
    raw_token = _extract_token(email_sender.sent[0][2])

    response = client.post(
        "/v1/auth/magic-link/verify",
        json={"token": raw_token},
        headers=_auth_headers(app_client_creds),
    )
    assert response.status_code == 200
    data = response.get_json()["data"]
    assert data["access_token"]
    assert data["refresh_token"]
    assert data["token_type"] == "Bearer"
    assert data["access_token_expires_at"]
    assert data["refresh_token_expires_at"]


def test_verify_magic_link_rejects_unknown_token(
    client: FlaskClient, app_client_creds: tuple[str, str]
) -> None:
    """An unknown token yields 400 ``MAGIC_LINK_INVALID``."""
    response = client.post(
        "/v1/auth/magic-link/verify",
        json={"token": "not-real"},
        headers=_auth_headers(app_client_creds),
    )
    assert response.status_code == 400
    assert response.get_json()["error"]["code"] == "MAGIC_LINK_INVALID"


def test_verify_magic_link_validates_token_field(
    client: FlaskClient, app_client_creds: tuple[str, str]
) -> None:
    """Missing ``token`` yields 422 ``VALIDATION_ERROR``."""
    response = client.post(
        "/v1/auth/magic-link/verify",
        json={},
        headers=_auth_headers(app_client_creds),
    )
    assert response.status_code == 422
    assert response.get_json()["error"]["code"] == "VALIDATION_ERROR"
