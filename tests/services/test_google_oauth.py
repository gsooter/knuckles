"""Tests for :mod:`knuckles.services.google_oauth`.

The service wraps the Google OAuth 2.0 + OIDC code flow:

* :func:`build_authorize_url` mints a state JWT, embeds the consuming
  app's redirect URI inside it, and assembles the consent URL.
* :func:`complete` verifies the state, exchanges the code for tokens,
  fetches the userinfo profile, upserts the user + OAuth link row, and
  returns a Knuckles :class:`~knuckles.services.tokens.TokenPair`.

Network calls are stubbed at the module level so these tests run
hermetically against the SQLite ``db_session`` fixture.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy.orm import Session

from knuckles.core.exceptions import GOOGLE_AUTH_FAILED, AppError
from knuckles.data.models import OAuthProvider
from knuckles.data.repositories import auth as repo
from knuckles.services import google_oauth


def _register_client(db_session: Session) -> str:
    """Insert a minimal app-client row and return its id.

    Args:
        db_session: Active SQLAlchemy session.

    Returns:
        The new ``app_clients.client_id``.
    """
    repo.create_app_client(
        db_session,
        client_id="greenroom-prod",
        app_name="Greenroom",
        client_secret_hash="hash",
        allowed_origins=["http://localhost:3000"],
    )
    return "greenroom-prod"


def _stub_google(
    monkeypatch: pytest.MonkeyPatch,
    *,
    profile: dict[str, Any] | None = None,
    tokens: dict[str, Any] | None = None,
) -> None:
    """Replace the Google HTTP helpers with predictable in-memory fakes.

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
            "picture": "https://example.com/avatar.png",
        },
    )


def test_build_authorize_url_embeds_state_and_redirect(
    db_session: Session,
) -> None:
    """The authorize URL carries a state JWT bound to the redirect URI."""
    client_id = _register_client(db_session)

    result = google_oauth.build_authorize_url(
        redirect_uri="http://localhost:3000/auth/google/callback",
        app_client_id=client_id,
    )

    parts = urlsplit(result.authorize_url)
    qs = parse_qs(parts.query)
    assert parts.netloc == "accounts.google.com"
    assert qs["client_id"]
    assert qs["redirect_uri"] == ["http://localhost:3000/auth/google/callback"]
    assert qs["response_type"] == ["code"]
    assert qs["state"] == [result.state]
    # State JWT decodes back to its embedded redirect URI + app_client_id.
    from knuckles.core.state_jwt import verify_state

    claims = verify_state(result.state, purpose="google_oauth")
    assert claims["redirect_uri"] == "http://localhost:3000/auth/google/callback"
    assert claims["app_client_id"] == client_id


def test_complete_creates_user_and_returns_token_pair(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """First sign-in upserts a user, links the provider, and returns tokens."""
    client_id = _register_client(db_session)
    _stub_google(monkeypatch)

    issued = google_oauth.build_authorize_url(
        redirect_uri="http://localhost:3000/auth/google/callback",
        app_client_id=client_id,
    )

    pair = google_oauth.complete(
        db_session,
        code="abc",
        state=issued.state,
        app_client_id=client_id,
    )
    assert pair.access_token
    assert pair.refresh_token

    user = repo.get_user_by_email(db_session, "user@example.com")
    assert user is not None
    assert user.display_name == "User Example"

    link = repo.get_oauth_provider(db_session, OAuthProvider.GOOGLE, "google-sub-123")
    assert link is not None
    assert link.user_id == user.id
    assert link.access_token == "google-access"
    assert link.refresh_token == "google-refresh"


def test_complete_reuses_existing_user_by_provider_id(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A repeat sign-in updates the existing link row, doesn't duplicate."""
    client_id = _register_client(db_session)
    _stub_google(monkeypatch)

    issued = google_oauth.build_authorize_url(
        redirect_uri="http://localhost:3000/auth/google/callback",
        app_client_id=client_id,
    )
    google_oauth.complete(
        db_session, code="abc", state=issued.state, app_client_id=client_id
    )

    second = google_oauth.build_authorize_url(
        redirect_uri="http://localhost:3000/auth/google/callback",
        app_client_id=client_id,
    )
    google_oauth.complete(
        db_session, code="def", state=second.state, app_client_id=client_id
    )

    user = repo.get_user_by_email(db_session, "user@example.com")
    assert user is not None
    assert len(user.oauth_providers) == 1


def test_complete_links_to_existing_email(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Email match on a user with no Google link adds a new provider row."""
    client_id = _register_client(db_session)
    existing = repo.create_user(db_session, email="user@example.com")
    _stub_google(monkeypatch)

    issued = google_oauth.build_authorize_url(
        redirect_uri="http://localhost:3000/auth/google/callback",
        app_client_id=client_id,
    )
    google_oauth.complete(
        db_session, code="abc", state=issued.state, app_client_id=client_id
    )

    link = repo.get_oauth_provider(db_session, OAuthProvider.GOOGLE, "google-sub-123")
    assert link is not None
    assert link.user_id == existing.id


def test_complete_rejects_unverified_email(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Unverified Google email yields ``GOOGLE_AUTH_FAILED``."""
    client_id = _register_client(db_session)
    _stub_google(
        monkeypatch,
        profile={
            "sub": "google-sub-123",
            "email": "shady@example.com",
            "email_verified": False,
            "name": "Shady",
            "picture": None,
        },
    )

    issued = google_oauth.build_authorize_url(
        redirect_uri="http://localhost:3000/auth/google/callback",
        app_client_id=client_id,
    )

    with pytest.raises(AppError) as exc:
        google_oauth.complete(
            db_session, code="abc", state=issued.state, app_client_id=client_id
        )
    assert exc.value.code == GOOGLE_AUTH_FAILED


def test_complete_rejects_invalid_state(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A forged or expired state JWT yields ``GOOGLE_AUTH_FAILED``."""
    client_id = _register_client(db_session)
    _stub_google(monkeypatch)

    with pytest.raises(AppError) as exc:
        google_oauth.complete(
            db_session,
            code="abc",
            state="not.a.real.jwt",
            app_client_id=client_id,
        )
    assert exc.value.code == GOOGLE_AUTH_FAILED


def test_complete_rejects_state_for_wrong_app_client(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A state minted for one app cannot be redeemed by another."""
    client_id = _register_client(db_session)
    repo.create_app_client(
        db_session,
        client_id="other-app",
        app_name="Other",
        client_secret_hash="hash",
        allowed_origins=["http://other.test"],
    )
    _stub_google(monkeypatch)

    issued = google_oauth.build_authorize_url(
        redirect_uri="http://localhost:3000/auth/google/callback",
        app_client_id=client_id,
    )

    with pytest.raises(AppError) as exc:
        google_oauth.complete(
            db_session, code="abc", state=issued.state, app_client_id="other-app"
        )
    assert exc.value.code == GOOGLE_AUTH_FAILED
