"""Tests for :mod:`knuckles.services.apple_oauth`.

Apple's quirks vs Google: a rotating ES256 ``client_secret`` JWT, no
userinfo endpoint (identity comes from the id_token), string-encoded
``email_verified`` and ``is_private_email`` claims, and a name that
only arrives in the ``user`` form payload on the *first* sign-in.

The three monkeypatchable seams (``_mint_client_secret``, ``_post_token``,
``_verify_id_token``) keep these tests hermetic without touching
:mod:`requests` or :mod:`jwt` globals.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy.orm import Session

from knuckles.core.exceptions import APPLE_AUTH_FAILED, AppError
from knuckles.data.models import OAuthProvider
from knuckles.data.repositories import auth as repo
from knuckles.services import apple_oauth


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


def test_build_authorize_url_uses_form_post_response_mode(
    db_session: Session,
) -> None:
    """The Apple consent URL requests ``response_mode=form_post``."""
    client_id = _register_client(db_session)

    result = apple_oauth.build_authorize_url(
        redirect_uri="http://localhost:3000/auth/apple/callback",
        app_client_id=client_id,
    )

    parts = urlsplit(result.authorize_url)
    qs = parse_qs(parts.query)
    assert parts.netloc == "appleid.apple.com"
    assert qs["response_type"] == ["code"]
    assert qs["response_mode"] == ["form_post"]
    assert qs["scope"] == ["name email"]
    assert qs["state"] == [result.state]

    from knuckles.core.state_jwt import verify_state

    claims = verify_state(result.state, purpose="apple_oauth")
    assert claims["redirect_uri"] == "http://localhost:3000/auth/apple/callback"
    assert claims["app_client_id"] == client_id


def test_complete_creates_user_and_returns_token_pair(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """First sign-in upserts a user, links Apple, and mints tokens."""
    client_id = _register_client(db_session)
    _stub_apple(monkeypatch)

    issued = apple_oauth.build_authorize_url(
        redirect_uri="http://localhost:3000/auth/apple/callback",
        app_client_id=client_id,
    )
    pair = apple_oauth.complete(
        db_session,
        code="abc",
        state=issued.state,
        app_client_id=client_id,
        user_data={"name": {"firstName": "User", "lastName": "Example"}},
    )
    assert pair.access_token
    assert pair.refresh_token

    user = repo.get_user_by_email(db_session, "user@example.com")
    assert user is not None
    assert user.display_name == "User Example"

    link = repo.get_oauth_provider(db_session, OAuthProvider.APPLE, "apple-sub-123")
    assert link is not None
    assert link.user_id == user.id
    assert link.access_token == "apple-access"
    assert link.refresh_token == "apple-refresh"


def test_complete_accepts_relay_email_when_unverified(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Apple private-relay addresses arrive unverified but are still trusted."""
    client_id = _register_client(db_session)
    _stub_apple(
        monkeypatch,
        profile={
            "sub": "apple-sub-relay",
            "email": "abc123@privaterelay.appleid.com",
            "email_verified": "false",
            "is_private_email": "true",
        },
    )

    issued = apple_oauth.build_authorize_url(
        redirect_uri="http://localhost:3000/auth/apple/callback",
        app_client_id=client_id,
    )
    pair = apple_oauth.complete(
        db_session, code="abc", state=issued.state, app_client_id=client_id
    )
    assert pair.access_token

    user = repo.get_user_by_email(db_session, "abc123@privaterelay.appleid.com")
    assert user is not None


def test_complete_rejects_unverified_non_relay_email(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An unverified email that isn't a private-relay address is rejected."""
    client_id = _register_client(db_session)
    _stub_apple(
        monkeypatch,
        profile={
            "sub": "apple-sub-shady",
            "email": "shady@example.com",
            "email_verified": "false",
            "is_private_email": "false",
        },
    )

    issued = apple_oauth.build_authorize_url(
        redirect_uri="http://localhost:3000/auth/apple/callback",
        app_client_id=client_id,
    )

    with pytest.raises(AppError) as exc:
        apple_oauth.complete(
            db_session, code="abc", state=issued.state, app_client_id=client_id
        )
    assert exc.value.code == APPLE_AUTH_FAILED


def test_complete_rejects_invalid_state(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A forged state JWT yields ``APPLE_AUTH_FAILED``."""
    client_id = _register_client(db_session)
    _stub_apple(monkeypatch)

    with pytest.raises(AppError) as exc:
        apple_oauth.complete(
            db_session,
            code="abc",
            state="not.a.real.jwt",
            app_client_id=client_id,
        )
    assert exc.value.code == APPLE_AUTH_FAILED


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
    _stub_apple(monkeypatch)

    issued = apple_oauth.build_authorize_url(
        redirect_uri="http://localhost:3000/auth/apple/callback",
        app_client_id=client_id,
    )

    with pytest.raises(AppError) as exc:
        apple_oauth.complete(
            db_session, code="abc", state=issued.state, app_client_id="other-app"
        )
    assert exc.value.code == APPLE_AUTH_FAILED


def test_complete_rejects_missing_id_token(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Token response without an id_token yields ``APPLE_AUTH_FAILED``."""
    client_id = _register_client(db_session)
    _stub_apple(
        monkeypatch,
        tokens={
            "access_token": "apple-access",
            "refresh_token": "apple-refresh",
            "expires_in": 3600,
        },
    )

    issued = apple_oauth.build_authorize_url(
        redirect_uri="http://localhost:3000/auth/apple/callback",
        app_client_id=client_id,
    )

    with pytest.raises(AppError) as exc:
        apple_oauth.complete(
            db_session, code="abc", state=issued.state, app_client_id=client_id
        )
    assert exc.value.code == APPLE_AUTH_FAILED


def test_complete_reuses_existing_user_by_provider_id(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A repeat sign-in updates the existing link row, doesn't duplicate."""
    client_id = _register_client(db_session)
    _stub_apple(monkeypatch)

    issued = apple_oauth.build_authorize_url(
        redirect_uri="http://localhost:3000/auth/apple/callback",
        app_client_id=client_id,
    )
    apple_oauth.complete(
        db_session, code="abc", state=issued.state, app_client_id=client_id
    )

    second = apple_oauth.build_authorize_url(
        redirect_uri="http://localhost:3000/auth/apple/callback",
        app_client_id=client_id,
    )
    apple_oauth.complete(
        db_session, code="def", state=second.state, app_client_id=client_id
    )

    user = repo.get_user_by_email(db_session, "user@example.com")
    assert user is not None
    assert len(user.oauth_providers) == 1


def test_complete_links_to_existing_email(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Email match on a user with no Apple link adds a new provider row."""
    client_id = _register_client(db_session)
    existing = repo.create_user(db_session, email="user@example.com")
    _stub_apple(monkeypatch)

    issued = apple_oauth.build_authorize_url(
        redirect_uri="http://localhost:3000/auth/apple/callback",
        app_client_id=client_id,
    )
    apple_oauth.complete(
        db_session, code="abc", state=issued.state, app_client_id=client_id
    )

    link = repo.get_oauth_provider(db_session, OAuthProvider.APPLE, "apple-sub-123")
    assert link is not None
    assert link.user_id == existing.id


def test_complete_omits_display_name_when_user_data_missing(
    db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Subsequent sign-ins (no ``user_data``) don't overwrite the existing name."""
    client_id = _register_client(db_session)
    _stub_apple(monkeypatch)

    issued = apple_oauth.build_authorize_url(
        redirect_uri="http://localhost:3000/auth/apple/callback",
        app_client_id=client_id,
    )
    apple_oauth.complete(
        db_session,
        code="abc",
        state=issued.state,
        app_client_id=client_id,
        user_data=None,
    )

    user = repo.get_user_by_email(db_session, "user@example.com")
    assert user is not None
    assert user.display_name is None
