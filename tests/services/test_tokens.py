"""Tests for ``knuckles.services.tokens``.

Exercises refresh-token rotation, reuse detection, expiry handling,
cross-client rejection, and logout. Every path that issues or rotates
a token is covered.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from knuckles.core.exceptions import (
    INVALID_CLIENT,
    REFRESH_TOKEN_EXPIRED,
    REFRESH_TOKEN_INVALID,
    REFRESH_TOKEN_REUSED,
    AppError,
)
from knuckles.data.models import RefreshToken
from knuckles.data.repositories import auth as repo
from knuckles.services import tokens


def _setup_user_and_client(session: Session) -> tuple[str, str]:
    """Create one user + one app client for the tests to consume.

    Args:
        session: Active SQLAlchemy session.

    Returns:
        Tuple of (user_id as str, client_id).
    """
    user = repo.create_user(session, email="user@example.com")
    client = repo.create_app_client(
        session,
        client_id="greenroom-prod",
        app_name="Greenroom Production",
        client_secret_hash="hash",
        allowed_origins=[],
    )
    return str(user.id), client.client_id


def test_issue_session_returns_access_and_refresh(db_session: Session) -> None:
    """``issue_session`` returns a valid access token + refresh plaintext."""
    user_id, client_id = _setup_user_and_client(db_session)

    pair = tokens.issue_session(
        db_session,
        user_id=user_id,
        app_client_id=client_id,
    )

    assert pair.access_token
    assert pair.refresh_token
    assert pair.access_token_expires_at > datetime.now(tz=UTC)
    assert pair.refresh_token_expires_at > datetime.now(tz=UTC) + timedelta(days=29)


def test_issue_session_writes_hashed_refresh_row(db_session: Session) -> None:
    """The refresh row stores the hash, never the plaintext."""
    user_id, client_id = _setup_user_and_client(db_session)

    pair = tokens.issue_session(db_session, user_id=user_id, app_client_id=client_id)

    rows = db_session.query(RefreshToken).all()
    assert len(rows) == 1
    assert rows[0].token_hash != pair.refresh_token
    expected = hashlib.sha256(pair.refresh_token.encode("ascii")).hexdigest()
    assert rows[0].token_hash == expected
    assert rows[0].used_at is None


def test_rotate_refresh_token_issues_new_pair(db_session: Session) -> None:
    """``rotate_refresh_token`` marks the old row used and writes a new one."""
    user_id, client_id = _setup_user_and_client(db_session)
    original = tokens.issue_session(
        db_session, user_id=user_id, app_client_id=client_id
    )

    rotated = tokens.rotate_refresh_token(
        db_session,
        refresh_token=original.refresh_token,
        app_client_id=client_id,
    )

    assert rotated.refresh_token != original.refresh_token
    assert rotated.access_token != original.access_token

    rows = db_session.query(RefreshToken).all()
    assert len(rows) == 2
    used = [r for r in rows if r.used_at is not None]
    active = [r for r in rows if r.used_at is None]
    assert len(used) == 1
    assert len(active) == 1


def test_rotate_refresh_token_detects_reuse(db_session: Session) -> None:
    """Presenting a used token revokes every active token for the user."""
    user_id, client_id = _setup_user_and_client(db_session)
    first = tokens.issue_session(db_session, user_id=user_id, app_client_id=client_id)
    second = tokens.rotate_refresh_token(
        db_session, refresh_token=first.refresh_token, app_client_id=client_id
    )

    # Reuse the already-consumed first token.
    with pytest.raises(AppError) as exc:
        tokens.rotate_refresh_token(
            db_session,
            refresh_token=first.refresh_token,
            app_client_id=client_id,
        )

    assert exc.value.code == REFRESH_TOKEN_REUSED

    # The still-active `second` token must also be revoked now.
    second_hash = hashlib.sha256(second.refresh_token.encode("ascii")).hexdigest()
    row = repo.get_refresh_token_by_hash(db_session, second_hash)
    assert row is not None
    assert row.used_at is not None


def test_rotate_refresh_token_rejects_unknown_token(db_session: Session) -> None:
    """An unrecognized token value is rejected as invalid."""
    _, client_id = _setup_user_and_client(db_session)

    with pytest.raises(AppError) as exc:
        tokens.rotate_refresh_token(
            db_session, refresh_token="not-a-real-token", app_client_id=client_id
        )
    assert exc.value.code == REFRESH_TOKEN_INVALID


def test_rotate_refresh_token_rejects_expired(db_session: Session) -> None:
    """An expired (but not yet used) token is rejected as expired."""
    user_id, client_id = _setup_user_and_client(db_session)
    pair = tokens.issue_session(db_session, user_id=user_id, app_client_id=client_id)

    token_hash = hashlib.sha256(pair.refresh_token.encode("ascii")).hexdigest()
    row = repo.get_refresh_token_by_hash(db_session, token_hash)
    assert row is not None
    row.expires_at = datetime.now(tz=UTC) - timedelta(seconds=1)
    db_session.flush()

    with pytest.raises(AppError) as exc:
        tokens.rotate_refresh_token(
            db_session,
            refresh_token=pair.refresh_token,
            app_client_id=client_id,
        )
    assert exc.value.code == REFRESH_TOKEN_EXPIRED


def test_rotate_refresh_token_rejects_wrong_client(db_session: Session) -> None:
    """A token issued for one client cannot be rotated by another."""
    user_id, client_id = _setup_user_and_client(db_session)
    repo.create_app_client(
        db_session,
        client_id="other-app",
        app_name="Other App",
        client_secret_hash="h",
        allowed_origins=[],
    )
    pair = tokens.issue_session(db_session, user_id=user_id, app_client_id=client_id)

    with pytest.raises(AppError) as exc:
        tokens.rotate_refresh_token(
            db_session,
            refresh_token=pair.refresh_token,
            app_client_id="other-app",
        )
    assert exc.value.code == INVALID_CLIENT


def test_revoke_refresh_token_marks_used(db_session: Session) -> None:
    """``revoke_refresh_token`` marks the row as used."""
    user_id, client_id = _setup_user_and_client(db_session)
    pair = tokens.issue_session(db_session, user_id=user_id, app_client_id=client_id)

    tokens.revoke_refresh_token(
        db_session,
        refresh_token=pair.refresh_token,
        app_client_id=client_id,
    )

    token_hash = hashlib.sha256(pair.refresh_token.encode("ascii")).hexdigest()
    row = repo.get_refresh_token_by_hash(db_session, token_hash)
    assert row is not None
    assert row.used_at is not None


def test_revoke_refresh_token_silent_on_unknown(db_session: Session) -> None:
    """Revoking an unknown token is a no-op (idempotent logout)."""
    _, client_id = _setup_user_and_client(db_session)

    tokens.revoke_refresh_token(
        db_session,
        refresh_token="unknown",
        app_client_id=client_id,
    )
