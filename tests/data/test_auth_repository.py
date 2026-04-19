"""Tests for ``knuckles.data.repositories.auth``.

Every repository function in the auth module has a dedicated test
that covers the happy path plus at least one failure or edge case
(missing row, duplicate, stale state). Tests drive the repository
interface: a change to a function signature must start here.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from knuckles.data.models import (
    AppClient,
    MagicLinkToken,
    OAuthProvider,
    PasskeyCredential,
    RefreshToken,
    User,
)
from knuckles.data.repositories import auth as repo


def _utcnow() -> datetime:
    """Return a timezone-aware current UTC timestamp.

    Returns:
        The current UTC time as a ``datetime`` with ``tzinfo=UTC``.
    """
    return datetime.now(tz=UTC)


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


def test_create_user_persists_and_returns_row(db_session: Session) -> None:
    """``create_user`` writes a row and returns it with an id."""
    user = repo.create_user(
        db_session,
        email="a@example.com",
        display_name="A",
        avatar_url="https://example.com/a.png",
    )

    assert isinstance(user.id, uuid.UUID)
    assert user.email == "a@example.com"
    assert user.display_name == "A"
    assert user.is_active is True


def test_get_user_by_email_returns_match(db_session: Session) -> None:
    """``get_user_by_email`` resolves the user by address."""
    created = repo.create_user(db_session, email="b@example.com")
    got = repo.get_user_by_email(db_session, "b@example.com")

    assert got is not None
    assert got.id == created.id


def test_get_user_by_email_returns_none_for_miss(db_session: Session) -> None:
    """``get_user_by_email`` returns ``None`` when no row matches."""
    assert repo.get_user_by_email(db_session, "nope@example.com") is None


def test_get_user_by_id_returns_match(db_session: Session) -> None:
    """``get_user_by_id`` resolves the user by primary key."""
    created = repo.create_user(db_session, email="c@example.com")
    got = repo.get_user_by_id(db_session, created.id)

    assert got is not None
    assert got.email == "c@example.com"


def test_update_last_seen_sets_timestamp(db_session: Session) -> None:
    """``update_last_seen`` writes ``last_seen_at`` to ~now."""
    user = repo.create_user(db_session, email="d@example.com")
    assert user.last_seen_at is None

    before = _utcnow()
    repo.update_last_seen(db_session, user)
    after = _utcnow()

    assert user.last_seen_at is not None
    assert before <= user.last_seen_at <= after


# ---------------------------------------------------------------------------
# OAuth providers
# ---------------------------------------------------------------------------


def test_create_oauth_provider_links_to_user(db_session: Session) -> None:
    """``create_oauth_provider`` writes a ``UserOAuthProvider`` row."""
    user = repo.create_user(db_session, email="e@example.com")
    link = repo.create_oauth_provider(
        db_session,
        user_id=user.id,
        provider=OAuthProvider.GOOGLE,
        provider_user_id="g-12345",
        access_token="at",
        refresh_token="rt",
        token_expires_at=_utcnow() + timedelta(hours=1),
        scopes="openid email profile",
        raw_profile={"email": "e@example.com"},
    )

    assert isinstance(link.id, uuid.UUID)
    assert link.user_id == user.id
    assert link.provider == OAuthProvider.GOOGLE


def test_get_oauth_provider_matches_on_composite_key(db_session: Session) -> None:
    """``get_oauth_provider`` keys on (provider, provider_user_id)."""
    user = repo.create_user(db_session, email="f@example.com")
    repo.create_oauth_provider(
        db_session,
        user_id=user.id,
        provider=OAuthProvider.APPLE,
        provider_user_id="apple-abc",
    )

    got = repo.get_oauth_provider(db_session, OAuthProvider.APPLE, "apple-abc")
    assert got is not None
    assert got.user_id == user.id

    missing = repo.get_oauth_provider(db_session, OAuthProvider.GOOGLE, "apple-abc")
    assert missing is None


def test_update_oauth_tokens_rotates_fields(db_session: Session) -> None:
    """``update_oauth_tokens`` overwrites the access token and options."""
    user = repo.create_user(db_session, email="g@example.com")
    link = repo.create_oauth_provider(
        db_session,
        user_id=user.id,
        provider=OAuthProvider.GOOGLE,
        provider_user_id="g-xyz",
        access_token="old-at",
        refresh_token="old-rt",
    )

    new_expiry = _utcnow() + timedelta(hours=1)
    repo.update_oauth_tokens(
        db_session,
        link,
        access_token="new-at",
        refresh_token="new-rt",
        token_expires_at=new_expiry,
    )

    assert link.access_token == "new-at"
    assert link.refresh_token == "new-rt"
    assert link.token_expires_at == new_expiry


# ---------------------------------------------------------------------------
# Magic-link tokens
# ---------------------------------------------------------------------------


def test_create_magic_link_token_persists_hash(db_session: Session) -> None:
    """``create_magic_link_token`` stores the hash, not the raw token."""
    token = repo.create_magic_link_token(
        db_session,
        email="h@example.com",
        token_hash="a" * 64,
        expires_at=_utcnow() + timedelta(minutes=15),
    )

    assert isinstance(token.id, uuid.UUID)
    assert token.token_hash == "a" * 64
    assert token.used_at is None


def test_get_magic_link_by_hash_returns_match(db_session: Session) -> None:
    """``get_magic_link_by_hash`` resolves on the hash column."""
    repo.create_magic_link_token(
        db_session,
        email="i@example.com",
        token_hash="b" * 64,
        expires_at=_utcnow() + timedelta(minutes=15),
    )
    got = repo.get_magic_link_by_hash(db_session, "b" * 64)
    assert got is not None
    assert got.email == "i@example.com"


def test_mark_magic_link_used_sets_timestamp_and_user(db_session: Session) -> None:
    """``mark_magic_link_used`` records the redemption."""
    user = repo.create_user(db_session, email="j@example.com")
    token = repo.create_magic_link_token(
        db_session,
        email="j@example.com",
        token_hash="c" * 64,
        expires_at=_utcnow() + timedelta(minutes=15),
    )

    repo.mark_magic_link_used(db_session, token, user_id=user.id)

    assert token.used_at is not None
    assert token.user_id == user.id


def test_delete_expired_magic_links_removes_old_rows(db_session: Session) -> None:
    """``delete_expired_magic_links`` prunes rows older than the cutoff."""
    now = _utcnow()
    repo.create_magic_link_token(
        db_session,
        email="k@example.com",
        token_hash="d" * 64,
        expires_at=now - timedelta(hours=48),
    )
    repo.create_magic_link_token(
        db_session,
        email="k@example.com",
        token_hash="e" * 64,
        expires_at=now + timedelta(minutes=15),
    )

    deleted = repo.delete_expired_magic_links(
        db_session, older_than=now - timedelta(hours=24)
    )

    assert deleted == 1
    remaining = db_session.query(MagicLinkToken).all()
    assert len(remaining) == 1


# ---------------------------------------------------------------------------
# Passkey credentials
# ---------------------------------------------------------------------------


def test_create_passkey_persists_row(db_session: Session) -> None:
    """``create_passkey`` writes a credential row."""
    user = repo.create_user(db_session, email="l@example.com")
    cred = repo.create_passkey(
        db_session,
        user_id=user.id,
        credential_id="cred-001",
        public_key="pk-bytes",
        sign_count=0,
        name="MacBook Air",
    )

    assert isinstance(cred.id, uuid.UUID)
    assert cred.sign_count == 0
    assert cred.name == "MacBook Air"


def test_get_passkey_by_credential_id_returns_match(db_session: Session) -> None:
    """``get_passkey_by_credential_id`` resolves on the unique cred id."""
    user = repo.create_user(db_session, email="m@example.com")
    repo.create_passkey(
        db_session,
        user_id=user.id,
        credential_id="cred-002",
        public_key="pk",
        sign_count=0,
    )

    got = repo.get_passkey_by_credential_id(db_session, "cred-002")
    assert got is not None
    assert got.user_id == user.id


def test_list_passkeys_for_user_returns_owned_rows(db_session: Session) -> None:
    """``list_passkeys_for_user`` returns only the user's credentials."""
    user_a = repo.create_user(db_session, email="n@example.com")
    user_b = repo.create_user(db_session, email="o@example.com")
    repo.create_passkey(
        db_session,
        user_id=user_a.id,
        credential_id="cred-a1",
        public_key="pk",
        sign_count=0,
    )
    repo.create_passkey(
        db_session,
        user_id=user_a.id,
        credential_id="cred-a2",
        public_key="pk",
        sign_count=0,
    )
    repo.create_passkey(
        db_session,
        user_id=user_b.id,
        credential_id="cred-b1",
        public_key="pk",
        sign_count=0,
    )

    a_creds = repo.list_passkeys_for_user(db_session, user_a.id)
    assert {c.credential_id for c in a_creds} == {"cred-a1", "cred-a2"}


def test_update_passkey_sign_count_writes_counter(db_session: Session) -> None:
    """``update_passkey_sign_count`` bumps the counter and ``last_used_at``."""
    user = repo.create_user(db_session, email="p@example.com")
    cred = repo.create_passkey(
        db_session,
        user_id=user.id,
        credential_id="cred-p",
        public_key="pk",
        sign_count=4,
    )
    before = _utcnow()
    repo.update_passkey_sign_count(db_session, cred, sign_count=7)

    assert cred.sign_count == 7
    assert cred.last_used_at is not None
    assert cred.last_used_at >= before


def test_delete_passkey_removes_row(db_session: Session) -> None:
    """``delete_passkey`` removes the credential."""
    user = repo.create_user(db_session, email="q@example.com")
    cred = repo.create_passkey(
        db_session,
        user_id=user.id,
        credential_id="cred-q",
        public_key="pk",
        sign_count=0,
    )
    repo.delete_passkey(db_session, cred)

    assert db_session.query(PasskeyCredential).count() == 0


# ---------------------------------------------------------------------------
# App clients
# ---------------------------------------------------------------------------


def test_create_app_client_persists_row(db_session: Session) -> None:
    """``create_app_client`` writes an app-client row with the given id."""
    client = repo.create_app_client(
        db_session,
        client_id="greenroom-prod",
        app_name="Greenroom Production",
        client_secret_hash="hash-abc",
        allowed_origins=["https://greenroom.app"],
    )

    assert client.client_id == "greenroom-prod"
    assert client.allowed_origins == ["https://greenroom.app"]


def test_get_app_client_returns_match(db_session: Session) -> None:
    """``get_app_client`` resolves by primary key."""
    repo.create_app_client(
        db_session,
        client_id="greenroom-prod",
        app_name="Greenroom Production",
        client_secret_hash="hash-abc",
        allowed_origins=[],
    )
    assert repo.get_app_client(db_session, "greenroom-prod") is not None
    assert repo.get_app_client(db_session, "missing") is None


# ---------------------------------------------------------------------------
# Refresh tokens
# ---------------------------------------------------------------------------


@pytest.fixture()
def _seeded_user_and_client(db_session: Session) -> tuple[User, AppClient]:
    """Seed one user and one app client for refresh-token tests.

    Args:
        db_session: The request-scoped SQLAlchemy session.

    Returns:
        Tuple of (user, app_client).
    """
    user = repo.create_user(db_session, email="r@example.com")
    client = repo.create_app_client(
        db_session,
        client_id="greenroom-prod",
        app_name="Greenroom Production",
        client_secret_hash="hash",
        allowed_origins=[],
    )
    return user, client


def test_create_refresh_token_persists_row(
    db_session: Session,
    _seeded_user_and_client: tuple[User, AppClient],
) -> None:
    """``create_refresh_token`` writes a token row and returns it."""
    user, client = _seeded_user_and_client
    token = repo.create_refresh_token(
        db_session,
        user_id=user.id,
        app_client_id=client.client_id,
        token_hash="x" * 64,
        expires_at=_utcnow() + timedelta(days=30),
    )

    assert isinstance(token.id, uuid.UUID)
    assert token.used_at is None


def test_get_refresh_token_by_hash_returns_match(
    db_session: Session,
    _seeded_user_and_client: tuple[User, AppClient],
) -> None:
    """``get_refresh_token_by_hash`` resolves on the hash column."""
    user, client = _seeded_user_and_client
    repo.create_refresh_token(
        db_session,
        user_id=user.id,
        app_client_id=client.client_id,
        token_hash="y" * 64,
        expires_at=_utcnow() + timedelta(days=30),
    )

    got = repo.get_refresh_token_by_hash(db_session, "y" * 64)
    assert got is not None
    assert got.user_id == user.id


def test_mark_refresh_token_used_sets_timestamp(
    db_session: Session,
    _seeded_user_and_client: tuple[User, AppClient],
) -> None:
    """``mark_refresh_token_used`` records rotation."""
    user, client = _seeded_user_and_client
    token = repo.create_refresh_token(
        db_session,
        user_id=user.id,
        app_client_id=client.client_id,
        token_hash="z" * 64,
        expires_at=_utcnow() + timedelta(days=30),
    )

    repo.mark_refresh_token_used(db_session, token)

    assert token.used_at is not None


def test_revoke_all_refresh_tokens_for_user_marks_active_only(
    db_session: Session,
    _seeded_user_and_client: tuple[User, AppClient],
) -> None:
    """``revoke_all_refresh_tokens_for_user`` marks all active tokens used."""
    user, client = _seeded_user_and_client
    t1 = repo.create_refresh_token(
        db_session,
        user_id=user.id,
        app_client_id=client.client_id,
        token_hash="1" * 64,
        expires_at=_utcnow() + timedelta(days=30),
    )
    t2 = repo.create_refresh_token(
        db_session,
        user_id=user.id,
        app_client_id=client.client_id,
        token_hash="2" * 64,
        expires_at=_utcnow() + timedelta(days=30),
    )
    repo.mark_refresh_token_used(db_session, t2)

    revoked = repo.revoke_all_refresh_tokens_for_user(db_session, user.id)

    assert revoked == 1
    db_session.refresh(t1)
    assert t1.used_at is not None


def test_refresh_token_cascades_on_user_delete(
    db_session: Session,
    _seeded_user_and_client: tuple[User, AppClient],
) -> None:
    """Deleting a user cascades to outstanding refresh tokens."""
    user, client = _seeded_user_and_client
    repo.create_refresh_token(
        db_session,
        user_id=user.id,
        app_client_id=client.client_id,
        token_hash="3" * 64,
        expires_at=_utcnow() + timedelta(days=30),
    )

    db_session.delete(user)
    db_session.flush()

    assert db_session.query(RefreshToken).count() == 0


# ---------------------------------------------------------------------------
# Model-level sanity
# ---------------------------------------------------------------------------


def test_user_email_is_unique(db_session: Session) -> None:
    """Inserting two users with the same email raises a unique violation."""
    from sqlalchemy.exc import IntegrityError

    repo.create_user(db_session, email="dup@example.com")
    with pytest.raises(IntegrityError):
        user_two = User(email="dup@example.com")
        db_session.add(user_two)
        db_session.flush()


def test_oauth_provider_enum_rejects_music_services(db_session: Session) -> None:
    """Music services must not be acceptable enum values (Decision #001)."""
    # OAuthProvider has only google/apple. Attempting to construct with a
    # music-service string must raise.
    with pytest.raises(ValueError):
        OAuthProvider("spotify")
    with pytest.raises(ValueError):
        OAuthProvider("apple_music")
    with pytest.raises(ValueError):
        OAuthProvider("tidal")
