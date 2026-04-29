"""Repository functions for every Knuckles-owned table.

All database access in Knuckles goes through this module. Route
handlers and service functions never run SQL or construct ORM
queries directly — they call the functions below.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import cast

from sqlalchemy import CursorResult, delete, select, update
from sqlalchemy.orm import Session

from knuckles.data.models import (
    AppClient,
    MagicLinkToken,
    OAuthProvider,
    PasskeyCredential,
    RefreshToken,
    User,
    UserOAuthProvider,
)

# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------


def create_user(
    session: Session,
    *,
    email: str,
    display_name: str | None = None,
    avatar_url: str | None = None,
) -> User:
    """Insert a new user row.

    Args:
        session: Active SQLAlchemy session.
        email: Canonical email address for the user.
        display_name: Optional display name from the identity provider.
        avatar_url: Optional avatar URL from the identity provider.

    Returns:
        The newly created ``User``.
    """
    user = User(
        email=email,
        display_name=display_name,
        avatar_url=avatar_url,
    )
    session.add(user)
    session.flush()
    return user


def get_user_by_id(session: Session, user_id: uuid.UUID) -> User | None:
    """Fetch a user by primary key.

    Args:
        session: Active SQLAlchemy session.
        user_id: UUID of the user.

    Returns:
        The ``User`` or ``None`` if no row matches.
    """
    return session.get(User, user_id)


def get_user_by_email(session: Session, email: str) -> User | None:
    """Fetch a user by email address.

    Args:
        session: Active SQLAlchemy session.
        email: Email address to look up.

    Returns:
        The ``User`` or ``None`` if no row matches.
    """
    stmt = select(User).where(User.email == email)
    return session.execute(stmt).scalar_one_or_none()


def update_last_seen(session: Session, user: User) -> User:
    """Set ``users.last_seen_at`` to the current UTC time.

    Args:
        session: Active SQLAlchemy session.
        user: The user row to update.

    Returns:
        The same ``User`` with the timestamp set.
    """
    user.last_seen_at = datetime.now(tz=UTC)
    session.flush()
    return user


# ---------------------------------------------------------------------------
# OAuth providers
# ---------------------------------------------------------------------------


def create_oauth_provider(
    session: Session,
    *,
    user_id: uuid.UUID,
    provider: OAuthProvider,
    provider_user_id: str,
    access_token: str | None = None,
    refresh_token: str | None = None,
    token_expires_at: datetime | None = None,
    scopes: str | None = None,
    raw_profile: dict[str, object] | None = None,
) -> UserOAuthProvider:
    """Insert a ``UserOAuthProvider`` row linking a provider account to a user.

    Args:
        session: Active SQLAlchemy session.
        user_id: UUID of the owning user.
        provider: Identity provider (``google`` or ``apple``).
        provider_user_id: The identifier returned by the provider.
        access_token: Access token from the provider, if any.
        refresh_token: Refresh token from the provider, if any.
        token_expires_at: Expiry timestamp of the provider access token.
        scopes: Space-delimited scope string granted by the user.
        raw_profile: The profile payload returned by the provider.

    Returns:
        The newly created ``UserOAuthProvider``.
    """
    link = UserOAuthProvider(
        user_id=user_id,
        provider=provider,
        provider_user_id=provider_user_id,
        access_token=access_token,
        refresh_token=refresh_token,
        token_expires_at=token_expires_at,
        scopes=scopes,
        raw_profile=raw_profile,
    )
    session.add(link)
    session.flush()
    return link


def get_oauth_provider(
    session: Session,
    provider: OAuthProvider,
    provider_user_id: str,
) -> UserOAuthProvider | None:
    """Fetch an OAuth link by (provider, provider_user_id).

    Args:
        session: Active SQLAlchemy session.
        provider: Identity provider to look up.
        provider_user_id: The identifier from the provider.

    Returns:
        The ``UserOAuthProvider`` or ``None`` if no row matches.
    """
    stmt = select(UserOAuthProvider).where(
        UserOAuthProvider.provider == provider,
        UserOAuthProvider.provider_user_id == provider_user_id,
    )
    return session.execute(stmt).scalar_one_or_none()


def update_oauth_tokens(
    session: Session,
    link: UserOAuthProvider,
    *,
    access_token: str,
    refresh_token: str | None = None,
    token_expires_at: datetime | None = None,
) -> UserOAuthProvider:
    """Overwrite the stored OAuth tokens on an existing link row.

    Args:
        session: Active SQLAlchemy session.
        link: The existing link row to update.
        access_token: New access token from the provider.
        refresh_token: Optional new refresh token.
        token_expires_at: Optional new expiry timestamp.

    Returns:
        The same link row with the new values applied.
    """
    link.access_token = access_token
    if refresh_token is not None:
        link.refresh_token = refresh_token
    if token_expires_at is not None:
        link.token_expires_at = token_expires_at
    session.flush()
    return link


# ---------------------------------------------------------------------------
# Magic-link tokens
# ---------------------------------------------------------------------------


def create_magic_link_token(
    session: Session,
    *,
    email: str,
    token_hash: str,
    expires_at: datetime,
    user_id: uuid.UUID | None = None,
) -> MagicLinkToken:
    """Insert a pending magic-link token row.

    Args:
        session: Active SQLAlchemy session.
        email: Address the link was issued to.
        token_hash: SHA-256 hex digest of the raw token.
        expires_at: Hard expiry of the token.
        user_id: Optional user id — left ``None`` for first-time
            addresses and populated on redemption.

    Returns:
        The newly created ``MagicLinkToken``.
    """
    token = MagicLinkToken(
        email=email,
        token_hash=token_hash,
        expires_at=expires_at,
        user_id=user_id,
    )
    session.add(token)
    session.flush()
    return token


def get_magic_link_by_hash(session: Session, token_hash: str) -> MagicLinkToken | None:
    """Fetch a magic-link row by its SHA-256 hash.

    Args:
        session: Active SQLAlchemy session.
        token_hash: SHA-256 hex digest to look up.

    Returns:
        The ``MagicLinkToken`` or ``None`` if no row matches.
    """
    stmt = select(MagicLinkToken).where(MagicLinkToken.token_hash == token_hash)
    return session.execute(stmt).scalar_one_or_none()


def mark_magic_link_used(
    session: Session,
    token: MagicLinkToken,
    *,
    user_id: uuid.UUID,
) -> MagicLinkToken:
    """Record that a magic-link row has been redeemed.

    Args:
        session: Active SQLAlchemy session.
        token: The token row to update.
        user_id: The user the link authenticated.

    Returns:
        The same token row with ``used_at`` set.
    """
    token.used_at = datetime.now(tz=UTC)
    token.user_id = user_id
    session.flush()
    return token


def delete_expired_magic_links(session: Session, *, older_than: datetime) -> int:
    """Delete magic-link rows whose ``expires_at`` is before ``older_than``.

    Args:
        session: Active SQLAlchemy session.
        older_than: Cutoff timestamp; rows older than this are deleted.

    Returns:
        The number of rows deleted.
    """
    stmt = delete(MagicLinkToken).where(MagicLinkToken.expires_at < older_than)
    result = cast("CursorResult[object]", session.execute(stmt))
    session.flush()
    return int(result.rowcount or 0)


# ---------------------------------------------------------------------------
# Passkey credentials
# ---------------------------------------------------------------------------


def create_passkey(
    session: Session,
    *,
    user_id: uuid.UUID,
    credential_id: str,
    public_key: str,
    sign_count: int,
    transports: str | None = None,
    name: str | None = None,
) -> PasskeyCredential:
    """Insert a passkey credential row.

    Args:
        session: Active SQLAlchemy session.
        user_id: UUID of the owning user.
        credential_id: Base64url-encoded credential id.
        public_key: CBOR public key (base64url) for the credential.
        sign_count: Initial sign count reported by the authenticator.
        transports: Optional comma-delimited transport hints.
        name: Optional human-facing label.

    Returns:
        The newly created ``PasskeyCredential``.
    """
    cred = PasskeyCredential(
        user_id=user_id,
        credential_id=credential_id,
        public_key=public_key,
        sign_count=sign_count,
        transports=transports,
        name=name,
    )
    session.add(cred)
    session.flush()
    return cred


def get_passkey_by_credential_id(
    session: Session, credential_id: str
) -> PasskeyCredential | None:
    """Fetch a passkey credential by its WebAuthn credential id.

    Args:
        session: Active SQLAlchemy session.
        credential_id: Base64url-encoded credential id to look up.

    Returns:
        The ``PasskeyCredential`` or ``None`` if no row matches.
    """
    stmt = select(PasskeyCredential).where(
        PasskeyCredential.credential_id == credential_id
    )
    return session.execute(stmt).scalar_one_or_none()


def list_passkeys_for_user(
    session: Session, user_id: uuid.UUID
) -> list[PasskeyCredential]:
    """Return every passkey credential registered to a user.

    Args:
        session: Active SQLAlchemy session.
        user_id: UUID of the user.

    Returns:
        A list of ``PasskeyCredential`` rows (possibly empty).
    """
    stmt = select(PasskeyCredential).where(PasskeyCredential.user_id == user_id)
    return list(session.execute(stmt).scalars().all())


def update_passkey_sign_count(
    session: Session,
    cred: PasskeyCredential,
    *,
    sign_count: int,
) -> PasskeyCredential:
    """Bump the sign count and record a successful assertion.

    Args:
        session: Active SQLAlchemy session.
        cred: The credential row to update.
        sign_count: New sign count reported by the authenticator.

    Returns:
        The same credential row with updated fields.
    """
    cred.sign_count = sign_count
    cred.last_used_at = datetime.now(tz=UTC)
    session.flush()
    return cred


def delete_passkey(session: Session, cred: PasskeyCredential) -> None:
    """Remove a passkey credential row.

    Args:
        session: Active SQLAlchemy session.
        cred: The credential row to delete.
    """
    session.delete(cred)
    session.flush()


def delete_passkey_for_user(
    session: Session,
    *,
    user_id: uuid.UUID,
    credential_id: str,
) -> bool:
    """Delete a passkey credential row, scoped to its owning user.

    The ``user_id`` filter is load-bearing — it makes it impossible
    for a request authenticated as user A to delete user B's
    credential by guessing or capturing its id.

    Args:
        session: Active SQLAlchemy session.
        user_id: UUID of the user the credential must belong to.
        credential_id: Base64url-encoded credential id of the row to
            delete.

    Returns:
        ``True`` if a row was deleted, ``False`` if no matching row
        existed for this user (the caller decides whether to surface
        a 404).
    """
    stmt = select(PasskeyCredential).where(
        PasskeyCredential.user_id == user_id,
        PasskeyCredential.credential_id == credential_id,
    )
    cred = session.execute(stmt).scalar_one_or_none()
    if cred is None:
        return False
    session.delete(cred)
    session.flush()
    return True


# ---------------------------------------------------------------------------
# App clients
# ---------------------------------------------------------------------------


def create_app_client(
    session: Session,
    *,
    client_id: str,
    app_name: str,
    client_secret_hash: str,
    allowed_origins: list[str],
) -> AppClient:
    """Register a new consuming app as an ``app_clients`` row.

    Args:
        session: Active SQLAlchemy session.
        client_id: Public client identifier (used as JWT ``aud``).
        app_name: Human-friendly application name.
        client_secret_hash: SHA-256 hex digest of the client secret.
        allowed_origins: Origins the app may redirect to / run from.

    Returns:
        The newly created ``AppClient``.
    """
    client = AppClient(
        client_id=client_id,
        app_name=app_name,
        client_secret_hash=client_secret_hash,
        allowed_origins=allowed_origins,
    )
    session.add(client)
    session.flush()
    return client


def get_app_client(session: Session, client_id: str) -> AppClient | None:
    """Fetch an ``AppClient`` by its primary key.

    Args:
        session: Active SQLAlchemy session.
        client_id: The client id to look up.

    Returns:
        The ``AppClient`` or ``None`` if no row matches.
    """
    return session.get(AppClient, client_id)


# ---------------------------------------------------------------------------
# Refresh tokens
# ---------------------------------------------------------------------------


def create_refresh_token(
    session: Session,
    *,
    user_id: uuid.UUID,
    app_client_id: str,
    token_hash: str,
    expires_at: datetime,
) -> RefreshToken:
    """Insert a new refresh-token row.

    Args:
        session: Active SQLAlchemy session.
        user_id: UUID of the owning user.
        app_client_id: ``app_clients.client_id`` the token is issued for.
        token_hash: SHA-256 hex digest of the opaque refresh token.
        expires_at: Hard expiry wall-clock UTC.

    Returns:
        The newly created ``RefreshToken``.
    """
    token = RefreshToken(
        user_id=user_id,
        app_client_id=app_client_id,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    session.add(token)
    session.flush()
    return token


def get_refresh_token_by_hash(session: Session, token_hash: str) -> RefreshToken | None:
    """Fetch a refresh-token row by its SHA-256 hash.

    Args:
        session: Active SQLAlchemy session.
        token_hash: SHA-256 hex digest to look up.

    Returns:
        The ``RefreshToken`` or ``None`` if no row matches.
    """
    stmt = select(RefreshToken).where(RefreshToken.token_hash == token_hash)
    return session.execute(stmt).scalar_one_or_none()


def mark_refresh_token_used(session: Session, token: RefreshToken) -> RefreshToken:
    """Record that a refresh token has been rotated.

    Args:
        session: Active SQLAlchemy session.
        token: The refresh-token row to update.

    Returns:
        The same row with ``used_at`` set.
    """
    token.used_at = datetime.now(tz=UTC)
    session.flush()
    return token


def revoke_all_refresh_tokens_for_user(session: Session, user_id: uuid.UUID) -> int:
    """Mark every still-active refresh token for a user as used.

    Used as the reuse-detection response: once a consumed refresh
    token is re-presented, every outstanding token for the user is
    invalidated so the attacker's copy cannot rotate again.

    Args:
        session: Active SQLAlchemy session.
        user_id: UUID of the user whose tokens should be revoked.

    Returns:
        Number of rows revoked.
    """
    now = datetime.now(tz=UTC)
    stmt = (
        update(RefreshToken)
        .where(RefreshToken.user_id == user_id, RefreshToken.used_at.is_(None))
        .values(used_at=now)
    )
    result = cast("CursorResult[object]", session.execute(stmt))
    session.flush()
    return int(result.rowcount or 0)
