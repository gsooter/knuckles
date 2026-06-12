"""Repository functions for every Knuckles-owned table.

All database access in Knuckles goes through this module. Route
handlers and service functions never run SQL or construct ORM
queries directly — they call the functions below.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import cast

from sqlalchemy import CursorResult, delete, func, select, update
from sqlalchemy.orm import Session
from sqlalchemy.orm.attributes import flag_modified

from knuckles.data.models import (
    AppClient,
    MagicLinkToken,
    OAuthProvider,
    PasskeyCredential,
    RefreshToken,
    User,
    UserOAuthProvider,
)


class _Unset:
    """Sentinel type distinguishing "argument absent" from explicit ``None``.

    Profile updates need three-way semantics: a field can be set to a
    value, cleared with ``None``, or left untouched when the caller
    never mentioned it. A default of ``None`` cannot express the third
    state, so optional update parameters default to the module-level
    :data:`_UNSET` instance instead.
    """

    __slots__ = ()


_UNSET = _Unset()

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


def update_user_profile(
    session: Session,
    user: User,
    *,
    display_name: str | None | _Unset = _UNSET,
    avatar_url: str | None | _Unset = _UNSET,
) -> User:
    """Apply a partial profile update to a user row.

    Parameters left at the :data:`_UNSET` sentinel keep their current
    value; an explicit ``None`` clears the column. That distinction is
    what lets ``PATCH /v1/me`` treat an absent body key and a JSON
    ``null`` differently.

    Args:
        session: Active SQLAlchemy session.
        user: The user row to update.
        display_name: New display name, ``None`` to clear, or absent.
        avatar_url: New avatar URL, ``None`` to clear, or absent.

    Returns:
        The same ``User`` with the requested fields applied.
    """
    if not isinstance(display_name, _Unset):
        user.display_name = display_name
    if not isinstance(avatar_url, _Unset):
        user.avatar_url = avatar_url
    session.flush()
    return user


def update_user_email(session: Session, user: User, *, email: str) -> User:
    """Rewrite a user's canonical email address.

    Callers are responsible for uniqueness checks — the service layer
    raises ``EMAIL_IN_USE`` before reaching here.

    Args:
        session: Active SQLAlchemy session.
        user: The user row to update.
        email: The new canonical email address.

    Returns:
        The same ``User`` with the new address applied.
    """
    user.email = email
    session.flush()
    return user


def delete_user(session: Session, user: User) -> None:
    """Remove a user row.

    Dependent rows (OAuth links, passkeys, refresh tokens) are removed
    by the ORM cascade / ``ON DELETE CASCADE`` foreign keys. Magic-link
    rows keyed by email are the caller's job — see
    :func:`delete_magic_links_for_email`.

    Args:
        session: Active SQLAlchemy session.
        user: The user row to delete.
    """
    session.delete(user)
    session.flush()


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
# OAuth provider removal
# ---------------------------------------------------------------------------


def delete_oauth_provider_for_user(
    session: Session,
    user_id: uuid.UUID,
    provider: OAuthProvider,
) -> bool:
    """Delete one provider link, scoped to its owning user.

    The ``user_id`` filter is load-bearing — exactly like
    :func:`delete_passkey_for_user`, it makes it impossible for a
    request authenticated as user A to unlink user B's provider.

    Args:
        session: Active SQLAlchemy session.
        user_id: UUID of the user the link must belong to.
        provider: Identity provider to unlink.

    Returns:
        ``True`` if a row was deleted, ``False`` if no matching row
        existed for this user (the caller decides whether to surface
        a 404).
    """
    stmt = select(UserOAuthProvider).where(
        UserOAuthProvider.user_id == user_id,
        UserOAuthProvider.provider == provider,
    )
    link = session.execute(stmt).scalar_one_or_none()
    if link is None:
        return False
    session.delete(link)
    session.flush()
    return True


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
    app_client_id: str | None = None,
    purpose: str = "sign_in",
) -> MagicLinkToken:
    """Insert a pending magic-link token row.

    Args:
        session: Active SQLAlchemy session.
        email: Address the link was issued to.
        token_hash: SHA-256 hex digest of the raw token.
        expires_at: Hard expiry of the token.
        user_id: Optional user id — left ``None`` for first-time
            addresses and populated on redemption. The email-change
            ceremony sets it at mint time.
        app_client_id: ``app_clients.client_id`` the link was issued
            through; verification rejects redemption via any other
            client (Decision #019).
        purpose: Ceremony tag — ``"sign_in"`` (default) or
            ``"email_change"``. Verification requires an exact match.

    Returns:
        The newly created ``MagicLinkToken``.
    """
    token = MagicLinkToken(
        email=email,
        token_hash=token_hash,
        expires_at=expires_at,
        user_id=user_id,
        app_client_id=app_client_id,
        purpose=purpose,
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


def delete_magic_links_for_email(session: Session, *, email: str) -> int:
    """Delete every magic-link row issued to one email address.

    Backs account deletion: a pending sign-in or email-change link for
    a deleted account must not stay redeemable.

    Args:
        session: Active SQLAlchemy session.
        email: Address whose rows are deleted.

    Returns:
        The number of rows deleted.
    """
    stmt = delete(MagicLinkToken).where(MagicLinkToken.email == email)
    result = cast("CursorResult[object]", session.execute(stmt))
    session.flush()
    return int(result.rowcount or 0)


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


def count_passkeys(session: Session) -> int:
    """Count every passkey credential row in the table.

    Backs the ``webauthn_rp_id`` immutability guardrail: changing the
    relying-party id invalidates each credential minted against the
    prior value, so the admin surface refuses the change while any
    rows exist (absent an explicit force).

    Args:
        session: Active SQLAlchemy session.

    Returns:
        Total number of ``passkey_credentials`` rows.
    """
    stmt = select(func.count()).select_from(PasskeyCredential)
    return int(session.execute(stmt).scalar_one())


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


def list_app_clients(session: Session) -> list[AppClient]:
    """Return every registered ``AppClient`` ordered by client id.

    Args:
        session: Active SQLAlchemy session.

    Returns:
        All ``app_clients`` rows sorted by ``client_id`` (possibly
        empty).
    """
    stmt = select(AppClient).order_by(AppClient.client_id)
    return list(session.execute(stmt).scalars().all())


def rotate_app_client_secret(
    session: Session,
    client_id: str,
    *,
    new_secret_hash: str,
) -> AppClient | None:
    """Replace the stored secret hash on an existing ``AppClient``.

    Deliberately separate from :func:`update_app_client_config` — the
    tenant-config allow-list must stay unable to touch
    ``client_secret_hash``.

    Args:
        session: Active SQLAlchemy session.
        client_id: Target ``app_clients.client_id``.
        new_secret_hash: SHA-256 hex digest of the new plaintext
            secret.

    Returns:
        The updated ``AppClient``, or ``None`` if no row matches.
    """
    client = session.get(AppClient, client_id)
    if client is None:
        return None
    client.client_secret_hash = new_secret_hash
    session.flush()
    return client


def set_app_client_origins(
    session: Session,
    client_id: str,
    *,
    allowed_origins: list[str],
) -> AppClient | None:
    """Replace the entire ``allowed_origins`` list on an ``AppClient``.

    Like :func:`rotate_app_client_secret`, this is kept outside the
    tenant-config allow-list on purpose — origins gate redirect-URL
    trust and deserve their own explicit seam.

    Args:
        session: Active SQLAlchemy session.
        client_id: Target ``app_clients.client_id``.
        allowed_origins: The new complete list of allowed origins.

    Returns:
        The updated ``AppClient``, or ``None`` if no row matches.
    """
    client = session.get(AppClient, client_id)
    if client is None:
        return None
    client.allowed_origins = list(allowed_origins)
    session.flush()
    return client


# Set of attributes that ``update_app_client_config`` is allowed to set.
# Restricting writes to this allow-list prevents the CLI from being
# turned into a generic ``UPDATE app_clients SET <anything>`` shim —
# the client secret hash, allowed origins, and timestamps stay out of
# reach.
_TENANT_CONFIG_FIELDS: frozenset[str] = frozenset(
    {
        "resend_api_key",
        "resend_from_email",
        "google_oauth_client_id",
        "google_oauth_client_secret",
        "apple_oauth_client_id",
        "apple_oauth_team_id",
        "apple_oauth_key_id",
        "apple_oauth_private_key",
        "webauthn_rp_id",
        "webauthn_rp_name",
        "webauthn_origin",
    }
)


def update_app_client_config(
    session: Session,
    *,
    client_id: str,
    **fields: str | None,
) -> AppClient | None:
    """Update per-tenant config columns on an existing ``AppClient``.

    Args:
        session: Active SQLAlchemy session.
        client_id: Target ``app_clients.client_id``.
        **fields: Column name → new value (or ``None`` to revert to
            env-var fallback). Only the per-tenant config columns
            defined in :data:`_TENANT_CONFIG_FIELDS` are accepted;
            attempting to set any other attribute raises
            :class:`ValueError`.

    Returns:
        The updated ``AppClient``, or ``None`` if no row matches the
        given ``client_id``.

    Raises:
        ValueError: If any key in ``fields`` is outside the
            ``_TENANT_CONFIG_FIELDS`` allow-list.
    """
    unknown = set(fields) - _TENANT_CONFIG_FIELDS
    if unknown:
        raise ValueError(f"Cannot update non-tenant-config fields: {sorted(unknown)}")
    client = session.get(AppClient, client_id)
    if client is None:
        return None
    for attr, value in fields.items():
        setattr(client, attr, value)
    session.flush()
    return client


_ENCRYPTED_APP_CLIENT_COLUMNS = (
    "resend_api_key",
    "google_oauth_client_secret",
    "apple_oauth_private_key",
)


def reencrypt_app_client_secrets(session: Session) -> int:
    """Rewrite every populated encrypted column under the primary key.

    Backs ``scripts/reencrypt_tenant_secrets.py`` (the Fernet rotation
    promised by Decision #017). Reading an encrypted column decrypts
    it with whichever key in the ``KNUCKLES_SECRETS_KEY`` list
    matches; flagging the attribute dirty forces the next flush to
    re-encrypt the plaintext with the list's primary (first) key.

    Args:
        session: Active SQLAlchemy session.

    Returns:
        Number of ``app_clients`` rows that carried at least one
        encrypted value and were rewritten.
    """
    rewritten = 0
    for client in session.execute(select(AppClient)).scalars():
        touched = False
        for column in _ENCRYPTED_APP_CLIENT_COLUMNS:
            if getattr(client, column):
                flag_modified(client, column)
                touched = True
        if touched:
            rewritten += 1
    session.flush()
    return rewritten


def delete_expired_refresh_tokens(session: Session, *, older_than: datetime) -> int:
    """Delete refresh-token rows whose ``expires_at`` is before a cutoff.

    Consumed rows are retained only for reuse detection, and an
    expired token can never rotate — so purging past-expiry rows
    keeps the table bounded without weakening the reuse guarantee.

    Args:
        session: Active SQLAlchemy session.
        older_than: Cutoff timestamp; rows expired before this are
            deleted.

    Returns:
        The number of rows deleted.
    """
    stmt = delete(RefreshToken).where(RefreshToken.expires_at < older_than)
    result = cast("CursorResult[object]", session.execute(stmt))
    session.flush()
    return int(result.rowcount or 0)


def ping(session: Session) -> bool:
    """Execute a trivial query to prove database connectivity.

    Backs the deep ``/health`` probe: a worker whose pool is exhausted
    or whose database is down should report degraded instead of green.

    Args:
        session: Active SQLAlchemy session.

    Returns:
        True when the round trip succeeds.

    Raises:
        sqlalchemy.exc.SQLAlchemyError: Propagated when the database
            is unreachable.
    """
    session.execute(select(1))
    return True


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


def consume_refresh_token(session: Session, token: RefreshToken) -> bool:
    """Atomically claim a refresh token for rotation.

    Issues a conditional ``UPDATE ... WHERE used_at IS NULL`` so two
    concurrent rotations of the same token admit exactly one winner —
    the read-then-write pattern alone would let both racers pass the
    reuse check under READ COMMITTED.

    Args:
        session: Active SQLAlchemy session.
        token: The refresh-token row to consume.

    Returns:
        True if this caller consumed the token; False if it was
        already consumed (a concurrent or prior use).
    """
    now = datetime.now(tz=UTC)
    stmt = (
        update(RefreshToken)
        .where(RefreshToken.id == token.id, RefreshToken.used_at.is_(None))
        .values(used_at=now)
    )
    result = cast("CursorResult[object]", session.execute(stmt))
    session.flush()
    if int(result.rowcount or 0) == 1:
        session.expire(token, ["used_at"])
        return True
    return False


def list_active_refresh_tokens_for_user(
    session: Session,
    user_id: uuid.UUID,
    *,
    app_client_id: str,
    now: datetime,
) -> list[RefreshToken]:
    """Return a user's active refresh tokens for one app client.

    Active means ``used_at IS NULL`` and ``expires_at`` after ``now``.
    Because rotation replaces rows, the returned ids change on every
    refresh — this is a point-in-time view, not a stable session
    handle.

    Args:
        session: Active SQLAlchemy session.
        user_id: UUID of the owning user.
        app_client_id: ``app_clients.client_id`` to scope the list to.
        now: Wall-clock UTC instant used for the expiry comparison.

    Returns:
        Matching ``RefreshToken`` rows ordered by creation time
        (possibly empty).
    """
    stmt = (
        select(RefreshToken)
        .where(
            RefreshToken.user_id == user_id,
            RefreshToken.app_client_id == app_client_id,
            RefreshToken.used_at.is_(None),
            RefreshToken.expires_at > now,
        )
        .order_by(RefreshToken.created_at)
    )
    return list(session.execute(stmt).scalars().all())


def revoke_refresh_token_by_id(
    session: Session,
    *,
    user_id: uuid.UUID,
    app_client_id: str,
    token_id: uuid.UUID,
) -> bool:
    """Revoke one refresh token by id, scoped to its owner and tenant.

    The ``(user_id, app_client_id)`` filter is load-bearing — exactly
    like :func:`delete_passkey_for_user`, it makes it impossible for a
    request authenticated as user A (or calling through tenant B) to
    revoke a session it does not own. Rows that are already consumed
    or expired report ``False`` so the caller can 404.

    Args:
        session: Active SQLAlchemy session.
        user_id: UUID of the user the token must belong to.
        app_client_id: ``app_clients.client_id`` the token must have
            been issued for.
        token_id: Primary key of the ``refresh_tokens`` row.

    Returns:
        ``True`` if an active row was revoked, ``False`` if no
        matching active row existed for this user and client.
    """
    now = datetime.now(tz=UTC)
    stmt = select(RefreshToken).where(
        RefreshToken.id == token_id,
        RefreshToken.user_id == user_id,
        RefreshToken.app_client_id == app_client_id,
        RefreshToken.used_at.is_(None),
        RefreshToken.expires_at > now,
    )
    row = session.execute(stmt).scalar_one_or_none()
    if row is None:
        return False
    row.used_at = now
    session.flush()
    return True


def revoke_all_refresh_tokens_for_user(
    session: Session,
    user_id: uuid.UUID,
    *,
    app_client_id: str | None = None,
) -> int:
    """Mark every still-active refresh token for a user as used.

    Two callers, two scopes:

    * Reuse detection passes no ``app_client_id`` — a re-presented
      consumed token is a compromise signal, so every session across
      every consuming app is revoked (Decision #008).
    * User-initiated "sign out everywhere" passes the calling client
      so one tenant cannot destroy the user's sessions in another.

    Args:
        session: Active SQLAlchemy session.
        user_id: UUID of the user whose tokens should be revoked.
        app_client_id: When given, restrict the revocation to tokens
            issued for this app client.

    Returns:
        Number of rows revoked.
    """
    now = datetime.now(tz=UTC)
    stmt = (
        update(RefreshToken)
        .where(RefreshToken.user_id == user_id, RefreshToken.used_at.is_(None))
        .values(used_at=now)
    )
    if app_client_id is not None:
        stmt = stmt.where(RefreshToken.app_client_id == app_client_id)
    result = cast("CursorResult[object]", session.execute(stmt))
    session.flush()
    return int(result.rowcount or 0)
