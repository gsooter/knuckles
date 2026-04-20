"""SQLAlchemy ORM models for every Knuckles-owned table.

Knuckles is an identity-only service — see ``CLAUDE.md`` and
``DECISIONS.md`` (#001). The tables in this module are the complete
list of what Knuckles persists:

- ``users`` — the identity record.
- ``user_oauth_providers`` — linked identity providers
  (``google`` and ``apple`` only; never a music service).
- ``magic_link_tokens`` — pending / consumed magic-link rows, stored
  as SHA-256 hashes (Decision #006).
- ``passkey_credentials`` — one row per registered WebAuthn
  authenticator.
- ``app_clients`` — every consuming application registered with
  Knuckles (Decision #003).
- ``refresh_tokens`` — rotating one-shot refresh tokens (Decision
  #004), hashed at rest.

No other tables exist in Knuckles by design.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime

from sqlalchemy import (
    JSON,
    BigInteger,
    DateTime,
    Enum,
    ForeignKey,
    String,
    Text,
    Uuid,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from knuckles.core.database import Base, TimestampMixin


class OAuthProvider(enum.StrEnum):
    """Supported identity providers linked to a Knuckles user.

    Restricted to ``google`` and ``apple`` by Decision #001. Music
    services are Greenroom's concern and must never appear here.
    """

    GOOGLE = "google"
    APPLE = "apple"


class User(TimestampMixin, Base):
    """An authenticated Knuckles user.

    Attributes:
        id: Primary key used as the ``sub`` claim on every access token.
        email: Canonical email address. Unique across the table.
        display_name: Optional display name from the identity provider.
        avatar_url: Optional avatar URL from the identity provider.
        is_active: Soft-delete flag. Inactive users cannot sign in.
        last_seen_at: Updated on every successful token issuance.
        oauth_providers: Linked Google / Apple identities.
        passkeys: Registered WebAuthn credentials for this user.
        refresh_tokens: Outstanding refresh tokens across all app clients.
    """

    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    email: Mapped[str] = mapped_column(
        String(320), unique=True, nullable=False, index=True
    )
    display_name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    avatar_url: Mapped[str | None] = mapped_column(String(500), nullable=True)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    oauth_providers: Mapped[list[UserOAuthProvider]] = relationship(
        back_populates="user",
        lazy="selectin",
        cascade="all, delete-orphan",
    )
    passkeys: Mapped[list[PasskeyCredential]] = relationship(
        back_populates="user",
        lazy="selectin",
        cascade="all, delete-orphan",
    )
    refresh_tokens: Mapped[list[RefreshToken]] = relationship(
        back_populates="user",
        lazy="selectin",
        cascade="all, delete-orphan",
    )

    def __repr__(self) -> str:
        """Return a concise representation for debugging.

        Returns:
            A short string containing the email address.
        """
        return f"<User {self.email}>"


class UserOAuthProvider(TimestampMixin, Base):
    """A Google or Apple identity linked to a Knuckles user.

    Attributes:
        id: Surrogate primary key for the link row.
        user_id: Foreign key to the owning user.
        provider: Provider type — ``google`` or ``apple`` only.
        provider_user_id: The identifier returned by the provider's
            ``/userinfo`` / ``sub`` claim.
        access_token: Most recent access token from the provider,
            retained so future re-verification calls are possible.
        refresh_token: Most recent refresh token from the provider.
        token_expires_at: When the provider access token expires.
        scopes: Space-delimited scopes granted at the last login.
        raw_profile: The most recent profile payload returned by the
            provider, stored verbatim for audit.
        user: Relationship back to the owning user.
    """

    __tablename__ = "user_oauth_providers"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    provider: Mapped[OAuthProvider] = mapped_column(
        Enum(
            OAuthProvider,
            name="knuckles_oauth_provider",
            native_enum=True,
            values_callable=lambda enum_cls: [e.value for e in enum_cls],
        ),
        nullable=False,
    )
    provider_user_id: Mapped[str] = mapped_column(
        String(200), nullable=False, index=True
    )
    access_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    refresh_token: Mapped[str | None] = mapped_column(Text, nullable=True)
    token_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    scopes: Mapped[str | None] = mapped_column(Text, nullable=True)
    raw_profile: Mapped[dict[str, object] | None] = mapped_column(JSON, nullable=True)

    user: Mapped[User] = relationship(back_populates="oauth_providers")

    def __repr__(self) -> str:
        """Return a concise representation for debugging.

        Returns:
            A string with the provider and user id.
        """
        return f"<UserOAuthProvider {self.provider.value} user={self.user_id}>"


class MagicLinkToken(TimestampMixin, Base):
    """A single-use magic-link sign-in token (SHA-256 hashed at rest).

    See Decision #006 — the raw token appears only in the outgoing
    email URL and is compared by hashing the incoming value.

    Attributes:
        id: Surrogate primary key.
        email: Destination address the link was issued to.
        token_hash: SHA-256 hex digest of the raw token. Unique.
        expires_at: Hard expiry regardless of ``used_at`` state.
        used_at: Timestamp the link was redeemed. ``None`` means
            still redeemable within the expiry window.
        user_id: Set once the link is redeemed.
    """

    __tablename__ = "magic_link_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    email: Mapped[str] = mapped_column(String(320), nullable=False, index=True)
    token_hash: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True, index=True
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )

    def __repr__(self) -> str:
        """Return a concise representation for debugging.

        Returns:
            A string with the email and redemption state.
        """
        state = "used" if self.used_at is not None else "pending"
        return f"<MagicLinkToken email={self.email} state={state}>"


class PasskeyCredential(TimestampMixin, Base):
    """A WebAuthn passkey registered to a user.

    Attributes:
        id: Surrogate primary key.
        user_id: Owning user.
        credential_id: Base64url-encoded credential id. Unique across
            the table per WebAuthn spec.
        public_key: CBOR public key (base64url) used to verify assertions.
        sign_count: Monotonic counter reported by the authenticator. A
            regression signals credential cloning and fails verification.
        transports: Optional comma-delimited transport hints
            (e.g. ``internal,hybrid``).
        name: Optional user-facing label ("MacBook Air", "iPhone").
        last_used_at: Last successful assertion timestamp.
        user: Relationship back to the owning user.
    """

    __tablename__ = "passkey_credentials"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    credential_id: Mapped[str] = mapped_column(
        Text, nullable=False, unique=True, index=True
    )
    public_key: Mapped[str] = mapped_column(Text, nullable=False)
    sign_count: Mapped[int] = mapped_column(BigInteger, nullable=False, default=0)
    transports: Mapped[str | None] = mapped_column(String(200), nullable=True)
    name: Mapped[str | None] = mapped_column(String(200), nullable=True)
    last_used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    user: Mapped[User] = relationship(back_populates="passkeys")

    def __repr__(self) -> str:
        """Return a concise representation for debugging.

        Returns:
            A string with the user id and credential label.
        """
        label = self.name or self.credential_id[:12]
        return f"<PasskeyCredential user={self.user_id} name={label}>"


class AppClient(TimestampMixin, Base):
    """A consuming application registered with Knuckles.

    The ``client_id`` is a short stable identifier embedded in every
    token as the ``aud`` claim (Decision #003). The client secret is
    stored only as a SHA-256 hash; high-entropy random secrets need
    no password-style hashing.

    Attributes:
        client_id: Public primary key (e.g. ``greenroom-prod``).
        app_name: Human-friendly name for admin UIs.
        client_secret_hash: SHA-256 hex digest of the client secret.
        allowed_origins: Origins the app may redirect to / run from.
        refresh_tokens: Tokens issued for this client.
    """

    __tablename__ = "app_clients"

    client_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    app_name: Mapped[str] = mapped_column(String(200), unique=True, nullable=False)
    client_secret_hash: Mapped[str] = mapped_column(String(128), nullable=False)
    allowed_origins: Mapped[list[str]] = mapped_column(
        JSON, nullable=False, default=list
    )

    refresh_tokens: Mapped[list[RefreshToken]] = relationship(
        back_populates="app_client",
        lazy="selectin",
    )

    def __repr__(self) -> str:
        """Return a concise representation for debugging.

        Returns:
            A string with the client id.
        """
        return f"<AppClient {self.client_id}>"


class RefreshToken(TimestampMixin, Base):
    """A one-shot rotating refresh token issued to an app client.

    See Decision #004. Refresh tokens are opaque random strings; only
    the SHA-256 hash is stored. Every use of a refresh token rotates
    it (``used_at`` is set; a new row is issued). A second presentation
    of a used token is a reuse signal and triggers revocation of all
    active refresh tokens for the owning user.

    Attributes:
        id: Surrogate primary key.
        user_id: Owning user.
        app_client_id: The client the token was issued for.
        token_hash: SHA-256 hex digest of the opaque token. Unique.
        expires_at: Hard expiry wall-clock UTC.
        used_at: Timestamp the token was rotated. ``None`` means
            the token is still active.
        user: Relationship back to the owning user.
        app_client: Relationship back to the issuing app client.
    """

    __tablename__ = "refresh_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    app_client_id: Mapped[str] = mapped_column(
        String(64),
        ForeignKey("app_clients.client_id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    token_hash: Mapped[str] = mapped_column(
        String(128), nullable=False, unique=True, index=True
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    used_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    user: Mapped[User] = relationship(back_populates="refresh_tokens")
    app_client: Mapped[AppClient] = relationship(back_populates="refresh_tokens")

    def __repr__(self) -> str:
        """Return a concise representation for debugging.

        Returns:
            A string with the user id and redemption state.
        """
        state = "used" if self.used_at is not None else "active"
        return f"<RefreshToken user={self.user_id} state={state}>"
