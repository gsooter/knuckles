"""Typed response shapes for the Knuckles SDK.

These are returned by :class:`KnucklesClient` methods so consuming
code can rely on attribute access (``pair.access_token``) and IDE
autocompletion instead of poking at raw dicts.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any


@dataclass(frozen=True)
class TokenPair:
    """A matched access + refresh token issued by Knuckles.

    Attributes:
        access_token: RS256-signed JWT to attach as
            ``Authorization: Bearer``.
        access_token_expires_at: Wall-clock UTC expiry of the access
            token (mirrors the JWT ``exp`` claim).
        refresh_token: Opaque rotating refresh token. Store privately
            and present to :func:`KnucklesClient.refresh` to mint the
            next pair. Always swap in the new one — re-presenting a
            consumed token revokes every session for the user.
        refresh_token_expires_at: Wall-clock UTC expiry of the
            refresh token.
        token_type: Always ``"Bearer"``.
    """

    access_token: str
    access_token_expires_at: datetime
    refresh_token: str
    refresh_token_expires_at: datetime
    token_type: str = "Bearer"


@dataclass(frozen=True)
class CeremonyStart:
    """Return value of OAuth-style ``start`` calls.

    Attributes:
        authorize_url: URL the browser must navigate to.
        state: Signed state JWT the frontend echoes back on the
            ``complete`` step.
    """

    authorize_url: str
    state: str


@dataclass(frozen=True)
class PasskeyChallenge:
    """Return value of passkey ``begin`` calls.

    Attributes:
        options: WebAuthn ``PublicKeyCredentialCreation/RequestOptions``
            as a plain dict — pass directly to
            ``navigator.credentials.create()`` /
            ``navigator.credentials.get()`` after JSON-encoding.
        state: Signed state JWT to echo on the ``complete`` step.
    """

    options: dict[str, Any]
    state: str


@dataclass(frozen=True)
class UserProfile:
    """Return value of :func:`KnucklesClient.me`.

    Attributes:
        id: Knuckles ``users.id`` (UUID string).
        email: Canonical email.
        display_name: Optional display name (may be ``None``).
        avatar_url: Optional avatar URL (may be ``None``).
        app_client_id: ``aud`` of the access token used for the call.
    """

    id: str
    email: str
    display_name: str | None
    avatar_url: str | None
    app_client_id: str


@dataclass(frozen=True)
class PasskeyDescriptor:
    """One row from :func:`KnucklesClient.passkey.list`.

    Attributes:
        credential_id: WebAuthn credential id (base64url).
        name: User-facing label (may be ``None``).
        transports: Comma-joined transport hints (may be ``None``).
        created_at: When the passkey was registered.
        last_used_at: Last successful assertion (may be ``None``).
    """

    credential_id: str
    name: str | None
    transports: str | None
    created_at: datetime
    last_used_at: datetime | None
