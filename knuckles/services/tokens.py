"""Refresh-token and access-token orchestration.

This module is the only place that issues Knuckles session tokens. It
wraps :mod:`knuckles.core.jwt` (which actually signs access tokens) and
:mod:`knuckles.data.repositories.auth` (which persists refresh-token
rows) into the two flows every consuming app needs:

* **Issue** — after a successful identity ceremony (magic-link, OAuth,
  passkey), call :func:`issue_session` to mint a matched access+refresh
  pair.
* **Rotate** — on ``POST /v1/token/refresh``, call
  :func:`rotate_refresh_token` which marks the presented token consumed,
  mints a new pair, and detects reuse.
* **Revoke** — on ``POST /v1/logout``, call :func:`revoke_refresh_token`
  which is a silent no-op when the token is unknown (so logout is
  idempotent from the caller's perspective).

Refresh tokens are opaque base64url strings; only their SHA-256 digest
is stored. Reuse of an already-consumed token triggers revocation of
every active refresh token for the user — the industry-standard
recovery behavior for a leaked token.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import uuid
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from knuckles.core.config import get_settings
from knuckles.core.exceptions import (
    INVALID_CLIENT,
    REFRESH_TOKEN_EXPIRED,
    REFRESH_TOKEN_INVALID,
    REFRESH_TOKEN_REUSED,
    AppError,
)
from knuckles.core.jwt import issue_access_token
from knuckles.data.repositories import auth as repo

_audit = logging.getLogger("knuckles.audit")


@dataclass(frozen=True)
class TokenPair:
    """A matched access-token and refresh-token issued to a single session.

    Attributes:
        access_token: Signed RS256 JWT consuming apps attach as
            ``Authorization: Bearer``.
        access_token_expires_at: Wall-clock UTC expiry of the access
            token, mirroring the JWT ``exp`` claim.
        refresh_token: Opaque URL-safe token the consuming app stores
            privately and presents to rotate the access token.
        refresh_token_expires_at: Wall-clock UTC expiry of the refresh
            token, mirroring ``refresh_tokens.expires_at``.
    """

    access_token: str
    access_token_expires_at: datetime
    refresh_token: str
    refresh_token_expires_at: datetime


def _hash_token(token: str) -> str:
    """Return the SHA-256 hex digest of a refresh token.

    Args:
        token: The opaque refresh-token plaintext.

    Returns:
        The 64-character hex digest stored in ``refresh_tokens.token_hash``.
    """
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _generate_refresh_token() -> str:
    """Mint a new opaque refresh-token plaintext.

    Returns:
        A 43-character URL-safe token (256 bits of entropy).
    """
    return secrets.token_urlsafe(32)


def issue_session(
    session: Session,
    *,
    user_id: uuid.UUID | str,
    app_client_id: str,
    scopes: list[str] | None = None,
    email: str | None = None,
) -> TokenPair:
    """Mint a fresh access+refresh pair for a successful authentication.

    Args:
        session: Active SQLAlchemy session.
        user_id: UUID (or UUID string) of the authenticated user.
        app_client_id: ``app_clients.client_id`` of the consuming app.
        scopes: Optional scope list to embed in the access token.
        email: Optional email to embed in the access token.

    Returns:
        A :class:`TokenPair` with both tokens and their expiry instants.
    """
    settings = get_settings()
    user_uuid = user_id if isinstance(user_id, uuid.UUID) else uuid.UUID(str(user_id))
    now = datetime.now(tz=UTC)

    access_token = issue_access_token(
        user_id=user_uuid,
        app_client_id=app_client_id,
        scopes=scopes,
        email=email,
    )
    access_expires_at = now + timedelta(
        seconds=settings.knuckles_access_token_ttl_seconds
    )

    refresh_plaintext = _generate_refresh_token()
    refresh_expires_at = now + timedelta(
        seconds=settings.knuckles_refresh_token_ttl_seconds
    )
    repo.create_refresh_token(
        session,
        user_id=user_uuid,
        app_client_id=app_client_id,
        token_hash=_hash_token(refresh_plaintext),
        expires_at=refresh_expires_at,
    )

    _audit.info(
        "session_issued user_id=%s app_client_id=%s",
        user_uuid,
        app_client_id,
    )
    return TokenPair(
        access_token=access_token,
        access_token_expires_at=access_expires_at,
        refresh_token=refresh_plaintext,
        refresh_token_expires_at=refresh_expires_at,
    )


def rotate_refresh_token(
    session: Session,
    *,
    refresh_token: str,
    app_client_id: str,
    scopes: list[str] | None = None,
    email: str | None = None,
) -> TokenPair:
    """Consume a refresh token and mint a new access+refresh pair.

    Marks the presented token as ``used_at=now`` on success, then issues
    a new pair. If the token has already been consumed, every active
    refresh token for the user is revoked and ``REFRESH_TOKEN_REUSED``
    is raised — the standard recovery behavior for a leaked token.

    Args:
        session: Active SQLAlchemy session.
        refresh_token: Opaque refresh-token plaintext presented by the
            consuming app.
        app_client_id: ``app_clients.client_id`` asserted by the caller;
            must match the one the token was issued for.
        scopes: Optional scopes for the new access token.
        email: Optional email claim for the new access token.

    Returns:
        A fresh :class:`TokenPair`.

    Raises:
        AppError: With code ``REFRESH_TOKEN_INVALID`` (unknown token or
            deactivated user), ``REFRESH_TOKEN_REUSED`` (already
            consumed, including a lost race against a concurrent
            rotation), ``REFRESH_TOKEN_EXPIRED`` (past ``expires_at``),
            or ``INVALID_CLIENT`` (token issued for a different app).
    """
    row = repo.get_refresh_token_by_hash(session, _hash_token(refresh_token))
    if row is None:
        raise AppError(
            code=REFRESH_TOKEN_INVALID,
            message="Refresh token is invalid.",
            status_code=401,
        )

    if row.used_at is not None:
        _revoke_all_for_reuse(session, row.user_id, app_client_id)

    expires_at = row.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if expires_at <= datetime.now(tz=UTC):
        raise AppError(
            code=REFRESH_TOKEN_EXPIRED,
            message="Refresh token has expired.",
            status_code=401,
        )

    if row.app_client_id != app_client_id:
        raise AppError(
            code=INVALID_CLIENT,
            message="Refresh token was not issued for this client.",
            status_code=401,
        )

    user = repo.get_user_by_id(session, row.user_id)
    if user is None or not user.is_active:
        raise AppError(
            code=REFRESH_TOKEN_INVALID,
            message="Refresh token is invalid.",
            status_code=401,
        )

    # The conditional consume is the single-use guarantee: under a
    # concurrent rotation of the same token, exactly one request wins.
    # The loser is indistinguishable from a replayed stolen token, so
    # it gets the full reuse response.
    if not repo.consume_refresh_token(session, row):
        _revoke_all_for_reuse(session, row.user_id, app_client_id)

    return issue_session(
        session,
        user_id=row.user_id,
        app_client_id=app_client_id,
        scopes=scopes,
        email=email if email is not None else user.email,
    )


def _revoke_all_for_reuse(
    session: Session,
    user_id: uuid.UUID,
    app_client_id: str,
) -> None:
    """Apply the reuse-detection response and raise.

    Revokes every active refresh token for the user (across all app
    clients — a reuse event is a compromise signal, so the blast
    radius is deliberately global per Decision #008) and raises
    ``REFRESH_TOKEN_REUSED``.

    Args:
        session: Active SQLAlchemy session.
        user_id: UUID of the user whose tokens are revoked.
        app_client_id: Calling client, for the audit log line.

    Raises:
        AppError: Always, with code ``REFRESH_TOKEN_REUSED``.
    """
    revoked = repo.revoke_all_refresh_tokens_for_user(session, user_id)
    _audit.warning(
        "refresh_token_reused user_id=%s app_client_id=%s "
        "tokens_revoked=%d — every session for this user has been "
        "invalidated; user must re-authenticate.",
        user_id,
        app_client_id,
        revoked,
    )
    raise AppError(
        code=REFRESH_TOKEN_REUSED,
        message="Refresh token has already been used.",
        status_code=401,
    )


def revoke_all_sessions(
    session: Session,
    *,
    user_id: uuid.UUID,
    app_client_id: str,
) -> int:
    """Revoke every active refresh token a user holds with one app.

    Backs the user-initiated "sign out of all devices" endpoint. The
    revocation is scoped to the calling app client — a shared identity
    signed in to two consuming apps keeps its other app's sessions.
    The cross-tenant blanket revoke is reserved for the
    reuse-detection security response.

    Args:
        session: Active SQLAlchemy session.
        user_id: UUID of the user signing out.
        app_client_id: ``app_clients.client_id`` of the calling app.

    Returns:
        Number of refresh tokens revoked.
    """
    revoked = repo.revoke_all_refresh_tokens_for_user(
        session, user_id, app_client_id=app_client_id
    )
    _audit.info(
        "logout_all user_id=%s app_client_id=%s tokens_revoked=%d",
        user_id,
        app_client_id,
        revoked,
    )
    return revoked


def revoke_refresh_token(
    session: Session,
    *,
    refresh_token: str,
    app_client_id: str,
) -> None:
    """Mark a refresh token as consumed, ignoring unknown/mismatched values.

    Logout must be idempotent — a token that was never issued or was
    issued for a different client silently succeeds. That lets clients
    call logout without racing the token state on the server.

    Args:
        session: Active SQLAlchemy session.
        refresh_token: Opaque refresh-token plaintext to revoke.
        app_client_id: ``app_clients.client_id`` asserted by the caller.
    """
    row = repo.get_refresh_token_by_hash(session, _hash_token(refresh_token))
    if row is None or row.app_client_id != app_client_id:
        return
    if row.used_at is not None:
        return
    repo.mark_refresh_token_used(session, row)
