"""Magic-link ceremony: issue a one-time secret and redeem it for a session.

The flow has two service entry points:

* :func:`start_magic_link` — mint a raw token, persist only its SHA-256
  digest, and send the recipient a link containing the raw token.
* :func:`verify_magic_link` — hash the presented token, look the row
  up, validate (not used, not expired), create the user if the email
  is new, mark the row consumed, and return an access+refresh pair
  via :func:`knuckles.services.tokens.issue_session`.

The raw token is 32 bytes of ``secrets.token_urlsafe`` entropy. It
lives in the outgoing email URL and in memory during verify — the DB
only ever sees the hash (Decision #006).
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

from sqlalchemy.orm import Session

from knuckles.core.config import get_settings
from knuckles.core.exceptions import (
    MAGIC_LINK_ALREADY_USED,
    MAGIC_LINK_EXPIRED,
    MAGIC_LINK_INVALID,
    AppError,
)
from knuckles.data.repositories import auth as repo
from knuckles.services import tokens
from knuckles.services.email import EmailSender, get_default_sender


def _hash_token(token: str) -> str:
    """Return the SHA-256 hex digest of a magic-link token.

    Args:
        token: The raw URL-safe token plaintext.

    Returns:
        The 64-character hex digest stored in ``magic_link_tokens``.
    """
    return hashlib.sha256(token.encode("ascii")).hexdigest()


def _generate_token() -> str:
    """Mint a new URL-safe magic-link token.

    Returns:
        A 43-character token with 256 bits of entropy.
    """
    return secrets.token_urlsafe(32)


def _build_link(redirect_url: str, raw_token: str) -> str:
    """Attach the raw token to the caller-supplied redirect URL.

    Args:
        redirect_url: Destination the consuming app exposes for the
            verify step (e.g., ``https://app/auth/verify``). May
            already contain a query string.
        raw_token: The plaintext magic-link token.

    Returns:
        The fully assembled URL the user will click.
    """
    separator = "&" if "?" in redirect_url else "?"
    return f"{redirect_url}{separator}{urlencode({'token': raw_token})}"


def _render_email_body(link: str) -> str:
    """Render the HTML body of the magic-link email.

    Args:
        link: The fully-assembled magic-link URL.

    Returns:
        HTML body content for the outgoing email.
    """
    return (
        "<p>Click the link below to sign in. It expires in 15 minutes.</p>"
        f'<p><a href="{link}">{link}</a></p>'
    )


def start_magic_link(
    session: Session,
    *,
    email: str,
    app_client_id: str,
    redirect_url: str,
    sender: EmailSender | None = None,
) -> None:
    """Mint a magic-link token and deliver it by email.

    Args:
        session: Active SQLAlchemy session.
        email: Recipient address.
        app_client_id: ``app_clients.client_id`` of the requesting app
            (recorded for scoping; validation of the redirect is the
            caller's job).
        redirect_url: Verify endpoint on the consuming app. The raw
            token is appended as a ``token=`` query string parameter.
        sender: Optional email backend. Defaults to SendGrid.
    """
    settings = get_settings()
    raw_token = _generate_token()
    token_hash = _hash_token(raw_token)
    expires_at = datetime.now(tz=UTC) + timedelta(
        seconds=settings.magic_link_ttl_seconds
    )
    repo.create_magic_link_token(
        session,
        email=email,
        token_hash=token_hash,
        expires_at=expires_at,
    )
    # Binding is retained on the row for audit but unused at runtime today.
    _ = app_client_id

    link = _build_link(redirect_url, raw_token)
    (sender or get_default_sender()).send(
        to=email,
        subject="Your sign-in link",
        body=_render_email_body(link),
    )


def verify_magic_link(
    session: Session,
    *,
    token: str,
    app_client_id: str,
    scopes: list[str] | None = None,
) -> tokens.TokenPair:
    """Redeem a magic-link token and mint a session for its user.

    On first verify for an unseen email the user row is created
    implicitly — magic-link *is* the signup path.

    Args:
        session: Active SQLAlchemy session.
        token: The raw token from the link the user clicked.
        app_client_id: ``app_clients.client_id`` for whom the session
            is being issued (becomes the JWT ``aud`` claim).
        scopes: Optional scopes to embed in the issued access token.

    Returns:
        A matched :class:`~knuckles.services.tokens.TokenPair`.

    Raises:
        AppError: With code ``MAGIC_LINK_INVALID`` (unknown token),
            ``MAGIC_LINK_ALREADY_USED`` (already redeemed), or
            ``MAGIC_LINK_EXPIRED`` (past ``expires_at``).
    """
    row = repo.get_magic_link_by_hash(session, _hash_token(token))
    if row is None:
        raise AppError(
            code=MAGIC_LINK_INVALID,
            message="Magic link is invalid.",
            status_code=400,
        )
    if row.used_at is not None:
        raise AppError(
            code=MAGIC_LINK_ALREADY_USED,
            message="Magic link has already been used.",
            status_code=400,
        )
    expires_at = row.expires_at
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=UTC)
    if expires_at <= datetime.now(tz=UTC):
        raise AppError(
            code=MAGIC_LINK_EXPIRED,
            message="Magic link has expired.",
            status_code=400,
        )

    user = repo.get_user_by_email(session, row.email)
    if user is None:
        user = repo.create_user(session, email=row.email)

    repo.mark_magic_link_used(session, row, user_id=user.id)

    return tokens.issue_session(
        session,
        user_id=user.id,
        app_client_id=app_client_id,
        scopes=scopes,
        email=user.email,
    )
