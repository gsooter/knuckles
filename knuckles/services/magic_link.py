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


_BODY_STYLE = (
    "margin:0;padding:0;background:#f5f5f5;"
    "font-family:-apple-system,BlinkMacSystemFont,"
    "'Segoe UI',Helvetica,Arial,sans-serif;"
)
_OUTER_TABLE_STYLE = "background:#f5f5f5;padding:40px 20px;"
_CARD_STYLE = (
    "max-width:480px;background:#ffffff;" "border-radius:12px;border:1px solid #e5e5e5;"
)
_HEADER_CELL_STYLE = "padding:40px 40px 24px;text-align:center;"
_HEADER_TEXT_STYLE = (
    "margin:0;font-size:22px;font-weight:600;" "color:#1a1a1a;letter-spacing:-0.3px;"
)
_BODY_CELL_STYLE = "padding:0 40px 32px;"
_LEDE_STYLE = "margin:0 0 24px;font-size:16px;line-height:1.5;color:#333;"
_BUTTON_CELL_STYLE = "padding:8px 0 24px;"
_BUTTON_STYLE = (
    "display:inline-block;padding:14px 28px;"
    "background:#1a1a1a;color:#ffffff;text-decoration:none;"
    "border-radius:8px;font-size:15px;font-weight:500;"
)
_FALLBACK_LEAD_STYLE = "margin:0 0 8px;font-size:13px;line-height:1.5;color:#666;"
_FALLBACK_LINK_WRAP_STYLE = (
    "margin:0;font-size:13px;line-height:1.5;" "color:#888;word-break:break-all;"
)
_FALLBACK_LINK_STYLE = "color:#888;text-decoration:underline;"
_FOOTER_CELL_STYLE = "padding:0 40px 32px;border-top:1px solid #eee;"
_FOOTER_STYLE = "margin:24px 0 0;font-size:12px;line-height:1.5;color:#999;"

_EMAIL_TEMPLATE = f"""\
<!DOCTYPE html>
<html>
  <body style="{_BODY_STYLE}">
    <table role="presentation" cellspacing="0" cellpadding="0" border="0"
           width="100%" style="{_OUTER_TABLE_STYLE}">
      <tr>
        <td align="center">
          <table role="presentation" cellspacing="0" cellpadding="0" border="0"
                 width="480" style="{_CARD_STYLE}">
            <tr>
              <td style="{_HEADER_CELL_STYLE}">
                <h1 style="{_HEADER_TEXT_STYLE}">{{app_name}}</h1>
              </td>
            </tr>
            <tr>
              <td style="{_BODY_CELL_STYLE}">
                <p style="{_LEDE_STYLE}">Click the button below to sign in. This link expires in 15 minutes and can only be used once.</p>
                <table role="presentation" cellspacing="0" cellpadding="0"
                       border="0" width="100%">
                  <tr>
                    <td align="center" style="{_BUTTON_CELL_STYLE}">
                      <a href="{{link}}" style="{_BUTTON_STYLE}">Sign in to {{app_name}}</a>
                    </td>
                  </tr>
                </table>
                <p style="{_FALLBACK_LEAD_STYLE}">Or paste this link into your browser:</p>
                <p style="{_FALLBACK_LINK_WRAP_STYLE}"><a href="{{link}}" style="{_FALLBACK_LINK_STYLE}">{{link}}</a></p>
              </td>
            </tr>
            <tr>
              <td style="{_FOOTER_CELL_STYLE}">
                <p style="{_FOOTER_STYLE}">If you didn't request this email, you can safely ignore it.</p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
</html>
"""  # noqa: E501


def _render_email_body(link: str, app_name: str) -> str:
    """Render the HTML body of the magic-link email.

    Args:
        link: The fully-assembled magic-link URL.
        app_name: Display name of the requesting app; rendered in the
            email header and the call-to-action button so the recipient
            sees consistent branding between the UI they started from
            and the email they received.

    Returns:
        HTML body content for the outgoing email.
    """
    return _EMAIL_TEMPLATE.format(link=link, app_name=app_name)


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
        sender: Optional email backend. Defaults to Resend.
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

    app_client = repo.get_app_client(session, app_client_id)
    app_name = app_client.app_name if app_client is not None else "your account"

    link = _build_link(redirect_url, raw_token)
    (sender or get_default_sender()).send(
        to=email,
        subject=f"Sign in to {app_name}",
        body=_render_email_body(link, app_name),
        from_name=app_name,
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
