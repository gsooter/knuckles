"""Magic-link ceremonies: one-time email secrets for sign-in and email change.

The sign-in flow has two service entry points:

* :func:`start_magic_link` — mint a raw token, persist only its SHA-256
  digest, and send the recipient a link containing the raw token.
* :func:`verify_magic_link` — hash the presented token, look the row
  up, validate (purpose, tenant, not used, not expired), create the
  user if the email is new, mark the row consumed, and return an
  access+refresh pair via :func:`knuckles.services.tokens.issue_session`.

The email-change flow reuses the same table and token mechanics with a
``purpose="email_change"`` tag:

* :func:`start_email_change` — mint a token bound to the current user
  and the *new* address, and email the new address.
* :func:`verify_email_change` — redeem the token, enforce email
  uniqueness, and rewrite ``users.email``.

Purposes are mutually exclusive at verify time — a token minted for
one ceremony can never be redeemed through the other.

The raw token is 32 bytes of ``secrets.token_urlsafe`` entropy. It
lives in the outgoing email URL and in memory during verify — the DB
only ever sees the hash (Decision #006).
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import uuid
from datetime import UTC, datetime, timedelta
from urllib.parse import urlencode

from sqlalchemy.orm import Session

from knuckles.core.config import get_settings
from knuckles.core.exceptions import (
    EMAIL_IN_USE,
    MAGIC_LINK_ALREADY_USED,
    MAGIC_LINK_EXPIRED,
    MAGIC_LINK_INVALID,
    AppError,
)
from knuckles.data.models import AppClient, MagicLinkToken, User
from knuckles.data.repositories import auth as repo
from knuckles.services import tokens
from knuckles.services._tenant_config import resolve_tenant_fields
from knuckles.services.email import EmailSender, get_default_sender

_audit = logging.getLogger("knuckles.audit")

# Magic-link ceremony tags persisted in ``magic_link_tokens.purpose``.
PURPOSE_SIGN_IN = "sign_in"
PURPOSE_EMAIL_CHANGE = "email_change"


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
    "max-width:480px;background:#ffffff;border-radius:12px;border:1px solid #e5e5e5;"
)
_HEADER_CELL_STYLE = "padding:40px 40px 24px;text-align:center;"
_HEADER_TEXT_STYLE = (
    "margin:0;font-size:22px;font-weight:600;color:#1a1a1a;letter-spacing:-0.3px;"
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
    "margin:0;font-size:13px;line-height:1.5;color:#888;word-break:break-all;"
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
                <p style="{_LEDE_STYLE}">{{lede}}</p>
                <table role="presentation" cellspacing="0" cellpadding="0"
                       border="0" width="100%">
                  <tr>
                    <td align="center" style="{_BUTTON_CELL_STYLE}">
                      <a href="{{link}}" style="{_BUTTON_STYLE}">{{action}}</a>
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


_SIGN_IN_LEDE = (
    "Click the button below to sign in. This link expires in 15 minutes "
    "and can only be used once."
)
_EMAIL_CHANGE_LEDE = (
    "Click the button below to confirm your new email address. This link "
    "expires in 15 minutes and can only be used once."
)


def _render_email_body(
    link: str,
    app_name: str,
    *,
    lede: str = _SIGN_IN_LEDE,
    action: str | None = None,
) -> str:
    """Render the HTML body of a magic-link email.

    Args:
        link: The fully-assembled magic-link URL.
        app_name: Display name of the requesting app; rendered in the
            email header so the recipient sees consistent branding
            between the UI they started from and the email they
            received.
        lede: Lead paragraph above the button. Defaults to the
            sign-in copy.
        action: Button label. Defaults to ``"Sign in to {app_name}"``.

    Returns:
        HTML body content for the outgoing email.
    """
    return _EMAIL_TEMPLATE.format(
        link=link,
        app_name=app_name,
        lede=lede,
        action=action or f"Sign in to {app_name}",
    )


def _tenant_sender(app_client: AppClient | None) -> EmailSender:
    """Resolve the email backend for one tenant (Decision #017).

    The Resend group is non-atomic: a tenant may override only its
    From address while the API key stays operator-global during the
    transition.

    Args:
        app_client: The calling tenant's ``app_clients`` row, or
            ``None`` for legacy callers.

    Returns:
        A concrete :class:`EmailSender` configured with the tenant's
        resolved Resend credentials.
    """
    settings = get_settings()
    resolved = resolve_tenant_fields(
        app_client,
        group="resend",
        fields={
            "resend_api_key": settings.resend_api_key,
            "resend_from_email": settings.resend_from_email,
        },
        atomic=False,
    )
    return get_default_sender(
        api_key=resolved["resend_api_key"] or None,
        from_address=resolved["resend_from_email"] or None,
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
        app_client_id=app_client_id,
    )

    app_client = repo.get_app_client(session, app_client_id)
    app_name = app_client.app_name if app_client is not None else "your account"

    link = _build_link(redirect_url, raw_token)
    effective_sender = sender or _tenant_sender(app_client)
    effective_sender.send(
        to=email,
        subject=f"Sign in to {app_name}",
        body=_render_email_body(link, app_name),
        from_name=app_name,
    )


def _load_redeemable_row(
    session: Session,
    *,
    token: str,
    app_client_id: str,
    purpose: str,
) -> MagicLinkToken:
    """Look up a magic-link row and run the shared redemption checks.

    Both ceremonies (sign-in and email change) funnel through this
    helper so the validation rules live in exactly one place: the row
    must exist, carry the expected ``purpose``, belong to the calling
    tenant, be unredeemed, and be unexpired.

    Args:
        session: Active SQLAlchemy session.
        token: The raw token from the link the user clicked.
        app_client_id: ``app_clients.client_id`` of the calling app.
        purpose: Required ceremony tag (``"sign_in"`` or
            ``"email_change"``). A mismatch is indistinguishable from
            an unknown token by design.

    Returns:
        The validated, still-redeemable ``MagicLinkToken`` row.

    Raises:
        AppError: With code ``MAGIC_LINK_INVALID`` (unknown token,
            wrong ceremony purpose, or token issued through a
            different app client), ``MAGIC_LINK_ALREADY_USED``
            (already redeemed), or ``MAGIC_LINK_EXPIRED`` (past
            ``expires_at``).
    """
    row = repo.get_magic_link_by_hash(session, _hash_token(token))
    if row is None:
        raise AppError(
            code=MAGIC_LINK_INVALID,
            message="Magic link is invalid.",
            status_code=400,
        )
    if row.purpose != purpose:
        # A token minted for one ceremony must never redeem another —
        # an email-change token redeemed as a sign-in would mint a
        # session for a user that may not exist yet.
        raise AppError(
            code=MAGIC_LINK_INVALID,
            message="Magic link is invalid.",
            status_code=400,
        )
    if row.app_client_id is not None and row.app_client_id != app_client_id:
        # The link belongs to a different tenant (Decision #019). A
        # NULL means the row predates tenant scoping; those verify
        # unscoped until their 15-minute TTL closes the window.
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
    return row


def verify_magic_link(
    session: Session,
    *,
    token: str,
    app_client_id: str,
    scopes: list[str] | None = None,
) -> tokens.TokenPair:
    """Redeem a magic-link token and mint a session for its user.

    On first verify for an unseen email the user row is created
    implicitly — magic-link *is* the signup path. Only rows minted
    with ``purpose="sign_in"`` are accepted; an email-change token is
    rejected as invalid.

    Args:
        session: Active SQLAlchemy session.
        token: The raw token from the link the user clicked.
        app_client_id: ``app_clients.client_id`` for whom the session
            is being issued (becomes the JWT ``aud`` claim).
        scopes: Optional scopes to embed in the issued access token.

    Returns:
        A matched :class:`~knuckles.services.tokens.TokenPair`.

    Raises:
        AppError: With code ``MAGIC_LINK_INVALID`` (unknown token,
            non-sign-in purpose, token issued through a different app
            client, or the owning user has been deactivated),
            ``MAGIC_LINK_ALREADY_USED`` (already redeemed), or
            ``MAGIC_LINK_EXPIRED`` (past ``expires_at``).
    """
    row = _load_redeemable_row(
        session,
        token=token,
        app_client_id=app_client_id,
        purpose=PURPOSE_SIGN_IN,
    )

    user = repo.get_user_by_email(session, row.email)
    if user is not None and not user.is_active:
        # Mirror the OAuth and passkey paths: a deactivated account
        # must not regain a session just because it kept email access.
        raise AppError(
            code=MAGIC_LINK_INVALID,
            message="Magic link is invalid.",
            status_code=400,
        )
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


def start_email_change(
    session: Session,
    *,
    user_id: uuid.UUID,
    new_email: str,
    app_client_id: str,
    redirect_url: str,
    sender: EmailSender | None = None,
) -> None:
    """Mint an email-change token and deliver it to the new address.

    The token row is bound at mint time to the requesting user and
    tagged ``purpose="email_change"`` so it can never be redeemed as a
    sign-in. Sending to the *new* address is the verification: only
    someone with access to that inbox can complete the change.

    Args:
        session: Active SQLAlchemy session.
        user_id: UUID of the signed-in user requesting the change.
        new_email: The address the account should move to. Uniqueness
            is enforced at verify time, not here, so this call leaks
            nothing about which addresses are registered.
        app_client_id: ``app_clients.client_id`` of the requesting app
            (the token can only be verified through the same tenant).
        redirect_url: Verify endpoint on the consuming app. The raw
            token is appended as a ``token=`` query string parameter.
        sender: Optional email backend. Defaults to the tenant's
            resolved Resend credentials.
    """
    settings = get_settings()
    raw_token = _generate_token()
    expires_at = datetime.now(tz=UTC) + timedelta(
        seconds=settings.magic_link_ttl_seconds
    )
    repo.create_magic_link_token(
        session,
        email=new_email,
        token_hash=_hash_token(raw_token),
        expires_at=expires_at,
        user_id=user_id,
        app_client_id=app_client_id,
        purpose=PURPOSE_EMAIL_CHANGE,
    )

    app_client = repo.get_app_client(session, app_client_id)
    app_name = app_client.app_name if app_client is not None else "your account"

    link = _build_link(redirect_url, raw_token)
    effective_sender = sender or _tenant_sender(app_client)
    effective_sender.send(
        to=new_email,
        subject=f"Confirm your new email for {app_name}",
        body=_render_email_body(
            link,
            app_name,
            lede=_EMAIL_CHANGE_LEDE,
            action="Confirm new email",
        ),
        from_name=app_name,
    )


def verify_email_change(
    session: Session,
    *,
    token: str,
    app_client_id: str,
) -> User:
    """Redeem an email-change token and rewrite the user's email.

    Sessions are deliberately **not** revoked: outstanding access
    tokens carry the old email claim until their next refresh, and
    consuming apps must tolerate that window. Revoking here would
    punish the user for confirming their own change without closing
    any real attack — the bearer of the link already controls the new
    inbox.

    Args:
        session: Active SQLAlchemy session.
        token: The raw token from the confirmation link.
        app_client_id: ``app_clients.client_id`` of the calling app;
            must match the tenant the change was started through.

    Returns:
        The updated ``User`` with the new email applied.

    Raises:
        AppError: With code ``MAGIC_LINK_INVALID`` (unknown token,
            non-email-change purpose, different tenant, missing or
            deactivated user), ``MAGIC_LINK_ALREADY_USED`` (already
            redeemed), ``MAGIC_LINK_EXPIRED`` (past ``expires_at``),
            or ``EMAIL_IN_USE`` (HTTP 409) when another account
            already owns the new address.
    """
    row = _load_redeemable_row(
        session,
        token=token,
        app_client_id=app_client_id,
        purpose=PURPOSE_EMAIL_CHANGE,
    )

    if row.user_id is None:
        raise AppError(
            code=MAGIC_LINK_INVALID,
            message="Magic link is invalid.",
            status_code=400,
        )
    user = repo.get_user_by_id(session, row.user_id)
    if user is None or not user.is_active:
        raise AppError(
            code=MAGIC_LINK_INVALID,
            message="Magic link is invalid.",
            status_code=400,
        )

    existing = repo.get_user_by_email(session, row.email)
    if existing is not None and existing.id != user.id:
        raise AppError(
            code=EMAIL_IN_USE,
            message="This email address is already in use.",
            status_code=409,
        )

    repo.update_user_email(session, user, email=row.email)
    repo.mark_magic_link_used(session, row, user_id=user.id)
    # Deliberately no email addresses in the log line.
    _audit.info(
        "email_changed user_id=%s app_client_id=%s",
        user.id,
        app_client_id,
    )
    return user
