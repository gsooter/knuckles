"""Tests for the email-change ceremony in :mod:`knuckles.services.magic_link`.

The flow is the verified two-step: :func:`start_email_change` mints a
purpose-tagged magic-link row and emails the *new* address;
:func:`verify_email_change` redeems the token, enforces uniqueness,
and rewrites ``users.email``. Sessions are deliberately left intact —
access tokens carry the old email claim until refresh.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from knuckles.core.exceptions import (
    EMAIL_IN_USE,
    MAGIC_LINK_ALREADY_USED,
    MAGIC_LINK_EXPIRED,
    MAGIC_LINK_INVALID,
    AppError,
)
from knuckles.data.models import MagicLinkToken, User
from knuckles.data.repositories import auth as repo
from knuckles.services import magic_link, tokens


class _FakeEmailSender:
    """In-process recorder that captures outgoing emails.

    Attributes:
        sent: List of the (to, subject, body, from_name) tuples captured
            in order.
    """

    def __init__(self) -> None:
        """Initialize an empty capture list."""
        self.sent: list[tuple[str, str, str, str | None]] = []

    def send(
        self,
        *,
        to: str,
        subject: str,
        body: str,
        from_name: str | None = None,
    ) -> None:
        """Record the send instead of hitting Resend.

        Args:
            to: Recipient email address.
            subject: Email subject line.
            body: Email body (plain text or HTML).
            from_name: Optional display name the ``From`` header should
                use.
        """
        self.sent.append((to, subject, body, from_name))


@pytest.fixture()
def email_sender() -> _FakeEmailSender:
    """Return a fresh fake email sender for each test.

    Returns:
        A new :class:`_FakeEmailSender` with no captured sends.
    """
    return _FakeEmailSender()


def _extract_token(body: str) -> str:
    """Pull the raw token out of a captured email body.

    Args:
        body: The HTML email body recorded by :class:`_FakeEmailSender`.

    Returns:
        The raw URL-safe token from the first ``token=`` query parameter.
    """
    match = re.search(r"token=([A-Za-z0-9_-]+)", body)
    assert match is not None, "no token in email body"
    return match.group(1)


def _register_client(db_session: Session) -> str:
    """Register a minimal app-client row for the test and return its id.

    Args:
        db_session: Active SQLAlchemy session.

    Returns:
        The new ``app_clients.client_id``.
    """
    repo.create_app_client(
        db_session,
        client_id="greenroom-prod",
        app_name="Greenroom",
        client_secret_hash="hash",
        allowed_origins=["http://localhost:3000"],
    )
    return "greenroom-prod"


def _start_change(
    db_session: Session,
    sender: _FakeEmailSender,
    *,
    user: User,
    new_email: str = "new@example.com",
    app_client_id: str = "greenroom-prod",
) -> str:
    """Run :func:`start_email_change` and return the raw token sent.

    Args:
        db_session: Active SQLAlchemy session.
        sender: Fake sender capturing the email.
        user: User changing their address.
        new_email: Target address for the change.
        app_client_id: Issuing tenant.

    Returns:
        The raw token extracted from the captured email.
    """
    magic_link.start_email_change(
        db_session,
        user_id=user.id,
        new_email=new_email,
        app_client_id=app_client_id,
        redirect_url="http://localhost:3000/settings/email/verify",
        sender=sender,
    )
    return _extract_token(sender.sent[-1][2])


def test_start_email_change_sends_to_new_address_with_branding(
    db_session: Session, email_sender: _FakeEmailSender
) -> None:
    """The confirmation email goes to the NEW address with tenant branding."""
    client_id = _register_client(db_session)
    user = repo.create_user(db_session, email="old@example.com")

    _start_change(db_session, email_sender, user=user, app_client_id=client_id)

    assert len(email_sender.sent) == 1
    to, subject, body, from_name = email_sender.sent[0]
    assert to == "new@example.com"
    assert subject == "Confirm your new email for Greenroom"
    assert from_name == "Greenroom"
    assert "http://localhost:3000/settings/email/verify?token=" in body


def test_start_email_change_persists_purpose_tagged_hashed_row(
    db_session: Session, email_sender: _FakeEmailSender
) -> None:
    """The row stores the hash (never the raw token) and the purpose tag."""
    client_id = _register_client(db_session)
    user = repo.create_user(db_session, email="old@example.com")

    raw = _start_change(db_session, email_sender, user=user, app_client_id=client_id)

    row = db_session.query(MagicLinkToken).one()
    assert row.purpose == "email_change"
    assert row.email == "new@example.com"
    assert row.user_id == user.id
    assert row.app_client_id == client_id
    assert row.used_at is None
    assert row.token_hash == hashlib.sha256(raw.encode("ascii")).hexdigest()


def test_verify_email_change_updates_email_and_marks_used(
    db_session: Session, email_sender: _FakeEmailSender
) -> None:
    """Happy path: the user's email is rewritten and the row consumed."""
    client_id = _register_client(db_session)
    user = repo.create_user(db_session, email="old@example.com")
    raw = _start_change(db_session, email_sender, user=user, app_client_id=client_id)

    result = magic_link.verify_email_change(
        db_session, token=raw, app_client_id=client_id
    )

    assert result.id == user.id
    assert result.email == "new@example.com"
    assert user.email == "new@example.com"
    row = db_session.query(MagicLinkToken).one()
    assert row.used_at is not None


def test_verify_email_change_rejects_sign_in_purpose_token(
    db_session: Session, email_sender: _FakeEmailSender
) -> None:
    """A plain sign-in token cannot drive an email change."""
    client_id = _register_client(db_session)
    repo.create_user(db_session, email="old@example.com")
    magic_link.start_magic_link(
        db_session,
        email="old@example.com",
        app_client_id=client_id,
        redirect_url="http://localhost:3000/auth/verify",
        sender=email_sender,
    )
    raw = _extract_token(email_sender.sent[0][2])

    with pytest.raises(AppError) as exc:
        magic_link.verify_email_change(db_session, token=raw, app_client_id=client_id)
    assert exc.value.code == MAGIC_LINK_INVALID


def test_verify_email_change_rejects_taken_email(
    db_session: Session, email_sender: _FakeEmailSender
) -> None:
    """Another user already holding the new address is a 409 EMAIL_IN_USE."""
    client_id = _register_client(db_session)
    user = repo.create_user(db_session, email="old@example.com")
    repo.create_user(db_session, email="taken@example.com")
    raw = _start_change(
        db_session,
        email_sender,
        user=user,
        new_email="taken@example.com",
        app_client_id=client_id,
    )

    with pytest.raises(AppError) as exc:
        magic_link.verify_email_change(db_session, token=raw, app_client_id=client_id)
    assert exc.value.code == EMAIL_IN_USE
    assert exc.value.status_code == 409
    assert user.email == "old@example.com"


def test_verify_email_change_rejects_cross_tenant_redemption(
    db_session: Session, email_sender: _FakeEmailSender
) -> None:
    """A change started under tenant A cannot be verified through tenant B."""
    client_id = _register_client(db_session)
    repo.create_app_client(
        db_session,
        client_id="other-app",
        app_name="Other App",
        client_secret_hash="hash2",
        allowed_origins=["http://localhost:4000"],
    )
    user = repo.create_user(db_session, email="old@example.com")
    raw = _start_change(db_session, email_sender, user=user, app_client_id=client_id)

    with pytest.raises(AppError) as exc:
        magic_link.verify_email_change(db_session, token=raw, app_client_id="other-app")
    assert exc.value.code == MAGIC_LINK_INVALID
    assert user.email == "old@example.com"


def test_verify_email_change_rejects_expired_token(
    db_session: Session, email_sender: _FakeEmailSender
) -> None:
    """An expired email-change token yields MAGIC_LINK_EXPIRED."""
    client_id = _register_client(db_session)
    user = repo.create_user(db_session, email="old@example.com")
    raw = _start_change(db_session, email_sender, user=user, app_client_id=client_id)

    row = db_session.query(MagicLinkToken).one()
    row.expires_at = datetime.now(tz=UTC) - timedelta(seconds=1)
    db_session.flush()

    with pytest.raises(AppError) as exc:
        magic_link.verify_email_change(db_session, token=raw, app_client_id=client_id)
    assert exc.value.code == MAGIC_LINK_EXPIRED


def test_verify_email_change_rejects_reused_token(
    db_session: Session, email_sender: _FakeEmailSender
) -> None:
    """A second redemption of the same token is MAGIC_LINK_ALREADY_USED."""
    client_id = _register_client(db_session)
    user = repo.create_user(db_session, email="old@example.com")
    raw = _start_change(db_session, email_sender, user=user, app_client_id=client_id)

    magic_link.verify_email_change(db_session, token=raw, app_client_id=client_id)
    with pytest.raises(AppError) as exc:
        magic_link.verify_email_change(db_session, token=raw, app_client_id=client_id)
    assert exc.value.code == MAGIC_LINK_ALREADY_USED


def test_verify_email_change_rejects_inactive_user(
    db_session: Session, email_sender: _FakeEmailSender
) -> None:
    """A deactivated account cannot complete an email change."""
    client_id = _register_client(db_session)
    user = repo.create_user(db_session, email="old@example.com")
    raw = _start_change(db_session, email_sender, user=user, app_client_id=client_id)
    user.is_active = False
    db_session.flush()

    with pytest.raises(AppError) as exc:
        magic_link.verify_email_change(db_session, token=raw, app_client_id=client_id)
    assert exc.value.code == MAGIC_LINK_INVALID


def test_verify_email_change_rejects_row_without_user(
    db_session: Session,
) -> None:
    """An email-change row with no ``user_id`` is invalid by definition."""
    client_id = _register_client(db_session)
    raw = "orphan-change-token"
    repo.create_magic_link_token(
        db_session,
        email="new@example.com",
        token_hash=hashlib.sha256(raw.encode("ascii")).hexdigest(),
        expires_at=datetime.now(tz=UTC) + timedelta(minutes=10),
        app_client_id=client_id,
        purpose="email_change",
    )

    with pytest.raises(AppError) as exc:
        magic_link.verify_email_change(db_session, token=raw, app_client_id=client_id)
    assert exc.value.code == MAGIC_LINK_INVALID


def test_verify_email_change_rejects_deleted_user(
    db_session: Session,
) -> None:
    """A row pointing at a since-deleted user is invalid."""
    client_id = _register_client(db_session)
    raw = "ghost-change-token"
    repo.create_magic_link_token(
        db_session,
        email="new@example.com",
        token_hash=hashlib.sha256(raw.encode("ascii")).hexdigest(),
        expires_at=datetime.now(tz=UTC) + timedelta(minutes=10),
        user_id=None,
        app_client_id=client_id,
        purpose="email_change",
    )
    row = db_session.query(MagicLinkToken).one()
    row.user_id = uuid.uuid4()
    db_session.flush()

    with pytest.raises(AppError) as exc:
        magic_link.verify_email_change(db_session, token=raw, app_client_id=client_id)
    assert exc.value.code == MAGIC_LINK_INVALID


def test_verify_email_change_does_not_revoke_sessions(
    db_session: Session, email_sender: _FakeEmailSender
) -> None:
    """Existing refresh tokens survive an email change by design.

    Access tokens carry the old email claim until refresh; consuming
    apps must tolerate that.
    """
    client_id = _register_client(db_session)
    user = repo.create_user(db_session, email="old@example.com")
    pair = tokens.issue_session(db_session, user_id=user.id, app_client_id=client_id)
    raw = _start_change(db_session, email_sender, user=user, app_client_id=client_id)

    magic_link.verify_email_change(db_session, token=raw, app_client_id=client_id)

    token_hash = hashlib.sha256(pair.refresh_token.encode("ascii")).hexdigest()
    row = repo.get_refresh_token_by_hash(db_session, token_hash)
    assert row is not None and row.used_at is None
