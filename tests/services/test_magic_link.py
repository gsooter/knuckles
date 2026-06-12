"""Tests for :mod:`knuckles.services.magic_link`.

The service owns the full magic-link ceremony: mint a one-time secret,
persist only its hash, send the link by email, then verify a presented
secret on the callback and mint a session. These tests drive the
contract end-to-end using an in-process fake email sender.
"""

from __future__ import annotations

import hashlib
import re
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy.orm import Session

from knuckles.core.exceptions import (
    MAGIC_LINK_ALREADY_USED,
    MAGIC_LINK_EXPIRED,
    MAGIC_LINK_INVALID,
    AppError,
)
from knuckles.data.models import MagicLinkToken
from knuckles.data.repositories import auth as repo
from knuckles.services import magic_link


class _FakeEmailSender:
    """In-process recorder that captures magic-link emails.

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
    """Pull the raw magic-link token out of a captured email body.

    Args:
        body: The HTML email body recorded by :class:`_FakeEmailSender`.

    Returns:
        The raw URL-safe token from the first ``token=`` query parameter.
    """
    match = re.search(r"token=([A-Za-z0-9_-]+)", body)
    assert match is not None, "no token in email body"
    return match.group(1)


def _aware(dt: datetime) -> datetime:
    """Coerce a possibly-naive datetime to UTC-aware.

    SQLite drops timezone info on read; this helper papers over that
    so tests can compare against ``datetime.now(tz=UTC)``.

    Args:
        dt: A datetime that may or may not carry tz info.

    Returns:
        A timezone-aware datetime in UTC.
    """
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=UTC)


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


def test_start_magic_link_sends_email_and_persists_hash(
    db_session: Session, email_sender: _FakeEmailSender
) -> None:
    """Starting the ceremony writes one hashed row and sends one email."""
    client_id = _register_client(db_session)

    magic_link.start_magic_link(
        db_session,
        email="user@example.com",
        app_client_id=client_id,
        redirect_url="http://localhost:3000/auth/verify",
        sender=email_sender,
    )

    rows = db_session.query(MagicLinkToken).all()
    assert len(rows) == 1
    assert rows[0].email == "user@example.com"
    assert rows[0].used_at is None
    assert _aware(rows[0].expires_at) > datetime.now(tz=UTC)

    assert len(email_sender.sent) == 1
    to, subject, body, from_name = email_sender.sent[0]
    assert to == "user@example.com"
    # Body must contain a link with a token — check presence, not exact value.
    assert "http://localhost:3000/auth/verify?token=" in body
    # Branding: recipient should see the calling app, not generic Knuckles copy.
    assert subject == "Sign in to Greenroom"
    assert from_name == "Greenroom"
    assert "Greenroom" in body


def test_start_magic_link_plaintext_token_is_never_persisted(
    db_session: Session, email_sender: _FakeEmailSender
) -> None:
    """The DB stores the SHA-256 digest, never the raw token."""
    client_id = _register_client(db_session)

    magic_link.start_magic_link(
        db_session,
        email="user@example.com",
        app_client_id=client_id,
        redirect_url="http://localhost:3000/auth/verify",
        sender=email_sender,
    )

    raw_token = _extract_token(email_sender.sent[0][2])

    row = db_session.query(MagicLinkToken).one()
    assert row.token_hash != raw_token
    assert row.token_hash == hashlib.sha256(raw_token.encode("ascii")).hexdigest()


def test_verify_magic_link_creates_user_and_issues_tokens(
    db_session: Session, email_sender: _FakeEmailSender
) -> None:
    """First verify for a new email creates a user and returns tokens."""
    client_id = _register_client(db_session)
    magic_link.start_magic_link(
        db_session,
        email="new@example.com",
        app_client_id=client_id,
        redirect_url="http://localhost:3000/auth/verify",
        sender=email_sender,
    )
    raw = _extract_token(email_sender.sent[0][2])

    pair = magic_link.verify_magic_link(db_session, token=raw, app_client_id=client_id)

    assert pair.access_token
    assert pair.refresh_token

    user = repo.get_user_by_email(db_session, "new@example.com")
    assert user is not None

    row = db_session.query(MagicLinkToken).one()
    assert row.used_at is not None
    assert row.user_id == user.id


def test_verify_magic_link_reuses_existing_user(
    db_session: Session, email_sender: _FakeEmailSender
) -> None:
    """Verifying for an address that already exists reuses the user row."""
    client_id = _register_client(db_session)
    existing = repo.create_user(db_session, email="returning@example.com")

    magic_link.start_magic_link(
        db_session,
        email="returning@example.com",
        app_client_id=client_id,
        redirect_url="http://localhost:3000/auth/verify",
        sender=email_sender,
    )
    raw = _extract_token(email_sender.sent[0][2])

    magic_link.verify_magic_link(db_session, token=raw, app_client_id=client_id)

    user = repo.get_user_by_email(db_session, "returning@example.com")
    assert user is not None
    assert user.id == existing.id


def test_verify_magic_link_rejects_unknown_token(db_session: Session) -> None:
    """An unknown raw token yields ``MAGIC_LINK_INVALID``."""
    client_id = _register_client(db_session)

    with pytest.raises(AppError) as exc:
        magic_link.verify_magic_link(
            db_session, token="not-real", app_client_id=client_id
        )
    assert exc.value.code == MAGIC_LINK_INVALID


def test_verify_magic_link_rejects_expired_token(
    db_session: Session, email_sender: _FakeEmailSender
) -> None:
    """An expired (but not yet used) token yields ``MAGIC_LINK_EXPIRED``."""
    client_id = _register_client(db_session)
    magic_link.start_magic_link(
        db_session,
        email="user@example.com",
        app_client_id=client_id,
        redirect_url="http://localhost:3000/auth/verify",
        sender=email_sender,
    )
    raw = _extract_token(email_sender.sent[0][2])

    row = db_session.query(MagicLinkToken).one()
    row.expires_at = datetime.now(tz=UTC) - timedelta(seconds=1)
    db_session.flush()

    with pytest.raises(AppError) as exc:
        magic_link.verify_magic_link(db_session, token=raw, app_client_id=client_id)
    assert exc.value.code == MAGIC_LINK_EXPIRED


def test_verify_magic_link_rejects_reused_token(
    db_session: Session, email_sender: _FakeEmailSender
) -> None:
    """A token that has already been redeemed yields ``MAGIC_LINK_ALREADY_USED``."""
    client_id = _register_client(db_session)
    magic_link.start_magic_link(
        db_session,
        email="user@example.com",
        app_client_id=client_id,
        redirect_url="http://localhost:3000/auth/verify",
        sender=email_sender,
    )
    raw = _extract_token(email_sender.sent[0][2])

    magic_link.verify_magic_link(db_session, token=raw, app_client_id=client_id)

    with pytest.raises(AppError) as exc:
        magic_link.verify_magic_link(db_session, token=raw, app_client_id=client_id)
    assert exc.value.code == MAGIC_LINK_ALREADY_USED


def test_start_magic_link_resolves_tenant_resend_credentials(
    db_session: Session,
    email_sender: _FakeEmailSender,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Tenant Resend columns reach the sender factory (Decision #017).

    When the caller does not inject a sender, the service must build
    one from the app-client's own ``resend_api_key`` /
    ``resend_from_email`` columns — not the operator env vars.
    """
    client_id = _register_client(db_session)
    row = repo.get_app_client(db_session, client_id)
    assert row is not None
    row.resend_api_key = "re_tenant_key"
    row.resend_from_email = "auth@tenant.example"
    db_session.flush()

    factory_calls: list[tuple[str | None, str | None]] = []

    def _recording_factory(
        api_key: str | None = None,
        from_address: str | None = None,
    ) -> _FakeEmailSender:
        """Record the credentials the service resolved.

        Args:
            api_key: Resend API key the service passed.
            from_address: From address the service passed.

        Returns:
            The shared fake sender.
        """
        factory_calls.append((api_key, from_address))
        return email_sender

    monkeypatch.setattr(magic_link, "get_default_sender", _recording_factory)

    magic_link.start_magic_link(
        db_session,
        email="user@example.com",
        app_client_id=client_id,
        redirect_url="http://localhost:3000/auth/verify",
    )

    assert factory_calls == [("re_tenant_key", "auth@tenant.example")]
    assert len(email_sender.sent) == 1


def test_start_magic_link_null_columns_fall_back_to_env(
    db_session: Session,
    email_sender: _FakeEmailSender,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """NULL tenant columns inherit the operator env credentials.

    The service passes ``None`` for both values so the sender factory
    applies its own env-var fallback — the documented transition
    mechanism for the legacy single-tenant deployment.
    """
    client_id = _register_client(db_session)

    factory_calls: list[tuple[str | None, str | None]] = []

    def _recording_factory(
        api_key: str | None = None,
        from_address: str | None = None,
    ) -> _FakeEmailSender:
        """Record the credentials the service resolved.

        Args:
            api_key: Resend API key the service passed.
            from_address: From address the service passed.

        Returns:
            The shared fake sender.
        """
        factory_calls.append((api_key, from_address))
        return email_sender

    monkeypatch.setattr(magic_link, "get_default_sender", _recording_factory)

    magic_link.start_magic_link(
        db_session,
        email="user@example.com",
        app_client_id=client_id,
        redirect_url="http://localhost:3000/auth/verify",
    )

    assert factory_calls == [(None, None)]


def test_verify_magic_link_rejects_inactive_user(
    db_session: Session, email_sender: _FakeEmailSender
) -> None:
    """A deactivated user cannot redeem a valid magic link.

    Mirrors the OAuth and passkey sign-in paths, which both reject
    inactive users before minting a session.
    """
    client_id = _register_client(db_session)
    user = repo.create_user(db_session, email="banned@example.com")
    user.is_active = False
    db_session.flush()

    magic_link.start_magic_link(
        db_session,
        email="banned@example.com",
        app_client_id=client_id,
        redirect_url="http://localhost:3000/auth/verify",
        sender=email_sender,
    )
    raw = _extract_token(email_sender.sent[0][2])

    with pytest.raises(AppError) as exc:
        magic_link.verify_magic_link(db_session, token=raw, app_client_id=client_id)
    assert exc.value.code == MAGIC_LINK_INVALID
    assert exc.value.status_code == 400


def test_verify_magic_link_rejects_cross_tenant_redemption(
    db_session: Session, email_sender: _FakeEmailSender
) -> None:
    """A link minted for tenant A cannot be redeemed through tenant B.

    The token row records its issuing app client; a different client
    presenting the raw token gets ``MAGIC_LINK_INVALID`` instead of a
    session minted under its own audience (confused deputy).
    """
    client_a = _register_client(db_session)
    repo.create_app_client(
        db_session,
        client_id="other-app",
        app_name="Other App",
        client_secret_hash="hash2",
        allowed_origins=["http://localhost:4000"],
    )

    magic_link.start_magic_link(
        db_session,
        email="user@example.com",
        app_client_id=client_a,
        redirect_url="http://localhost:3000/auth/verify",
        sender=email_sender,
    )
    raw = _extract_token(email_sender.sent[0][2])

    with pytest.raises(AppError) as exc:
        magic_link.verify_magic_link(db_session, token=raw, app_client_id="other-app")
    assert exc.value.code == MAGIC_LINK_INVALID

    # The issuing tenant can still redeem its own link.
    pair = magic_link.verify_magic_link(db_session, token=raw, app_client_id=client_a)
    assert pair.access_token


def test_verify_magic_link_accepts_legacy_unscoped_rows(
    db_session: Session,
) -> None:
    """Rows minted before tenant scoping (NULL client) still verify."""
    client_id = _register_client(db_session)
    raw = "legacy-raw-token"
    repo.create_magic_link_token(
        db_session,
        email="legacy@example.com",
        token_hash=hashlib.sha256(raw.encode("ascii")).hexdigest(),
        expires_at=datetime.now(tz=UTC) + timedelta(minutes=10),
    )

    pair = magic_link.verify_magic_link(db_session, token=raw, app_client_id=client_id)
    assert pair.access_token
