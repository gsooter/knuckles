"""Transactional-email adapter for Knuckles.

Knuckles sends exactly one kind of email in P3 — the magic-link — but
the adapter is factored so future ceremonies (passkey recovery, account
deletion confirmation) can plug in without editing the service layer.

The production backend is SendGrid. Local development (no
``SENDGRID_API_KEY`` set) falls through to :class:`ConsoleEmailSender`,
which prints the would-be email to stdout so the magic-link URL is
copy-pasteable from the Knuckles process log. Tests substitute an
in-process fake. The :class:`EmailSender` protocol exists to formalize
that seam so the service layer can type-annotate the dependency without
a hard import of any concrete sender class.
"""

from __future__ import annotations

import logging
import re
from typing import Protocol

from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail

from knuckles.core.config import get_settings
from knuckles.core.exceptions import EMAIL_DELIVERY_FAILED, AppError

_logger = logging.getLogger(__name__)


class EmailSender(Protocol):
    """Minimal interface every email backend must implement.

    The service layer depends on this protocol, never on a concrete
    sender class, so tests can hand-roll a drop-in recorder without
    monkeypatching SendGrid internals.
    """

    def send(self, *, to: str, subject: str, body: str) -> None:
        """Deliver one email.

        Args:
            to: Recipient email address.
            subject: Email subject line.
            body: Email body. Implementations are free to send it as
                either plain text or HTML.
        """
        ...


class SendGridEmailSender:
    """Production email backend backed by the SendGrid HTTP API."""

    def send(self, *, to: str, subject: str, body: str) -> None:
        """Deliver an email via SendGrid.

        Args:
            to: Recipient email address.
            subject: Email subject line.
            body: Email body. Sent as HTML so ``<a>`` links render.

        Raises:
            AppError: With code ``EMAIL_DELIVERY_FAILED`` if SendGrid
                returns a non-2xx response or the HTTP call raises.
        """
        settings = get_settings()
        message = Mail(
            from_email=settings.sendgrid_from_email,
            to_emails=to,
            subject=subject,
            html_content=body,
        )
        try:
            client = SendGridAPIClient(settings.sendgrid_api_key)
            response = client.send(message)
        except Exception as exc:  # pragma: no cover — network path
            _logger.exception("SendGrid call failed")
            raise AppError(
                code=EMAIL_DELIVERY_FAILED,
                message="Failed to send email.",
                status_code=502,
            ) from exc

        status = getattr(response, "status_code", 0)
        if not (200 <= status < 300):  # pragma: no cover — network path
            _logger.error("SendGrid returned status %s", status)
            raise AppError(
                code=EMAIL_DELIVERY_FAILED,
                message="Failed to send email.",
                status_code=502,
            )


class ConsoleEmailSender:
    """Development email backend that logs outgoing mail to stdout.

    Used automatically when ``SENDGRID_API_KEY`` is empty so local
    magic-link testing does not require a real SendGrid account. The
    body is scanned for an ``http(s)://…`` URL which is printed on its
    own line to make the sign-in link easy to copy from the terminal.
    """

    _URL_RE = re.compile(r"https?://[^\s\"'<>]+")

    def send(self, *, to: str, subject: str, body: str) -> None:
        """Print an email to stdout instead of delivering it.

        Args:
            to: Recipient email address (logged but not used).
            subject: Email subject line.
            body: Email body. Scanned for an ``http(s)://`` URL which is
                echoed separately for easy copying.
        """
        match = self._URL_RE.search(body)
        link = match.group(0) if match else "(no link found in body)"
        _logger.warning(
            "[ConsoleEmailSender] dev email — SendGrid unconfigured.\n"
            "  To:      %s\n"
            "  Subject: %s\n"
            "  Link:    %s",
            to,
            subject,
            link,
        )


def get_default_sender() -> EmailSender:
    """Return the configured default email backend.

    When ``SENDGRID_API_KEY`` is unset we fall back to
    :class:`ConsoleEmailSender` so local development can exercise the
    magic-link flow without real email delivery. Production deploys set
    the key and get :class:`SendGridEmailSender`. Callers are expected
    to inject their own sender in tests.

    Returns:
        A concrete :class:`EmailSender` implementation.
    """
    settings = get_settings()
    if not settings.sendgrid_api_key:
        return ConsoleEmailSender()
    return SendGridEmailSender()
