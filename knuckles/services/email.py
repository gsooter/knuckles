"""Transactional-email adapter for Knuckles.

Knuckles sends exactly one kind of email in P3 — the magic-link — but
the adapter is factored so future ceremonies (passkey recovery, account
deletion confirmation) can plug in without editing the service layer.

The production backend is SendGrid. Tests substitute an in-process
fake. The :class:`EmailSender` protocol exists to formalize that seam
so the service layer can type-annotate the dependency without a hard
import of :class:`SendGridEmailSender`.
"""

from __future__ import annotations

import logging
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


def get_default_sender() -> EmailSender:
    """Return the configured default email backend.

    Returns:
        A :class:`SendGridEmailSender` instance. Callers are expected
        to inject their own sender in tests.
    """
    return SendGridEmailSender()
