"""Transactional-email adapter for Knuckles.

Knuckles sends exactly one kind of email in P3 — the magic-link — but
the adapter is factored so future ceremonies (passkey recovery, account
deletion confirmation) can plug in without editing the service layer.

The production backend is Resend. Local development (no
``RESEND_API_KEY`` set) falls through to :class:`ConsoleEmailSender`,
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

import requests

from knuckles.core.config import get_settings
from knuckles.core.exceptions import EMAIL_DELIVERY_FAILED, AppError

_logger = logging.getLogger(__name__)

_RESEND_ENDPOINT = "https://api.resend.com/emails"
_RESEND_TIMEOUT_SECONDS = 10


class EmailSender(Protocol):
    """Minimal interface every email backend must implement.

    The service layer depends on this protocol, never on a concrete
    sender class, so tests can hand-roll a drop-in recorder without
    monkeypatching HTTP internals.
    """

    def send(
        self,
        *,
        to: str,
        subject: str,
        body: str,
        from_name: str | None = None,
    ) -> None:
        """Deliver one email.

        Args:
            to: Recipient email address.
            subject: Email subject line.
            body: Email body. Implementations are free to send it as
                either plain text or HTML.
            from_name: Optional display name for the ``From`` header
                (e.g. ``"Greenroom"``). When provided, recipients see
                ``"{from_name} <{sender-email}>"`` in their inbox. The
                configured sender address is used regardless.
        """
        ...


class ResendEmailSender:
    """Production email backend backed by the Resend HTTP API.

    Resend's ``POST /emails`` accepts JSON with ``from``, ``to``,
    ``subject``, and ``html`` fields and returns ``{"id": "..."}`` on
    success. Any non-2xx response — or a network-layer failure — is
    normalized into an :class:`AppError` with code
    ``EMAIL_DELIVERY_FAILED`` so the ceremony layer has a single code
    to handle regardless of transport.
    """

    def send(
        self,
        *,
        to: str,
        subject: str,
        body: str,
        from_name: str | None = None,
    ) -> None:
        """Deliver an email via Resend.

        Args:
            to: Recipient email address.
            subject: Email subject line.
            body: Email body. Sent as HTML so ``<a>`` links render.
            from_name: Optional display name wrapped around the
                configured sender address (e.g. ``Greenroom
                <auth@knuckles.example>``). When omitted, the raw
                sender address is used.

        Raises:
            AppError: With code ``EMAIL_DELIVERY_FAILED`` if Resend
                returns a non-2xx response or the HTTP call raises.
        """
        settings = get_settings()
        sender = settings.resend_from_email
        from_header = f"{from_name} <{sender}>" if from_name else sender
        payload = {
            "from": from_header,
            "to": [to],
            "subject": subject,
            "html": body,
        }
        headers = {
            "Authorization": f"Bearer {settings.resend_api_key}",
            "Content-Type": "application/json",
        }
        try:
            response = requests.post(
                _RESEND_ENDPOINT,
                json=payload,
                headers=headers,
                timeout=_RESEND_TIMEOUT_SECONDS,
            )
        except requests.RequestException as exc:  # pragma: no cover — network path
            _logger.exception("Resend call failed")
            raise AppError(
                code=EMAIL_DELIVERY_FAILED,
                message="Failed to send email.",
                status_code=502,
            ) from exc

        if not (200 <= response.status_code < 300):  # pragma: no cover — network path
            _logger.error(
                "Resend returned status %s: %s",
                response.status_code,
                response.text,
            )
            raise AppError(
                code=EMAIL_DELIVERY_FAILED,
                message="Failed to send email.",
                status_code=502,
            )


class ConsoleEmailSender:
    """Development email backend that logs outgoing mail to stdout.

    Used automatically when ``RESEND_API_KEY`` is empty so local
    magic-link testing does not require a real Resend account. The
    body is scanned for an ``http(s)://…`` URL which is printed on its
    own line to make the sign-in link easy to copy from the terminal.
    """

    _URL_RE = re.compile(r"https?://[^\s\"'<>]+")

    def send(
        self,
        *,
        to: str,
        subject: str,
        body: str,
        from_name: str | None = None,
    ) -> None:
        """Print an email to stdout instead of delivering it.

        Args:
            to: Recipient email address (logged but not used).
            subject: Email subject line.
            body: Email body. Scanned for an ``http(s)://`` URL which is
                echoed separately for easy copying.
            from_name: Optional display name (logged but not otherwise
                used — the console sender has nowhere to put it).
        """
        match = self._URL_RE.search(body)
        link = match.group(0) if match else "(no link found in body)"
        _logger.warning(
            "[ConsoleEmailSender] dev email — Resend unconfigured.\n"
            "  From:    %s\n"
            "  To:      %s\n"
            "  Subject: %s\n"
            "  Link:    %s",
            from_name or "(no display name)",
            to,
            subject,
            link,
        )


def get_default_sender() -> EmailSender:
    """Return the configured default email backend.

    When ``RESEND_API_KEY`` is unset we fall back to
    :class:`ConsoleEmailSender` so local development can exercise the
    magic-link flow without real email delivery. Production deploys set
    the key and get :class:`ResendEmailSender`. Callers are expected
    to inject their own sender in tests.

    Returns:
        A concrete :class:`EmailSender` implementation.
    """
    settings = get_settings()
    if not settings.resend_api_key:
        return ConsoleEmailSender()
    return ResendEmailSender()
