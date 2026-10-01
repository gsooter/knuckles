"""Tests for the ``From`` header :class:`ResendEmailSender` builds.

Tenants store their sender as ``Name <address>`` (the documented shape
of ``app_clients.resend_from_email``), while the operator default is a
bare address. The sender used to wrap *every* value in
``"{app name} <...>"``, so a tenant value became
``Greenroom <Greenroom <signin@greenroom.live>>`` — malformed, rejected
by Resend, and the reason per-tenant senders never worked.
"""

from __future__ import annotations

from typing import Any

import pytest

from knuckles.services import email as email_mod


class _Response:
    """Minimal stand-in for a successful ``requests`` response."""

    status_code = 200
    text = '{"id": "test"}'


@pytest.fixture
def sent(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    """Capture Resend payloads instead of calling the network.

    Args:
        monkeypatch: pytest helper.

    Returns:
        The list each outgoing JSON payload is appended to.
    """
    payloads: list[dict[str, Any]] = []

    def fake_post(url: str, *, json: dict[str, Any], **_: Any) -> _Response:
        payloads.append(json)
        return _Response()

    monkeypatch.setattr(email_mod.requests, "post", fake_post)
    return payloads


def _send(from_address: str, from_name: str | None) -> None:
    """Send one email through a sender with the given From config.

    Args:
        from_address: The configured sender (bare or ``Name <addr>``).
        from_name: Display name the ceremony passes (the app name).
    """
    sender = email_mod.ResendEmailSender(api_key="re_test", from_address=from_address)
    sender.send(to="a@example.com", subject="s", body="b", from_name=from_name)


def test_bare_address_is_wrapped_in_the_app_name(sent: list[dict[str, Any]]) -> None:
    """The operator default stays as before: ``App <bare address>``."""
    _send("auth@knuckles.example.com", "Greenroom")
    assert sent[0]["from"] == "Greenroom <auth@knuckles.example.com>"


def test_tenant_name_and_address_is_used_as_is(sent: list[dict[str, Any]]) -> None:
    """Regression: a ``Name <addr>`` tenant value is not double-wrapped."""
    _send("Greenroom <signin@greenroom.live>", "Greenroom")
    assert sent[0]["from"] == "Greenroom <signin@greenroom.live>"


def test_no_display_name_sends_the_address_alone(sent: list[dict[str, Any]]) -> None:
    """Without an app name the configured value goes out untouched."""
    _send("signin@greenroom.live", None)
    assert sent[0]["from"] == "signin@greenroom.live"
