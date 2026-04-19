"""Tests for ``knuckles.core.state_jwt``."""

from __future__ import annotations

import time

import pytest

from knuckles.core.state_jwt import issue_state, verify_state


def test_issue_and_verify_roundtrip() -> None:
    token = issue_state(
        purpose="google_oauth",
        payload={"app_client_id": "greenroom", "nonce": "abc"},
    )
    claims = verify_state(token, purpose="google_oauth")
    assert claims["app_client_id"] == "greenroom"
    assert claims["nonce"] == "abc"
    assert claims["purpose"] == "google_oauth"


def test_verify_rejects_wrong_purpose() -> None:
    token = issue_state(purpose="google_oauth", payload={"nonce": "abc"})
    with pytest.raises(ValueError, match="purpose mismatch"):
        verify_state(token, purpose="apple_oauth")


def test_verify_rejects_expired_state(monkeypatch: pytest.MonkeyPatch) -> None:
    real_time = time.time
    monkeypatch.setattr("knuckles.core.state_jwt.time.time", lambda: real_time() - 600)
    token = issue_state(
        purpose="passkey_register", payload={"challenge": "xyz"}, ttl_seconds=300
    )
    monkeypatch.setattr("knuckles.core.state_jwt.time.time", real_time)

    with pytest.raises(ValueError, match="expired"):
        verify_state(token, purpose="passkey_register")


def test_verify_rejects_garbage_token() -> None:
    with pytest.raises(ValueError, match="invalid"):
        verify_state("not-a-jwt", purpose="google_oauth")
