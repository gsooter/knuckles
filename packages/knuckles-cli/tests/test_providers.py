"""Tests for local provider-credential parsing and validation."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import responses

from knuckles_cli.errors import CliError
from knuckles_cli.providers import (
    RESEND_DOMAINS_URL,
    apple_key_id_from_filename,
    check_resend_domain,
    email_address_of,
    parse_google_client_secret,
    passkey_config,
    validate_apple_identifier,
    validate_apple_private_key,
)


class TestGoogleClientSecret:
    """Parsing Google Cloud's downloaded OAuth client JSON."""

    def test_parses_web_client(self, google_json: Path) -> None:
        """A web client yields id, secret, and redirect origins."""
        creds = parse_google_client_secret(google_json.read_text())
        assert creds.client_id == "123.apps.googleusercontent.com"
        assert creds.client_secret == "GOCSPX-test"
        assert creds.redirect_origins == ["https://app.example.com"]

    def test_rejects_desktop_client(self) -> None:
        """An ``installed`` (desktop) client cannot do web redirects."""
        text = json.dumps({"installed": {"client_id": "x", "client_secret": "y"}})
        with pytest.raises(CliError) as exc:
            parse_google_client_secret(text)
        assert "Web application" in exc.value.message

    def test_rejects_non_json(self) -> None:
        """Garbage input fails with INVALID_INPUT."""
        with pytest.raises(CliError) as exc:
            parse_google_client_secret("not json")
        assert exc.value.code == "INVALID_INPUT"

    def test_rejects_missing_secret(self) -> None:
        """A web block without a secret is rejected."""
        text = json.dumps({"web": {"client_id": "x"}})
        with pytest.raises(CliError):
            parse_google_client_secret(text)


class TestApple:
    """Apple Sign-in key and identifier validation."""

    def test_accepts_p256_key(self, apple_p8: Path) -> None:
        """A P-256 PKCS#8 key passes."""
        validate_apple_private_key(apple_p8.read_text())

    def test_rejects_rsa_key(self, rsa_pem: str) -> None:
        """An RSA key is the wrong type for Apple's ES256 client secret."""
        with pytest.raises(CliError) as exc:
            validate_apple_private_key(rsa_pem)
        assert "P-256" in exc.value.message

    def test_rejects_garbage(self) -> None:
        """Non-PEM text is rejected."""
        with pytest.raises(CliError):
            validate_apple_private_key("hello")

    def test_key_id_from_filename(self) -> None:
        """Apple's ``AuthKey_<KEYID>.p8`` filename carries the key id."""
        assert apple_key_id_from_filename("/x/AuthKey_ABCDE12345.p8") == "ABCDE12345"
        assert apple_key_id_from_filename("/x/key.p8") is None

    def test_identifier_shape(self) -> None:
        """Team and key ids are ten uppercase alphanumerics."""
        assert validate_apple_identifier("ab12cd34ef", "team_id") == "AB12CD34EF"
        with pytest.raises(CliError):
            validate_apple_identifier("short", "team_id")


class TestPasskeyConfig:
    """WebAuthn relying-party derivation."""

    def test_defaults_rp_id_to_origin_host(self) -> None:
        """Without --rp-id the origin's host is the rp_id."""
        fields = passkey_config(origin="https://app.example.com/", rp_name="My Site")
        assert fields == {
            "webauthn_origin": "https://app.example.com",
            "webauthn_rp_id": "app.example.com",
            "webauthn_rp_name": "My Site",
        }

    def test_accepts_parent_domain_rp_id(self) -> None:
        """A registrable parent domain is a valid rp_id."""
        fields = passkey_config(
            origin="https://app.example.com", rp_id="example.com", rp_name="X"
        )
        assert fields["webauthn_rp_id"] == "example.com"

    def test_rejects_unrelated_rp_id(self) -> None:
        """An rp_id the origin is not under fails every ceremony."""
        with pytest.raises(CliError) as exc:
            passkey_config(
                origin="https://app.example.com", rp_id="other.com", rp_name="X"
            )
        assert "other.com" in exc.value.message

    def test_rejects_http_non_localhost(self) -> None:
        """WebAuthn requires a secure context outside localhost."""
        with pytest.raises(CliError):
            passkey_config(origin="http://app.example.com", rp_name="X")

    def test_allows_http_localhost(self) -> None:
        """Local development on http://localhost is a secure context."""
        fields = passkey_config(origin="http://localhost:3000", rp_name="X")
        assert fields["webauthn_rp_id"] == "localhost"


class TestEmail:
    """From-address parsing and Resend domain verification."""

    def test_address_of_display_form(self) -> None:
        """``Name <addr>`` yields the bare address."""
        assert (
            email_address_of("My Site <hi@mail.example.com>") == "hi@mail.example.com"
        )
        assert email_address_of("hi@example.com") == "hi@example.com"

    def test_address_rejects_garbage(self) -> None:
        """A value with no address fails."""
        with pytest.raises(CliError):
            email_address_of("My Site")

    def test_verified_domain_is_ok(self, mocked: responses.RequestsMock) -> None:
        """A verified sending domain reports ok."""
        mocked.get(
            RESEND_DOMAINS_URL,
            json={"data": [{"name": "mail.example.com", "status": "verified"}]},
        )
        status, _ = check_resend_domain("re_key", "mail.example.com")
        assert status == "ok"
        assert mocked.calls[0].request.headers["Authorization"] == "Bearer re_key"

    def test_unverified_domain_fails(self, mocked: responses.RequestsMock) -> None:
        """A pending domain fails with its status in the detail."""
        mocked.get(
            RESEND_DOMAINS_URL,
            json={"data": [{"name": "mail.example.com", "status": "pending"}]},
        )
        status, detail = check_resend_domain("re_key", "mail.example.com")
        assert status == "fail"
        assert "pending" in detail

    def test_missing_domain_fails(self, mocked: responses.RequestsMock) -> None:
        """A domain not added to Resend at all fails."""
        mocked.get(RESEND_DOMAINS_URL, json={"data": []})
        status, _ = check_resend_domain("re_key", "mail.example.com")
        assert status == "fail"

    def test_sending_only_key_warns(self, mocked: responses.RequestsMock) -> None:
        """A restricted key can't list domains; that is a warning."""
        mocked.get(
            RESEND_DOMAINS_URL,
            status=401,
            json={
                "name": "restricted_api_key",
                "message": "This API key is restricted to only send emails",
            },
        )
        status, _ = check_resend_domain("re_key", "mail.example.com")
        assert status == "warn"

    def test_invalid_key_fails(self, mocked: responses.RequestsMock) -> None:
        """A key Resend rejects outright fails."""
        mocked.get(
            RESEND_DOMAINS_URL,
            status=403,
            json={"name": "invalid_api_key", "message": "API key is invalid"},
        )
        status, _ = check_resend_domain("re_key", "mail.example.com")
        assert status == "fail"
