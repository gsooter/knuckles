"""Tests for ``knuckles doctor`` server and tenant checks."""

from __future__ import annotations

import requests
import responses

from knuckles_cli.api import KnucklesAPI
from knuckles_cli.doctor import Check, check_app, check_server

from .conftest import APP_ORIGIN, BASE_URL, app_row

JWKS = {"keys": [{"kty": "RSA", "kid": "k1", "alg": "RS256", "n": "x", "e": "AQAB"}]}


def _mock_server(
    mocked: responses.RequestsMock,
    *,
    issuer: str = BASE_URL,
    health_status: int = 200,
    jwks: dict[str, object] | None = None,
) -> None:
    """Register the three public discovery endpoints on the mock.

    Args:
        mocked: Active ``responses`` mock.
        issuer: ``issuer`` value the discovery doc reports.
        health_status: HTTP status for ``/health``.
        jwks: JWKS body; defaults to one RS256 key.
    """
    mocked.get(f"{BASE_URL}/health", status=health_status, json={"status": "ok"})
    mocked.get(
        f"{BASE_URL}/.well-known/openid-configuration",
        json={"issuer": issuer, "jwks_uri": f"{issuer}/.well-known/jwks.json"},
    )
    mocked.get(f"{BASE_URL}/.well-known/jwks.json", json=jwks or JWKS)


def _by_name(checks: list[Check]) -> dict[str, Check]:
    """Index checks by name for assertions.

    Args:
        checks: Checks returned by a doctor function.

    Returns:
        Mapping of check name to check.
    """
    return {c.name: c for c in checks}


class TestServerChecks:
    """Checks against the public discovery surface."""

    def test_healthy_server_is_all_ok(self, mocked: responses.RequestsMock) -> None:
        """A correct deployment passes every server check."""
        _mock_server(mocked)
        checks = check_server(KnucklesAPI(BASE_URL))
        assert {c.status for c in checks} == {"ok"}

    def test_issuer_mismatch_fails(self, mocked: responses.RequestsMock) -> None:
        """A trailing-slash issuer breaks every SDK's iss check."""
        _mock_server(mocked, issuer=f"{BASE_URL}/")
        checks = _by_name(check_server(KnucklesAPI(BASE_URL)))
        assert checks["issuer"].status == "fail"
        assert "KNUCKLES_BASE_URL" in checks["issuer"].detail

    def test_degraded_health_fails(self, mocked: responses.RequestsMock) -> None:
        """A 503 health check (database down) fails."""
        _mock_server(mocked, health_status=503)
        assert _by_name(check_server(KnucklesAPI(BASE_URL)))["health"].status == "fail"

    def test_empty_jwks_fails(self, mocked: responses.RequestsMock) -> None:
        """No signing keys means no token can be verified."""
        _mock_server(mocked, jwks={"keys": []})
        assert _by_name(check_server(KnucklesAPI(BASE_URL)))["jwks"].status == "fail"

    def test_unreachable_server_fails_once(
        self, mocked: responses.RequestsMock
    ) -> None:
        """A dead host yields a single failing reachability check."""
        mocked.get(f"{BASE_URL}/health", body=requests.ConnectionError("refused"))
        checks = check_server(KnucklesAPI(BASE_URL))
        assert [c.status for c in checks] == ["fail"]

    def test_plain_http_warns(self, mocked: responses.RequestsMock) -> None:
        """A non-localhost http:// URL leaks tokens; warn about it."""
        url = "http://auth.example.com"
        mocked.get(f"{url}/health", json={"status": "ok"})
        mocked.get(
            f"{url}/.well-known/openid-configuration",
            json={"issuer": url, "jwks_uri": f"{url}/.well-known/jwks.json"},
        )
        mocked.get(f"{url}/.well-known/jwks.json", json=JWKS)
        assert _by_name(check_server(KnucklesAPI(url)))["https"].status == "warn"


class TestAppChecks:
    """Checks over one redacted tenant row."""

    def test_fully_configured_app_is_ok(self) -> None:
        """Every group complete and consistent passes."""
        row = app_row(
            resend_from_email="Site <hi@example.com>",
            resend_api_key_configured=True,
            google_oauth_client_id="g",
            google_oauth_client_secret_configured=True,
            apple_oauth_client_id="com.example.web",
            apple_oauth_team_id="AB12CD34EF",
            apple_oauth_key_id="ABCDE12345",
            apple_oauth_private_key_configured=True,
            webauthn_rp_id="app.example.com",
            webauthn_rp_name="Site",
            webauthn_origin=APP_ORIGIN,
        )
        assert {c.status for c in check_app(row)} == {"ok"}

    def test_empty_groups_warn(self) -> None:
        """Unconfigured groups inherit env fallback or are off: warn."""
        checks = _by_name(check_app(app_row()))
        assert checks["my-site: google"].status == "warn"
        assert checks["my-site: passkey"].status == "warn"

    def test_partial_atomic_group_fails(self) -> None:
        """Half a Google group raises TENANT_CONFIG_INCOMPLETE at sign-in."""
        checks = _by_name(check_app(app_row(google_oauth_client_id="g")))
        google = checks["my-site: google"]
        assert google.status == "fail"
        assert "google_oauth_client_secret" in google.detail

    def test_partial_email_group_warns(self) -> None:
        """Email is non-atomic: a missing piece inherits from env."""
        checks = _by_name(check_app(app_row(resend_from_email="hi@example.com")))
        assert checks["my-site: email"].status == "warn"

    def test_no_origins_fails(self) -> None:
        """No allowed origins means every redirect_url is rejected."""
        checks = _by_name(check_app(app_row(allowed_origins=[])))
        assert checks["my-site: origins"].status == "fail"

    def test_insecure_origin_warns(self) -> None:
        """A plain-http non-localhost origin is flagged."""
        checks = _by_name(check_app(app_row(allowed_origins=["http://example.com"])))
        assert checks["my-site: origins"].status == "warn"

    def test_passkey_rp_id_mismatch_fails(self) -> None:
        """An origin outside the rp_id fails every passkey ceremony."""
        row = app_row(
            webauthn_rp_id="other.com",
            webauthn_rp_name="Site",
            webauthn_origin=APP_ORIGIN,
        )
        assert _by_name(check_app(row))["my-site: passkey"].status == "fail"

    def test_passkey_origin_not_allowed_warns(self) -> None:
        """A passkey origin missing from allowed_origins is suspicious."""
        row = app_row(
            webauthn_rp_id="example.com",
            webauthn_rp_name="Site",
            webauthn_origin="https://other.example.com",
        )
        assert _by_name(check_app(row))["my-site: passkey"].status == "warn"
