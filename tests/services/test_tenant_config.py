"""Tests for shared per-tenant config resolution (Decisions #017/#020).

Covers the group resolver's three behaviors — tenant precedence, env
fallback, and partial-group rejection — plus each service's wiring:
Google, Apple, and WebAuthn configs must come from the tenant's own
columns when set and must never silently mix tenant and operator
credentials within one group.
"""

from __future__ import annotations

import json

import pytest
from sqlalchemy.orm import Session

from knuckles.core.exceptions import TENANT_CONFIG_INCOMPLETE, AppError
from knuckles.data.models.auth import AppClient
from knuckles.data.repositories import auth as repo
from knuckles.services import apple_oauth, google_oauth, passkey
from knuckles.services._tenant_config import resolve_tenant_fields


def _make_client(db_session: Session, **columns: str) -> AppClient:
    """Register an app client with optional tenant-config columns.

    Args:
        db_session: Active SQLAlchemy session.
        columns: Tenant-config column values to set on the row.

    Returns:
        The persisted ``AppClient`` row.
    """
    client = repo.create_app_client(
        db_session,
        client_id="tenant-two",
        app_name="Tenant Two",
        client_secret_hash="hash",
        allowed_origins=["https://tenant-two.example"],
    )
    for name, value in columns.items():
        setattr(client, name, value)
    db_session.flush()
    return client


class TestResolveTenantFields:
    """The group resolver itself."""

    def test_full_tenant_group_wins_over_env(self, db_session: Session) -> None:
        """All-set tenant columns shadow the env fallbacks entirely."""
        client = _make_client(
            db_session,
            google_oauth_client_id="tenant-google-id",
            google_oauth_client_secret="tenant-google-secret",
        )
        resolved = resolve_tenant_fields(
            client,
            group="google_oauth",
            fields={
                "google_oauth_client_id": "env-id",
                "google_oauth_client_secret": "env-secret",
            },
        )
        assert resolved == {
            "google_oauth_client_id": "tenant-google-id",
            "google_oauth_client_secret": "tenant-google-secret",
        }

    def test_null_group_falls_back_to_env(self, db_session: Session) -> None:
        """An unconfigured group inherits the operator env values."""
        client = _make_client(db_session)
        resolved = resolve_tenant_fields(
            client,
            group="google_oauth",
            fields={
                "google_oauth_client_id": "env-id",
                "google_oauth_client_secret": "env-secret",
            },
        )
        assert resolved == {
            "google_oauth_client_id": "env-id",
            "google_oauth_client_secret": "env-secret",
        }

    def test_partial_atomic_group_is_rejected(self, db_session: Session) -> None:
        """A half-configured atomic group raises instead of mixing.

        Tenant client id + operator client secret is a guaranteed
        provider-side failure that would otherwise surface as an
        opaque auth error at sign-in time.
        """
        client = _make_client(db_session, google_oauth_client_id="tenant-id")
        with pytest.raises(AppError) as exc:
            resolve_tenant_fields(
                client,
                group="google_oauth",
                fields={
                    "google_oauth_client_id": "env-id",
                    "google_oauth_client_secret": "env-secret",
                },
            )
        assert exc.value.code == TENANT_CONFIG_INCOMPLETE
        assert exc.value.status_code == 500
        assert "google_oauth_client_secret" in exc.value.message

    def test_partial_non_atomic_group_mixes_per_field(
        self, db_session: Session
    ) -> None:
        """Non-atomic groups (Resend) may override field-by-field."""
        client = _make_client(db_session, resend_from_email="auth@tenant.example")
        resolved = resolve_tenant_fields(
            client,
            group="resend",
            fields={
                "resend_api_key": "env-key",
                "resend_from_email": "env@example.com",
            },
            atomic=False,
        )
        assert resolved == {
            "resend_api_key": "env-key",
            "resend_from_email": "auth@tenant.example",
        }

    def test_missing_row_falls_back_to_env(self) -> None:
        """No app-client row at all resolves the full env group."""
        resolved = resolve_tenant_fields(
            None,
            group="google_oauth",
            fields={"google_oauth_client_id": "env-id"},
        )
        assert resolved == {"google_oauth_client_id": "env-id"}

    def test_strict_mode_rejects_env_fallback(
        self, db_session: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """With fallback disabled, NULL columns are a config error.

        This is the enforceable retirement of Decision #017's
        transition mechanism: flip the flag once every tenant row is
        populated and no ceremony can silently run on operator
        credentials again.
        """
        monkeypatch.setenv("KNUCKLES_ALLOW_ENV_TENANT_FALLBACK", "false")
        client = _make_client(db_session)
        with pytest.raises(AppError) as exc:
            resolve_tenant_fields(
                client,
                group="google_oauth",
                fields={"google_oauth_client_id": "env-id"},
            )
        assert exc.value.code == TENANT_CONFIG_INCOMPLETE

    def test_strict_mode_accepts_full_tenant_group(
        self, db_session: Session, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Strict mode passes when the tenant carries the whole group."""
        monkeypatch.setenv("KNUCKLES_ALLOW_ENV_TENANT_FALLBACK", "false")
        client = _make_client(db_session, google_oauth_client_id="tenant-id")
        resolved = resolve_tenant_fields(
            client,
            group="google_oauth",
            fields={"google_oauth_client_id": "env-id"},
        )
        assert resolved == {"google_oauth_client_id": "tenant-id"}


class TestGoogleTenantConfig:
    """Google OAuth service wiring."""

    def test_authorize_url_uses_tenant_client_id(self, db_session: Session) -> None:
        """The consent URL carries the tenant's own Google client id."""
        client = _make_client(
            db_session,
            google_oauth_client_id="tenant-google-id",
            google_oauth_client_secret="tenant-google-secret",
        )
        start = google_oauth.build_authorize_url(
            db_session,
            redirect_uri="https://tenant-two.example/cb",
            app_client_id=client.client_id,
        )
        assert "client_id=tenant-google-id" in start.authorize_url

    def test_partial_google_group_errors_at_start(self, db_session: Session) -> None:
        """Tenant id without tenant secret fails loudly at /start."""
        client = _make_client(db_session, google_oauth_client_id="tenant-id")
        with pytest.raises(AppError) as exc:
            google_oauth.build_authorize_url(
                db_session,
                redirect_uri="https://tenant-two.example/cb",
                app_client_id=client.client_id,
            )
        assert exc.value.code == TENANT_CONFIG_INCOMPLETE


class TestAppleTenantConfig:
    """Apple OAuth service wiring."""

    def test_authorize_url_uses_tenant_client_id(self, db_session: Session) -> None:
        """The consent URL carries the tenant's own Services ID."""
        client = _make_client(
            db_session,
            apple_oauth_client_id="example.tenant.service",
            apple_oauth_team_id="TENANTTEAM",
            apple_oauth_key_id="TENANTKEY1",
            apple_oauth_private_key="tenant-pem",
        )
        start = apple_oauth.build_authorize_url(
            db_session,
            redirect_uri="https://tenant-two.example/cb",
            app_client_id=client.client_id,
        )
        assert "client_id=example.tenant.service" in start.authorize_url

    def test_partial_apple_group_errors_at_start(self, db_session: Session) -> None:
        """A half-configured Apple group fails loudly at /start."""
        client = _make_client(
            db_session, apple_oauth_client_id="example.tenant.service"
        )
        with pytest.raises(AppError) as exc:
            apple_oauth.build_authorize_url(
                db_session,
                redirect_uri="https://tenant-two.example/cb",
                app_client_id=client.client_id,
            )
        assert exc.value.code == TENANT_CONFIG_INCOMPLETE


class TestWebAuthnTenantConfig:
    """Passkey service wiring."""

    def test_register_options_use_tenant_rp(self, db_session: Session) -> None:
        """Registration options carry the tenant's own relying party."""
        client = _make_client(
            db_session,
            webauthn_rp_id="tenant-two.example",
            webauthn_origin="https://tenant-two.example",
        )
        user = repo.create_user(db_session, email="pk@tenant-two.example")
        start = passkey.register_begin(
            db_session,
            user_id=str(user.id),
            app_client_id=client.client_id,
        )
        rendered = json.dumps(start.options)
        assert "tenant-two.example" in rendered

    def test_partial_webauthn_group_errors(self, db_session: Session) -> None:
        """rp_id without origin is rejected before any ceremony."""
        client = _make_client(db_session, webauthn_rp_id="tenant-two.example")
        user = repo.create_user(db_session, email="pk2@tenant-two.example")
        with pytest.raises(AppError) as exc:
            passkey.register_begin(
                db_session,
                user_id=str(user.id),
                app_client_id=client.client_id,
            )
        assert exc.value.code == TENANT_CONFIG_INCOMPLETE

    def test_rp_name_defaults_to_app_name_for_configured_tenant(
        self, db_session: Session
    ) -> None:
        """A tenant with its own RP but no rp_name shows its app name.

        The operator-level WEBAUTHN_RP_NAME must not leak into another
        tenant's passkey prompt.
        """
        client = _make_client(
            db_session,
            webauthn_rp_id="tenant-two.example",
            webauthn_origin="https://tenant-two.example",
        )
        user = repo.create_user(db_session, email="pk3@tenant-two.example")
        start = passkey.register_begin(
            db_session,
            user_id=str(user.id),
            app_client_id=client.client_id,
        )
        assert start.options["rp"]["name"] == "Tenant Two"
