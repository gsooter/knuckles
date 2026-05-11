"""Add per-tenant config columns to ``app_clients``.

Revision ID: 20260511_tenant_config
Revises: 20260419_initial
Create Date: 2026-05-11

Adds nullable columns to ``app_clients`` so each consuming application
can provide its own Resend / Google OAuth / Apple OAuth / WebAuthn
configuration. Secret-bearing columns (``resend_api_key``,
``google_oauth_client_secret``, ``apple_oauth_private_key``) hold
Fernet ciphertext at rest — the symmetric key lives in
``KNUCKLES_SECRETS_KEY`` so a database-only compromise does not
yield the credentials. Non-secret columns hold plaintext.

Every column is NULL-able: a NULL means "inherit from the
Knuckles-operator env var of the same name." This preserves
single-tenant operation while consumers migrate to per-tenant
configuration. See Decision #017.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "20260511_tenant_config"
down_revision: str | None = "20260419_initial"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    """Add per-tenant configuration columns to ``app_clients``.

    Columns are added NULL-able with no server default; existing rows
    pick up ``NULL`` and continue to fall back to the operator-level
    env vars in :mod:`knuckles.core.config`.
    """
    # Resend (transactional email for magic-link).
    op.add_column(
        "app_clients",
        sa.Column("resend_api_key", sa.Text(), nullable=True),
    )
    op.add_column(
        "app_clients",
        sa.Column("resend_from_email", sa.String(320), nullable=True),
    )

    # Google OAuth.
    op.add_column(
        "app_clients",
        sa.Column("google_oauth_client_id", sa.String(200), nullable=True),
    )
    op.add_column(
        "app_clients",
        sa.Column("google_oauth_client_secret", sa.Text(), nullable=True),
    )

    # Apple OAuth (Sign in with Apple).
    op.add_column(
        "app_clients",
        sa.Column("apple_oauth_client_id", sa.String(200), nullable=True),
    )
    op.add_column(
        "app_clients",
        sa.Column("apple_oauth_team_id", sa.String(64), nullable=True),
    )
    op.add_column(
        "app_clients",
        sa.Column("apple_oauth_key_id", sa.String(64), nullable=True),
    )
    op.add_column(
        "app_clients",
        sa.Column("apple_oauth_private_key", sa.Text(), nullable=True),
    )

    # WebAuthn relying-party identity. ``webauthn_rp_id`` is effectively
    # immutable once any passkey has been registered against it — see
    # Decision #017 (open question) and the application-layer guardrail
    # in ``scripts/configure_app_client.py``.
    op.add_column(
        "app_clients",
        sa.Column("webauthn_rp_id", sa.String(253), nullable=True),
    )
    op.add_column(
        "app_clients",
        sa.Column("webauthn_rp_name", sa.String(200), nullable=True),
    )
    op.add_column(
        "app_clients",
        sa.Column("webauthn_origin", sa.String(500), nullable=True),
    )


def downgrade() -> None:
    """Drop the per-tenant configuration columns added by :func:`upgrade`."""
    op.drop_column("app_clients", "webauthn_origin")
    op.drop_column("app_clients", "webauthn_rp_name")
    op.drop_column("app_clients", "webauthn_rp_id")

    op.drop_column("app_clients", "apple_oauth_private_key")
    op.drop_column("app_clients", "apple_oauth_key_id")
    op.drop_column("app_clients", "apple_oauth_team_id")
    op.drop_column("app_clients", "apple_oauth_client_id")

    op.drop_column("app_clients", "google_oauth_client_secret")
    op.drop_column("app_clients", "google_oauth_client_id")

    op.drop_column("app_clients", "resend_from_email")
    op.drop_column("app_clients", "resend_api_key")
