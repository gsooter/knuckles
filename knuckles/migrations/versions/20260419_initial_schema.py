"""Create the initial Knuckles schema.

Revision ID: 20260419_initial
Revises:
Create Date: 2026-04-19

Establishes every table Knuckles owns — ``users``,
``user_oauth_providers``, ``magic_link_tokens``,
``passkey_credentials``, ``app_clients``, and ``refresh_tokens``.
The ``knuckles_oauth_provider`` enum is explicitly restricted to
``google`` and ``apple`` per Decision #001.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "20260419_initial"
down_revision: str | None = None
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    """Create every Knuckles-owned table."""
    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("display_name", sa.String(200), nullable=True),
        sa.Column("avatar_url", sa.String(500), nullable=True),
        sa.Column(
            "is_active",
            sa.Boolean(),
            nullable=False,
            server_default=sa.text("TRUE"),
        ),
        sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )
    op.create_index("ix_users_email", "users", ["email"])

    provider_enum = sa.Enum(
        "google",
        "apple",
        name="knuckles_oauth_provider",
    )
    provider_enum.create(op.get_bind(), checkfirst=True)

    op.create_table(
        "user_oauth_providers",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("provider", provider_enum, nullable=False),
        sa.Column("provider_user_id", sa.String(200), nullable=False),
        sa.Column("access_token", sa.Text(), nullable=True),
        sa.Column("refresh_token", sa.Text(), nullable=True),
        sa.Column("token_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scopes", sa.Text(), nullable=True),
        sa.Column("raw_profile", sa.JSON(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            ondelete="CASCADE",
        ),
    )
    op.create_index(
        "ix_user_oauth_providers_user_id",
        "user_oauth_providers",
        ["user_id"],
    )
    op.create_index(
        "ix_user_oauth_providers_provider_user_id",
        "user_oauth_providers",
        ["provider_user_id"],
    )

    op.create_table(
        "magic_link_tokens",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("email", sa.String(320), nullable=False),
        sa.Column("token_hash", sa.String(128), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("token_hash", name="uq_magic_link_tokens_token_hash"),
    )
    op.create_index(
        "ix_magic_link_tokens_email",
        "magic_link_tokens",
        ["email"],
    )
    op.create_index(
        "ix_magic_link_tokens_token_hash",
        "magic_link_tokens",
        ["token_hash"],
    )
    op.create_index(
        "ix_magic_link_tokens_user_id",
        "magic_link_tokens",
        ["user_id"],
    )

    op.create_table(
        "passkey_credentials",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("credential_id", sa.Text(), nullable=False),
        sa.Column("public_key", sa.Text(), nullable=False),
        sa.Column(
            "sign_count",
            sa.BigInteger(),
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("transports", sa.String(200), nullable=True),
        sa.Column("name", sa.String(200), nullable=True),
        sa.Column("last_used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint(
            "credential_id",
            name="uq_passkey_credentials_credential_id",
        ),
    )
    op.create_index(
        "ix_passkey_credentials_user_id",
        "passkey_credentials",
        ["user_id"],
    )
    op.create_index(
        "ix_passkey_credentials_credential_id",
        "passkey_credentials",
        ["credential_id"],
    )

    op.create_table(
        "app_clients",
        sa.Column("client_id", sa.String(64), primary_key=True, nullable=False),
        sa.Column("app_name", sa.String(200), nullable=False),
        sa.Column("client_secret_hash", sa.String(128), nullable=False),
        sa.Column("allowed_origins", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("app_name", name="uq_app_clients_app_name"),
    )

    op.create_table(
        "refresh_tokens",
        sa.Column("id", sa.Uuid(as_uuid=True), primary_key=True, nullable=False),
        sa.Column("user_id", sa.Uuid(as_uuid=True), nullable=False),
        sa.Column("app_client_id", sa.String(64), nullable=False),
        sa.Column("token_hash", sa.String(128), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            ondelete="CASCADE",
        ),
        sa.ForeignKeyConstraint(
            ["app_client_id"],
            ["app_clients.client_id"],
            ondelete="CASCADE",
        ),
        sa.UniqueConstraint("token_hash", name="uq_refresh_tokens_token_hash"),
    )
    op.create_index("ix_refresh_tokens_user_id", "refresh_tokens", ["user_id"])
    op.create_index(
        "ix_refresh_tokens_app_client_id",
        "refresh_tokens",
        ["app_client_id"],
    )
    op.create_index(
        "ix_refresh_tokens_token_hash",
        "refresh_tokens",
        ["token_hash"],
    )


def downgrade() -> None:
    """Drop every table created by :func:`upgrade`."""
    op.drop_index("ix_refresh_tokens_token_hash", table_name="refresh_tokens")
    op.drop_index(
        "ix_refresh_tokens_app_client_id",
        table_name="refresh_tokens",
    )
    op.drop_index("ix_refresh_tokens_user_id", table_name="refresh_tokens")
    op.drop_table("refresh_tokens")

    op.drop_table("app_clients")

    op.drop_index(
        "ix_passkey_credentials_credential_id",
        table_name="passkey_credentials",
    )
    op.drop_index(
        "ix_passkey_credentials_user_id",
        table_name="passkey_credentials",
    )
    op.drop_table("passkey_credentials")

    op.drop_index(
        "ix_magic_link_tokens_user_id",
        table_name="magic_link_tokens",
    )
    op.drop_index(
        "ix_magic_link_tokens_token_hash",
        table_name="magic_link_tokens",
    )
    op.drop_index(
        "ix_magic_link_tokens_email",
        table_name="magic_link_tokens",
    )
    op.drop_table("magic_link_tokens")

    op.drop_index(
        "ix_user_oauth_providers_provider_user_id",
        table_name="user_oauth_providers",
    )
    op.drop_index(
        "ix_user_oauth_providers_user_id",
        table_name="user_oauth_providers",
    )
    op.drop_table("user_oauth_providers")

    sa.Enum(name="knuckles_oauth_provider").drop(op.get_bind(), checkfirst=True)

    op.drop_index("ix_users_email", table_name="users")
    op.drop_table("users")
