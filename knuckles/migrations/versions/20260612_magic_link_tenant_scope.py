"""Bind magic-link tokens to their issuing app client.

Revision ID: 20260612_ml_tenant_scope
Revises: 20260511_tenant_config
Create Date: 2026-06-12

Adds a nullable ``app_client_id`` foreign key to ``magic_link_tokens``
so verification can reject a token minted through one tenant being
redeemed through another (Decision #019). Existing rows keep NULL and
verify under the legacy unscoped path until they expire (15-minute
TTL, so the window closes itself).
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "20260612_ml_tenant_scope"
down_revision: str | None = "20260511_tenant_config"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    """Add the ``app_client_id`` column, FK, and index."""
    op.add_column(
        "magic_link_tokens",
        sa.Column("app_client_id", sa.String(64), nullable=True),
    )
    op.create_foreign_key(
        "fk_magic_link_tokens_app_client_id",
        "magic_link_tokens",
        "app_clients",
        ["app_client_id"],
        ["client_id"],
        ondelete="CASCADE",
    )
    op.create_index(
        "ix_magic_link_tokens_app_client_id",
        "magic_link_tokens",
        ["app_client_id"],
    )


def downgrade() -> None:
    """Drop the index, FK, and column added by :func:`upgrade`."""
    op.drop_index(
        "ix_magic_link_tokens_app_client_id",
        table_name="magic_link_tokens",
    )
    op.drop_constraint(
        "fk_magic_link_tokens_app_client_id",
        "magic_link_tokens",
        type_="foreignkey",
    )
    op.drop_column("magic_link_tokens", "app_client_id")
