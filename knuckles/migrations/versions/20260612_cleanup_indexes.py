"""Index ``expires_at`` on the two token tables for cleanup queries.

Revision ID: 20260612_cleanup_indexes
Revises: 20260612_ml_tenant_scope
Create Date: 2026-06-12

The cleanup scripts (``cleanup_magic_links.py``,
``cleanup_refresh_tokens.py``) delete by ``expires_at < cutoff``;
without an index each run is a sequential scan of a table whose whole
problem is unbounded growth. Both indexes are plain b-trees — cheap
to maintain on insert-heavy tables and exactly what a range delete
wants.
"""

from __future__ import annotations

from alembic import op

# revision identifiers, used by Alembic.
revision = "20260612_cleanup_indexes"
down_revision: str | None = "20260612_ml_tenant_scope"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    """Create the ``expires_at`` indexes."""
    op.create_index(
        "ix_magic_link_tokens_expires_at",
        "magic_link_tokens",
        ["expires_at"],
    )
    op.create_index(
        "ix_refresh_tokens_expires_at",
        "refresh_tokens",
        ["expires_at"],
    )


def downgrade() -> None:
    """Drop the ``expires_at`` indexes."""
    op.drop_index("ix_refresh_tokens_expires_at", table_name="refresh_tokens")
    op.drop_index("ix_magic_link_tokens_expires_at", table_name="magic_link_tokens")
