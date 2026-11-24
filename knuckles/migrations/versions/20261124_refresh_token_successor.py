"""Record each refresh token's successor so lost rotations can be retried.

Revision ID: 20261124_rt_successor
Revises: 20260612_ml_purpose
Create Date: 2026-11-24

Adds a nullable self-referencing ``replaced_by_id`` to ``refresh_tokens``.
When a client re-presents a rotated token whose successor was never used,
the client never received that response (an app suspended mid-refresh,
a dropped connection); Knuckles retires the successor and rotates again
instead of revoking every session the person has. Existing rows keep
NULL and fall back to the old reuse behaviour.
"""

from __future__ import annotations

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = "20261124_rt_successor"
down_revision: str | None = "20260612_ml_purpose"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    """Add the ``replaced_by_id`` column and its self-referencing FK."""
    op.add_column(
        "refresh_tokens",
        sa.Column("replaced_by_id", sa.Uuid(as_uuid=True), nullable=True),
    )
    op.create_foreign_key(
        "fk_refresh_tokens_replaced_by_id",
        "refresh_tokens",
        "refresh_tokens",
        ["replaced_by_id"],
        ["id"],
        ondelete="SET NULL",
    )


def downgrade() -> None:
    """Drop the FK and the ``replaced_by_id`` column."""
    op.drop_constraint(
        "fk_refresh_tokens_replaced_by_id", "refresh_tokens", type_="foreignkey"
    )
    op.drop_column("refresh_tokens", "replaced_by_id")
