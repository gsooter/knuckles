"""Tag magic-link tokens with the ceremony they belong to.

Revision ID: 20260612_ml_purpose
Revises: 20260612_cleanup_indexes
Create Date: 2026-06-12

Adds ``magic_link_tokens.purpose`` so the email-change ceremony can
reuse the magic-link table without its tokens being redeemable as
sign-ins (and vice versa). Existing rows backfill to ``'sign_in'``
via the server default, which is exactly what they all are.

The column is a plain ``String(32)``, deliberately NOT a native PG
enum: native enums require an ``ALTER TYPE`` migration for every new
member, and a Python-side enum would additionally need the
``values_callable`` pin (CLAUDE.md rule #11) to avoid writing member
names instead of values. A short string column with application-level
validation sidesteps both footguns; the set of purposes is enforced
in :mod:`knuckles.services.magic_link`.
"""

from __future__ import annotations

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = "20260612_ml_purpose"
down_revision: str | None = "20260612_cleanup_indexes"
branch_labels: tuple[str, ...] | None = None
depends_on: tuple[str, ...] | None = None


def upgrade() -> None:
    """Add the ``purpose`` column with a ``'sign_in'`` server default."""
    op.add_column(
        "magic_link_tokens",
        sa.Column(
            "purpose",
            sa.String(32),
            nullable=False,
            server_default="sign_in",
        ),
    )


def downgrade() -> None:
    """Drop the ``purpose`` column added by :func:`upgrade`."""
    op.drop_column("magic_link_tokens", "purpose")
