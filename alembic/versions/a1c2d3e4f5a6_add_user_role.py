"""add user role

Revision ID: a1c2d3e4f5a6
Revises: c9200e6b99a4
Create Date: 2026-08-27 00:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a1c2d3e4f5a6"
down_revision: str | Sequence[str] | None = "c9200e6b99a4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "users",
        sa.Column("role", sa.String(), nullable=False, server_default="user"),
    )
    op.add_column(
        "sessions",
        sa.Column("role", sa.String(), nullable=False, server_default="user"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column("sessions", "role")
    op.drop_column("users", "role")
