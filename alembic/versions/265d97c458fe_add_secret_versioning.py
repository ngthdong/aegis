"""add secret versioning

Revision ID: 265d97c458fe
Revises: 3230ff9049b6
Create Date: 2026-07-31 01:30:48.886607

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "265d97c458fe"
down_revision: str | Sequence[str] | None = "3230ff9049b6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "secrets",
        sa.Column(
            "current_version",
            sa.Integer(),
            nullable=False,
            server_default=None,
        ),
    )

    op.create_table(
        "secret_versions",
        sa.Column("id", sa.String(), nullable=False),
        sa.Column("secret_id", sa.String(), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
        sa.Column("created_at", sa.String(), nullable=False),
        sa.CheckConstraint(
            "version >= 1",
            name="ck_secret_versions_version_positive",
        ),
        sa.ForeignKeyConstraint(
            ["secret_id"],
            ["secrets.id"],
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint(
            "secret_id",
            "version",
            name="uq_secret_versions_secret_id_version",
        ),
    )
    op.create_index(
        op.f("ix_secret_versions_secret_id"),
        "secret_versions",
        ["secret_id"],
        unique=False,
    )
    op.drop_column("secrets", "nonce")
    op.drop_column("secrets", "ciphertext")


def downgrade() -> None:
    op.add_column(
        "secrets",
        sa.Column("nonce", sa.LargeBinary(), nullable=False),
    )
    op.add_column(
        "secrets",
        sa.Column("ciphertext", sa.LargeBinary(), nullable=False),
    )

    op.drop_index(
        op.f("ix_secret_versions_secret_id"),
        table_name="secret_versions",
    )
    op.drop_table("secret_versions")

    op.drop_column("secrets", "current_version")
