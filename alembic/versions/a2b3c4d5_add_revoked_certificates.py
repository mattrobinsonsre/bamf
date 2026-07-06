"""Add revoked_certificates table (certificate revocation denylist).

Revision ID: a2b3c4d5
Revises: f1a2b3c4
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "a2b3c4d5"
down_revision: str | None = "f1a2b3c4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "revoked_certificates",
        sa.Column("fingerprint", sa.String(64), primary_key=True),
        sa.Column("revoked_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("reason", sa.Text(), nullable=True),
        sa.Column("revoked_by", sa.String(255), nullable=True),
        sa.Column("subject_cn", sa.String(255), nullable=True),
    )


def downgrade() -> None:
    op.drop_table("revoked_certificates")
