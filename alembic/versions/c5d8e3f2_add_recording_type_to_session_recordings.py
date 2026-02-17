"""Add recording_type to session_recordings table.

Supports both terminal recordings (asciicast v2 from ssh-audit) and
database query recordings (JSON from postgres-audit/mysql-audit).

Revision ID: c5d8e3f2
Revises: b7e2d4f1
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "c5d8e3f2"
down_revision: str | None = "b7e2d4f1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "session_recordings",
        sa.Column("recording_type", sa.String(20), nullable=False, server_default="terminal"),
    )


def downgrade() -> None:
    op.drop_column("session_recordings", "recording_type")
