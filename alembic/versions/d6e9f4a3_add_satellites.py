"""Add satellite_tokens and satellites tables.

Supports regional satellite deployments (proxy+bridge clusters) that
register with the central API using join tokens, similar to agent
registration.

Revision ID: d6e9f4a3
Revises: c5d8e3f2
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import UUID

from alembic import op

revision: str = "d6e9f4a3"
down_revision: str | None = "c5d8e3f2"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "satellite_tokens",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("token_hash", sa.String(64), unique=True, nullable=False, index=True),
        sa.Column("name", sa.String(63), nullable=False),
        sa.Column("satellite_name", sa.String(63), nullable=False),
        sa.Column("region", sa.String(255), nullable=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("max_uses", sa.Integer, nullable=True),
        sa.Column("use_count", sa.Integer, nullable=False, server_default="0"),
        sa.Column("is_revoked", sa.Boolean, nullable=False, server_default="false"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("created_by", sa.String(255), nullable=False),
    )

    op.create_table(
        "satellites",
        sa.Column("id", UUID(as_uuid=True), primary_key=True),
        sa.Column("name", sa.String(63), unique=True, nullable=False, index=True),
        sa.Column("region", sa.String(255), nullable=True),
        sa.Column("internal_token_hash", sa.String(64), nullable=False),
        sa.Column("bridge_bootstrap_token_hash", sa.String(64), nullable=False),
        sa.Column("latitude", sa.Float, nullable=True),
        sa.Column("longitude", sa.Float, nullable=True),
        sa.Column("is_active", sa.Boolean, nullable=False, server_default="true"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.func.now()),
    )


def downgrade() -> None:
    op.drop_table("satellites")
    op.drop_table("satellite_tokens")
