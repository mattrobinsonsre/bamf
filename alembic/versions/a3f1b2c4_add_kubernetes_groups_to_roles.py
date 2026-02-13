"""Add kubernetes_groups to roles table.

Stores Kubernetes group names for K8s API impersonation. When a user
with this role accesses a K8s resource, the agent sets Impersonate-Group
headers using these values.

Revision ID: a3f1b2c4
Revises: 698349c0
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

revision: str = "a3f1b2c4"
down_revision: str | None = "698349c0"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "roles",
        sa.Column("kubernetes_groups", JSONB, nullable=False, server_default="[]"),
    )


def downgrade() -> None:
    op.drop_column("roles", "kubernetes_groups")
