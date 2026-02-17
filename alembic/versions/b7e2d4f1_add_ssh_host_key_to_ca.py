"""Add ssh_host_key to certificate_authority table.

Stores a shared SSH host key (Ed25519, PEM-encoded) used by all bridge
pods for ssh-audit session recording. Generated once by the API alongside
the CA, distributed to bridges via the bootstrap response.

Revision ID: b7e2d4f1
Revises: a3f1b2c4
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "b7e2d4f1"
down_revision: str | None = "a3f1b2c4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column(
        "certificate_authority",
        sa.Column("ssh_host_key", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("certificate_authority", "ssh_host_key")
