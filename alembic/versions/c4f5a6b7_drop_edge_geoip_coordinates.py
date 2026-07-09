"""Drop the unused edges.latitude / edges.longitude GeoIP columns.

GeoIP-based nearest-edge selection was a dead path — nothing ever populated
these coordinates — and has been abandoned in favour of measured-latency edge
selection (#244, part of the edge flagship #119). This drops the columns.
Reversible: downgrade re-adds them as nullable floats.

Revision ID: c4f5a6b7
Revises: b3e4d5c6
"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "c4f5a6b7"
down_revision: str | None = "b3e4d5c6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_column("edges", "longitude")
    op.drop_column("edges", "latitude")


def downgrade() -> None:
    op.add_column("edges", sa.Column("latitude", sa.Float(), nullable=True))
    op.add_column("edges", sa.Column("longitude", sa.Float(), nullable=True))
