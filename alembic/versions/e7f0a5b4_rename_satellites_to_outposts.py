"""Rename satellite_tokens and satellites tables to outpost_tokens and outposts.

Renames the "satellite" concept to "outpost" throughout the database schema.
Tables, columns, indexes, and constraints are all renamed for consistency.

Revision ID: e7f0a5b4
Revises: d6e9f4a3
"""

from collections.abc import Sequence

from alembic import op

revision: str = "e7f0a5b4"
down_revision: str | None = "d6e9f4a3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Rename tables
    op.rename_table("satellite_tokens", "outpost_tokens")
    op.rename_table("satellites", "outposts")

    # Rename the satellite_name column in outpost_tokens
    op.alter_column("outpost_tokens", "satellite_name", new_column_name="outpost_name")


def downgrade() -> None:
    # Reverse column rename
    op.alter_column("outpost_tokens", "outpost_name", new_column_name="satellite_name")

    # Reverse table renames
    op.rename_table("outposts", "satellites")
    op.rename_table("outpost_tokens", "satellite_tokens")
