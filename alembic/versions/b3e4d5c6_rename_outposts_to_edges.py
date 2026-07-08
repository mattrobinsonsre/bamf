"""Rename outpost_tokens and outposts tables to edge_tokens and edges.

Renames the regional-relay concept from "outpost" to "edge" throughout the
database schema (#118). Mirrors the earlier satellites→outposts rename,
inverted. Reversible.

Revision ID: b3e4d5c6
Revises: a2b3c4d5
"""

from collections.abc import Sequence

from alembic import op

revision: str = "b3e4d5c6"
down_revision: str | None = "a2b3c4d5"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # Rename tables
    op.rename_table("outpost_tokens", "edge_tokens")
    op.rename_table("outposts", "edges")

    # Rename the outpost_name column in edge_tokens
    op.alter_column("edge_tokens", "outpost_name", new_column_name="edge_name")


def downgrade() -> None:
    # Reverse column rename
    op.alter_column("edge_tokens", "edge_name", new_column_name="outpost_name")

    # Reverse table renames
    op.rename_table("edges", "outposts")
    op.rename_table("edge_tokens", "outpost_tokens")
