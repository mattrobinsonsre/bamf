"""Drop users.is_sso_only column.

SSO users are distinguished by having no password_hash, not by a separate flag.
The is_sso_only column was redundant — local auth already rejects users without
a password hash.

Revision ID: 698349c0
Revises: 181801425e0b
"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

revision: str = "698349c0"
down_revision: str | None = "181801425e0b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.drop_column("users", "is_sso_only")


def downgrade() -> None:
    op.add_column(
        "users",
        sa.Column("is_sso_only", sa.Boolean(), nullable=False, server_default=sa.text("false")),
    )
