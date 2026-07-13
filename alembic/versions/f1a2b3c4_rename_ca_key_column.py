"""Rename certificate_authority.ca_key_encrypted to ca_key_pem.

The column was named "_encrypted", but the CA private key is stored as plain
PEM with no encryption at rest — by design: the database is the trust root and
a PostgreSQL backup is the DR artifact, protected by DB access controls (and,
optionally, an external CA provider that keeps the key in Vault/cert-manager).
Rename the column so the schema no longer implies encryption that isn't there.

Revision ID: f1a2b3c4
Revises: e7f0a5b4
"""

from collections.abc import Sequence

from alembic import op

revision: str = "f1a2b3c4"
down_revision: str | None = "e7f0a5b4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.alter_column(
        "certificate_authority", "ca_key_encrypted", new_column_name="ca_key_pem"
    )


def downgrade() -> None:
    op.alter_column(
        "certificate_authority", "ca_key_pem", new_column_name="ca_key_encrypted"
    )
