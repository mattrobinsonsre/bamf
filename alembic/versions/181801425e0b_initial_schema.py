"""Initial schema

Revision ID: 181801425e0b
Revises: -
Create Date: 2026-02-03

Creates all tables matching the current SQLAlchemy models.
"""

from collections.abc import Sequence

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

revision: str = "181801425e0b"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    # ── users ─────────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("email", sa.String(255), primary_key=True),
        sa.Column("display_name", sa.String(255), nullable=True),
        sa.Column("password_hash", sa.String(255), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("true")),
        sa.Column("is_sso_only", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column("last_login_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    # ── roles (custom only — built-ins are in code) ───────────────────────
    op.create_table(
        "roles",
        sa.Column("name", sa.String(63), primary_key=True),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column(
            "allow_labels",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column(
            "allow_names", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")
        ),
        sa.Column(
            "deny_labels", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        sa.Column(
            "deny_names", postgresql.JSONB(), nullable=False, server_default=sa.text("'[]'::jsonb")
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )

    # ── role_assignments (custom roles, FK to roles.name) ─────────────────
    op.create_table(
        "role_assignments",
        sa.Column("provider_name", sa.String(63), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column(
            "role_name",
            sa.String(63),
            sa.ForeignKey("roles.name", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("provider_name", "email", "role_name"),
    )

    # ── platform_role_assignments (admin/audit, no FK) ────────────────────
    op.create_table(
        "platform_role_assignments",
        sa.Column("provider_name", sa.String(63), nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("role_name", sa.String(63), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.PrimaryKeyConstraint("provider_name", "email", "role_name"),
    )

    # ── agents ────────────────────────────────────────────────────────────
    op.create_table(
        "agents",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("name", sa.String(63), unique=True, nullable=False),
        sa.Column("certificate_fingerprint", sa.String(64), nullable=True),
        sa.Column("certificate_expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
    )
    op.create_index("ix_agents_name", "agents", ["name"])

    # ── join_tokens ───────────────────────────────────────────────────────
    op.create_table(
        "join_tokens",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("token_hash", sa.String(64), unique=True, nullable=False),
        sa.Column("name", sa.String(63), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("max_uses", sa.Integer(), nullable=True),
        sa.Column("use_count", sa.Integer(), nullable=False, server_default=sa.text("0")),
        sa.Column(
            "agent_labels",
            postgresql.JSONB(),
            nullable=False,
            server_default=sa.text("'{}'::jsonb"),
        ),
        sa.Column("is_revoked", sa.Boolean(), nullable=False, server_default=sa.text("false")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("created_by", sa.String(255), nullable=False),
    )
    op.create_index("ix_join_tokens_token_hash", "join_tokens", ["token_hash"])

    # ── audit_logs ────────────────────────────────────────────────────────
    op.create_table(
        "audit_logs",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column(
            "timestamp",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.Column("event_type", sa.String(50), nullable=False),
        sa.Column("action", sa.String(50), nullable=False),
        sa.Column("actor_type", sa.String(20), nullable=False),
        sa.Column("actor_id", sa.String(255), nullable=True),
        sa.Column("actor_ip", sa.String(45), nullable=True),
        sa.Column("actor_user_agent", sa.String(500), nullable=True),
        sa.Column("target_type", sa.String(50), nullable=True),
        sa.Column("target_id", sa.String(255), nullable=True),
        sa.Column("request_id", sa.String(36), nullable=True),
        sa.Column(
            "details", postgresql.JSONB(), nullable=False, server_default=sa.text("'{}'::jsonb")
        ),
        sa.Column("success", sa.Boolean(), nullable=False),
        sa.Column("error_message", sa.Text(), nullable=True),
    )
    op.create_index("ix_audit_logs_timestamp", "audit_logs", ["timestamp"])
    op.create_index("ix_audit_logs_event_type", "audit_logs", ["event_type"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_logs_request_id", "audit_logs", ["request_id"])
    op.create_index("ix_audit_logs_timestamp_event", "audit_logs", ["timestamp", "event_type"])
    op.create_index("ix_audit_logs_actor", "audit_logs", ["actor_type", "actor_id"])

    # ── session_recordings ────────────────────────────────────────────────
    op.create_table(
        "session_recordings",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            primary_key=True,
            server_default=sa.text("gen_random_uuid()"),
        ),
        sa.Column("session_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("user_email", sa.String(255), nullable=False),
        sa.Column("resource_name", sa.String(63), nullable=False),
        sa.Column("recording_data", sa.Text(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("ended_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_session_recordings_session_id", "session_recordings", ["session_id"])
    op.create_index("ix_session_recordings_started_at", "session_recordings", ["started_at"])

    # ── certificate_authority ─────────────────────────────────────────────
    op.create_table(
        "certificate_authority",
        sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
        sa.Column("ca_cert", sa.Text(), nullable=False),
        sa.Column("ca_key_encrypted", sa.Text(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.func.now(),
        ),
        sa.UniqueConstraint("id"),
    )


def downgrade() -> None:
    op.drop_table("certificate_authority")
    op.drop_table("session_recordings")
    op.drop_table("audit_logs")
    op.drop_table("join_tokens")
    op.drop_table("agents")
    op.drop_table("platform_role_assignments")
    op.drop_table("role_assignments")
    op.drop_table("roles")
    op.drop_table("users")
