"""
SQLAlchemy database models for BAMF.

All models use:
- UUIDv7 primary keys (time-sortable), except users (email PK)
- snake_case column names
- Plural table names
- TIMESTAMPTZ with UTC for all timestamps
- Hard deletes (no soft delete columns)
"""

import uuid
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


def generate_uuid7() -> uuid.UUID:
    """Generate a UUIDv7 (time-sortable UUID)."""
    # UUIDv7: timestamp in first 48 bits, version in bits 48-51, random in rest
    import time

    timestamp_ms = int(time.time() * 1000)
    rand_bytes = uuid.uuid4().bytes[6:]

    # Construct UUIDv7
    uuid_bytes = (
        timestamp_ms.to_bytes(6, "big")
        + bytes([0x70 | (rand_bytes[0] & 0x0F)])  # Version 7
        + bytes([0x80 | (rand_bytes[1] & 0x3F)])  # Variant
        + rand_bytes[2:]
    )
    return uuid.UUID(bytes=uuid_bytes)


def utc_now() -> datetime:
    """Get current UTC datetime."""
    return datetime.now(UTC)


class Base(DeclarativeBase):
    """Base class for all models."""

    type_annotation_map = {
        dict[str, Any]: JSONB,
    }


class User(Base):
    """User account model.

    PK is email (natural key). Users are identified by email across all
    authentication providers. No UUID — email is the identity.
    Permissions live on roles, not on individual users.
    """

    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(255), primary_key=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    password_hash: Mapped[str | None] = mapped_column(String(255), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )


class Role(Base):
    """Custom role model for RBAC.

    Only admin-created roles live here. Built-in roles (admin, audit,
    everyone) are defined in bamf.auth.builtin_roles — not in the database.
    """

    __tablename__ = "roles"

    name: Mapped[str] = mapped_column(String(63), primary_key=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Permissions
    allow_labels: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    allow_names: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)
    deny_labels: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)
    deny_names: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)

    # Kubernetes groups for K8s impersonation (e.g., ["system:masters", "developers"])
    kubernetes_groups: Mapped[list[str]] = mapped_column(JSONB, default=list, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )


class RoleAssignment(Base):
    """Maps (provider, email) pairs to custom role names.

    FK to roles.name ensures only valid custom roles can be assigned.
    Platform roles (admin, audit) go in platform_role_assignments instead.

    This enables pre-provisioning: an admin can assign roles to an email
    before the user's first login. Provider-specific: "local" for internal
    assignments, or an SSO provider name for provider-scoped grants.
    """

    __tablename__ = "role_assignments"

    provider_name: Mapped[str] = mapped_column(String(63), primary_key=True)
    email: Mapped[str] = mapped_column(String(255), primary_key=True)
    role_name: Mapped[str] = mapped_column(
        String(63), ForeignKey("roles.name", ondelete="CASCADE"), primary_key=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )


class PlatformRoleAssignment(Base):
    """Admin and audit role assignments.

    Separate from role_assignments (which has FK to custom roles) because
    admin and audit are built-in platform roles with no row in the roles table.
    Same (provider_name, email) key pattern as role_assignments.
    """

    __tablename__ = "platform_role_assignments"

    provider_name: Mapped[str] = mapped_column(String(63), primary_key=True)
    email: Mapped[str] = mapped_column(String(255), primary_key=True)
    role_name: Mapped[str] = mapped_column(String(63), primary_key=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )


class Agent(Base):
    """Agent durable identity.

    Stores what the agent *is* (name, certificate). Runtime state
    (online/offline, last heartbeat, connected bridge, labels, resources)
    lives in Redis. See State Storage section in CLAUDE.md.
    """

    __tablename__ = "agents"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=generate_uuid7
    )
    name: Mapped[str] = mapped_column(String(63), unique=True, nullable=False, index=True)

    # Certificate info
    certificate_fingerprint: Mapped[str | None] = mapped_column(String(64), nullable=True)
    certificate_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )


class JoinToken(Base):
    """Join token for agent registration."""

    __tablename__ = "join_tokens"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=generate_uuid7
    )
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    name: Mapped[str] = mapped_column(String(63), nullable=False)

    # Limits
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    max_uses: Mapped[int | None] = mapped_column(Integer, nullable=True)  # None = unlimited
    use_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Labels to apply to agents using this token
    agent_labels: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    is_revoked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    created_by: Mapped[str] = mapped_column(String(255), nullable=False)  # email of creator


# No Bridge model — bridge state is ephemeral and lives entirely in Redis.
# See State Storage section in CLAUDE.md.


class AuditLog(Base):
    """Audit log for security events and admin actions."""

    __tablename__ = "audit_logs"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=generate_uuid7
    )
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False, index=True
    )

    # Event classification
    event_type: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # 'auth', 'access', 'admin'
    action: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )  # 'login', 'logout', 'access_granted', etc.

    # Actor
    actor_type: Mapped[str] = mapped_column(String(20), nullable=False)  # 'user', 'agent', 'system'
    actor_id: Mapped[str | None] = mapped_column(
        String(255), nullable=True
    )  # user email or agent name
    actor_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    actor_user_agent: Mapped[str | None] = mapped_column(String(500), nullable=True)

    # Target
    target_type: Mapped[str | None] = mapped_column(
        String(50), nullable=True
    )  # 'user', 'role', 'resource', etc.
    target_id: Mapped[str | None] = mapped_column(String(255), nullable=True)

    # Request context
    request_id: Mapped[str | None] = mapped_column(String(36), nullable=True, index=True)

    # Additional details
    details: Mapped[dict[str, Any]] = mapped_column(JSONB, default=dict, nullable=False)

    # Result
    success: Mapped[bool] = mapped_column(Boolean, nullable=False)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_audit_logs_timestamp_event", "timestamp", "event_type"),
        Index("ix_audit_logs_actor", "actor_type", "actor_id"),
    )


class SessionRecording(Base):
    """SSH session recording in asciicast v2 format.

    Stored by the bridge after an ssh-audit session completes.
    The recording_data field contains the full asciicast v2 JSON-lines content.
    """

    __tablename__ = "session_recordings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=generate_uuid7
    )
    session_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), nullable=False, index=True)
    user_email: Mapped[str] = mapped_column(String(255), nullable=False)
    resource_name: Mapped[str] = mapped_column(String(63), nullable=False)
    recording_data: Mapped[str] = mapped_column(Text, nullable=False)
    recording_type: Mapped[str] = mapped_column(String(20), default="terminal", nullable=False)
    started_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False, index=True
    )
    ended_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CertificateAuthority(Base):
    """Certificate authority storage (for DR backup)."""

    __tablename__ = "certificate_authority"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    ca_cert: Mapped[str] = mapped_column(Text, nullable=False)
    ca_key_encrypted: Mapped[str] = mapped_column(Text, nullable=False)  # Encrypted private key
    ssh_host_key: Mapped[str | None] = mapped_column(
        Text, nullable=True
    )  # PEM Ed25519 for ssh-audit
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    __table_args__ = (UniqueConstraint("id"),)  # Only one CA row
