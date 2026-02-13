"""Agent-related Pydantic models."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import Field

from .common import BAMFBaseModel, NamedModel, TimestampMixin


class AgentBase(NamedModel):
    """Base agent model."""


class AgentRegisterRequest(BAMFBaseModel):
    """Agent registration request."""

    join_token: str
    name: str = Field(..., min_length=1, max_length=63)
    labels: dict[str, str] = Field(default_factory=dict)


class AgentRegisterResponse(BAMFBaseModel):
    """Agent registration response.

    Contract: Go agent reads this in pkg/agent/api_client.go:Join().
    Fields must match the joinResponse struct. The private_key is the
    Ed25519 key the agent uses for TLS auth and the X-Bamf-Client-Cert
    header.
    """

    agent_id: UUID
    certificate: str  # PEM-encoded certificate
    private_key: str  # PEM-encoded Ed25519 private key
    certificate_expires_at: datetime
    ca_certificate: str  # BAMF CA public cert


class AgentResponse(AgentBase, TimestampMixin):
    """Agent response model.

    Combines durable identity from PostgreSQL with runtime state from Redis.
    The `from_db` method takes optional Redis-sourced fields as parameters.
    """

    id: UUID
    labels: dict[str, str] = Field(default_factory=dict)
    status: str = "unknown"
    last_heartbeat: datetime | None = None
    connected_bridge_id: str | None = None
    certificate_expires_at: datetime | None = None
    resource_count: int = 0

    @classmethod
    def from_db(
        cls,
        agent: Any,
        resource_count: int = 0,
        *,
        labels: dict[str, str] | None = None,
        status: str = "unknown",
        last_heartbeat: datetime | None = None,
        connected_bridge_id: str | None = None,
    ) -> "AgentResponse":
        """Create response from database model + Redis runtime state.

        Args:
            agent: SQLAlchemy Agent model (PG — durable identity).
            resource_count: Number of resources owned by this agent (from Redis).
            labels: Agent labels (from Redis).
            status: Agent online/offline status (from Redis).
            last_heartbeat: Last heartbeat timestamp (from Redis).
            connected_bridge_id: Currently connected bridge (from Redis).
        """
        return cls(
            id=agent.id,
            name=agent.name,
            status=status,
            labels=labels or {},
            last_heartbeat=last_heartbeat,
            connected_bridge_id=connected_bridge_id,
            certificate_expires_at=agent.certificate_expires_at,
            resource_count=resource_count,
            created_at=agent.created_at,
            updated_at=agent.updated_at,
        )
