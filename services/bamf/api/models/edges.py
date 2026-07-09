"""Edge API models.

Edges are regional proxy+bridge clusters that register with the
central API using join tokens, similar to agent registration.
"""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from pydantic import Field

from bamf.api.models.common import BAMFBaseModel, NamedModel

if TYPE_CHECKING:
    from bamf.db.models import Edge, EdgeToken


# ── Edge Token Models ────────────────────────────────────────────


class EdgeTokenCreate(NamedModel):
    """Request to create an edge join token."""

    edge_name: str = Field(
        ...,
        min_length=1,
        max_length=63,
        pattern=r"^[a-z][a-z0-9-]*$",
        description="DNS-safe edge name (e.g., 'eu', 'us-east')",
    )
    region: str | None = Field(
        default=None,
        max_length=255,
        description="Human-readable region label (e.g., 'EU West (Ireland)')",
    )
    expires_in_hours: int = Field(
        default=24,
        ge=1,
        le=8760,
        description="Hours until token expires",
    )
    max_uses: int | None = Field(
        default=None,
        ge=1,
        description="Maximum number of times the token can be used (null = unlimited)",
    )


class EdgeTokenResponse(BAMFBaseModel):
    """Edge token response (without the secret token value)."""

    id: UUID
    name: str
    edge_name: str
    region: str | None
    expires_at: datetime
    max_uses: int | None
    use_count: int
    is_revoked: bool
    created_at: datetime
    created_by: str

    @classmethod
    def from_db(cls, token: EdgeToken) -> EdgeTokenResponse:
        """Create response from database model."""
        return cls(
            id=token.id,
            name=token.name,
            edge_name=token.edge_name,
            region=token.region,
            expires_at=token.expires_at,
            max_uses=token.max_uses,
            use_count=token.use_count,
            is_revoked=token.is_revoked,
            created_at=token.created_at,
            created_by=token.created_by,
        )


class EdgeTokenCreateResponse(EdgeTokenResponse):
    """Response when creating an edge token - includes the secret value.

    The token value is only returned once at creation time.
    """

    token: str = Field(description="The secret token value - only shown once!")


# ── Edge Models ──────────────────────────────────────────────────


class EdgeJoinRequest(BAMFBaseModel):
    """Request to register an edge using a join token."""

    join_token: str = Field(description="The edge join token")


class EdgeJoinResponse(BAMFBaseModel):
    """Response after successful edge registration.

    Contains the tokens needed for proxy and bridge authentication.
    """

    edge_id: UUID
    edge_name: str
    region: str | None
    internal_token: str = Field(description="Token for proxy → API auth")
    bridge_bootstrap_token: str = Field(description="Token for bridge bootstrap")
    ca_certificate: str = Field(description="BAMF CA public certificate (PEM)")
    tunnel_domain: str = Field(description="Base tunnel domain")


class EdgeResponse(BAMFBaseModel):
    """Edge details (without secret tokens)."""

    id: UUID
    name: str
    region: str | None
    is_active: bool
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_db(cls, edge: Edge) -> EdgeResponse:
        """Create response from database model."""
        return cls(
            id=edge.id,
            name=edge.name,
            region=edge.region,
            is_active=edge.is_active,
            created_at=edge.created_at,
            updated_at=edge.updated_at,
        )
