"""Outpost API models.

Outposts are regional proxy+bridge clusters that register with the
central API using join tokens, similar to agent registration.
"""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from pydantic import Field

from bamf.api.models.common import BAMFBaseModel, NamedModel

if TYPE_CHECKING:
    from bamf.db.models import Outpost, OutpostToken


# ── Outpost Token Models ────────────────────────────────────────────


class OutpostTokenCreate(NamedModel):
    """Request to create an outpost join token."""

    outpost_name: str = Field(
        ...,
        min_length=1,
        max_length=63,
        pattern=r"^[a-z][a-z0-9-]*$",
        description="DNS-safe outpost name (e.g., 'eu', 'us-east')",
    )
    region: str | None = Field(
        default=None,
        max_length=255,
        description="Human-readable region label (e.g., 'EU West (Ireland)')",
    )
    latitude: float | None = Field(
        default=None,
        ge=-90,
        le=90,
        description="Latitude for GeoIP routing",
    )
    longitude: float | None = Field(
        default=None,
        ge=-180,
        le=180,
        description="Longitude for GeoIP routing",
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


class OutpostTokenResponse(BAMFBaseModel):
    """Outpost token response (without the secret token value)."""

    id: UUID
    name: str
    outpost_name: str
    region: str | None
    expires_at: datetime
    max_uses: int | None
    use_count: int
    is_revoked: bool
    created_at: datetime
    created_by: str

    @classmethod
    def from_db(cls, token: "OutpostToken") -> "OutpostTokenResponse":
        """Create response from database model."""
        return cls(
            id=token.id,
            name=token.name,
            outpost_name=token.outpost_name,
            region=token.region,
            expires_at=token.expires_at,
            max_uses=token.max_uses,
            use_count=token.use_count,
            is_revoked=token.is_revoked,
            created_at=token.created_at,
            created_by=token.created_by,
        )


class OutpostTokenCreateResponse(OutpostTokenResponse):
    """Response when creating an outpost token - includes the secret value.

    The token value is only returned once at creation time.
    """

    token: str = Field(description="The secret token value - only shown once!")


# ── Outpost Models ──────────────────────────────────────────────────


class OutpostJoinRequest(BAMFBaseModel):
    """Request to register an outpost using a join token."""

    join_token: str = Field(description="The outpost join token")


class OutpostJoinResponse(BAMFBaseModel):
    """Response after successful outpost registration.

    Contains the tokens needed for proxy and bridge authentication.
    """

    outpost_id: UUID
    outpost_name: str
    region: str | None
    internal_token: str = Field(description="Token for proxy → API auth")
    bridge_bootstrap_token: str = Field(description="Token for bridge bootstrap")
    ca_certificate: str = Field(description="BAMF CA public certificate (PEM)")
    tunnel_domain: str = Field(description="Base tunnel domain")


class OutpostResponse(BAMFBaseModel):
    """Outpost details (without secret tokens)."""

    id: UUID
    name: str
    region: str | None
    latitude: float | None
    longitude: float | None
    is_active: bool
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_db(cls, outpost: "Outpost") -> "OutpostResponse":
        """Create response from database model."""
        return cls(
            id=outpost.id,
            name=outpost.name,
            region=outpost.region,
            latitude=outpost.latitude,
            longitude=outpost.longitude,
            is_active=outpost.is_active,
            created_at=outpost.created_at,
            updated_at=outpost.updated_at,
        )
