"""Satellite API models.

Satellites are regional proxy+bridge clusters that register with the
central API using join tokens, similar to agent registration.
"""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from pydantic import Field

from bamf.api.models.common import BAMFBaseModel, NamedModel

if TYPE_CHECKING:
    from bamf.db.models import Satellite, SatelliteToken


# ── Satellite Token Models ────────────────────────────────────────────


class SatelliteTokenCreate(NamedModel):
    """Request to create a satellite join token."""

    satellite_name: str = Field(
        ...,
        min_length=1,
        max_length=63,
        pattern=r"^[a-z][a-z0-9-]*$",
        description="DNS-safe satellite name (e.g., 'eu', 'us-east')",
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


class SatelliteTokenResponse(BAMFBaseModel):
    """Satellite token response (without the secret token value)."""

    id: UUID
    name: str
    satellite_name: str
    region: str | None
    expires_at: datetime
    max_uses: int | None
    use_count: int
    is_revoked: bool
    created_at: datetime
    created_by: str

    @classmethod
    def from_db(cls, token: "SatelliteToken") -> "SatelliteTokenResponse":
        """Create response from database model."""
        return cls(
            id=token.id,
            name=token.name,
            satellite_name=token.satellite_name,
            region=token.region,
            expires_at=token.expires_at,
            max_uses=token.max_uses,
            use_count=token.use_count,
            is_revoked=token.is_revoked,
            created_at=token.created_at,
            created_by=token.created_by,
        )


class SatelliteTokenCreateResponse(SatelliteTokenResponse):
    """Response when creating a satellite token - includes the secret value.

    The token value is only returned once at creation time.
    """

    token: str = Field(description="The secret token value - only shown once!")


# ── Satellite Models ──────────────────────────────────────────────────


class SatelliteJoinRequest(BAMFBaseModel):
    """Request to register a satellite using a join token."""

    join_token: str = Field(description="The satellite join token")


class SatelliteJoinResponse(BAMFBaseModel):
    """Response after successful satellite registration.

    Contains the tokens needed for proxy and bridge authentication.
    """

    satellite_id: UUID
    satellite_name: str
    region: str | None
    internal_token: str = Field(description="Token for proxy → API auth")
    bridge_bootstrap_token: str = Field(description="Token for bridge bootstrap")
    ca_certificate: str = Field(description="BAMF CA public certificate (PEM)")
    tunnel_domain: str = Field(description="Base tunnel domain")


class SatelliteResponse(BAMFBaseModel):
    """Satellite details (without secret tokens)."""

    id: UUID
    name: str
    region: str | None
    latitude: float | None
    longitude: float | None
    is_active: bool
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_db(cls, satellite: "Satellite") -> "SatelliteResponse":
        """Create response from database model."""
        return cls(
            id=satellite.id,
            name=satellite.name,
            region=satellite.region,
            latitude=satellite.latitude,
            longitude=satellite.longitude,
            is_active=satellite.is_active,
            created_at=satellite.created_at,
            updated_at=satellite.updated_at,
        )
