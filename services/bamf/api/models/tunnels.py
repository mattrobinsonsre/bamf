"""Models for active tunnel dashboard."""

from datetime import datetime

from bamf.api.models.common import BAMFBaseModel


class ActiveTunnel(BAMFBaseModel):
    """A single active tunnel session."""

    session_id: str
    user_email: str
    resource_name: str
    protocol: str
    bridge_id: str
    status: str  # "pending" or "established"
    created_at: datetime
    established_at: datetime | None = None
    duration_seconds: float | None = None


class ActiveTunnelsResponse(BAMFBaseModel):
    """Response for the active tunnels endpoint."""

    tunnels: list[ActiveTunnel]
    total: int
    by_user: dict[str, int]
    by_resource: dict[str, int]
    by_bridge: dict[str, int]
    by_protocol: dict[str, int]
