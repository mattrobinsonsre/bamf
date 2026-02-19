"""Bridge-related Pydantic models.

Bridges are ephemeral — all state lives in Redis, not PostgreSQL.
These models define the API contract between Go bridges and the Python API.
"""

from datetime import datetime

from pydantic import Field

from .common import BAMFBaseModel


class BridgeRegisterRequest(BAMFBaseModel):
    """Bridge registration request (sent on bridge startup)."""

    bridge_id: str = Field(..., min_length=1, max_length=63)
    hostname: str = Field(..., min_length=1)


class BridgeStatusRequest(BAMFBaseModel):
    """Bridge status update request."""

    status: str = Field(..., pattern="^(ready|draining|offline)$")


class BridgeHeartbeatRequest(BAMFBaseModel):
    """Bridge heartbeat request."""

    active_tunnels: int = Field(default=0, ge=0)
    hostname: str = Field(default="", description="Bridge hostname for re-registration")


class SessionValidateRequest(BAMFBaseModel):
    """Session token validation request from bridge."""

    session_token: str = Field(..., min_length=1)


class SessionValidateResponse(BAMFBaseModel):
    """Session validation response to bridge."""

    token: str
    user_email: str
    resource_name: str
    agent_id: str
    protocol: str
    created_at: datetime
    expires_at: datetime


class TunnelEstablishRequest(BAMFBaseModel):
    """Request agent connection info for a tunnel."""

    session_token: str = Field(..., min_length=1)
    agent_id: str = Field(..., min_length=1)


class TunnelEstablishResponse(BAMFBaseModel):
    """Agent connection details for tunnel establishment."""

    agent_id: str
    agent_name: str
    resource_name: str
    resource_type: str
    target_host: str
    target_port: int
    tunnel_token: str


class TunnelEstablishedNotification(BAMFBaseModel):
    """Notification that a tunnel has been established."""

    session_token: str
    tunnel_id: str


class TunnelClosedNotification(BAMFBaseModel):
    """Notification that a tunnel has closed."""

    session_token: str = ""
    tunnel_id: str
    bytes_sent: int = Field(default=0, ge=0)
    bytes_received: int = Field(default=0, ge=0)


class SessionRecordingUpload(BAMFBaseModel):
    """Session recording upload from bridge.

    Sent by the bridge after an audited session completes. Supports:
    - asciicast-v2: Terminal recordings from ssh-audit sessions
    - queries-v1: Database query logs from postgres-audit/mysql-audit sessions
    """

    format: str = Field(
        default="asciicast-v2", pattern="^(asciicast-v2|queries-v1|http-exchange-v1)$"
    )
    data: str = Field(..., min_length=1, description="Recording data")
    recording_type: str | None = Field(
        default=None,
        pattern="^(terminal|queries|http)$",
        description="Recording type (inferred from format if not set)",
    )


class DrainTunnelInfo(BAMFBaseModel):
    """Info about a tunnel on a draining bridge.

    Go contract: pkg/bridge/api_client.go:DrainTunnelInfo
    """

    session_token: str = Field(..., min_length=1)
    protocol: str = Field(..., min_length=1)


class DrainRequest(BAMFBaseModel):
    """Request to drain tunnels from a bridge.

    Go contract: pkg/bridge/api_client.go:RequestDrain() sends this.
    """

    tunnels: list[DrainTunnelInfo] = Field(..., min_length=1)


class DrainResponse(BAMFBaseModel):
    """Response indicating which tunnels were migrated.

    Go contract: pkg/bridge/api_client.go:DrainResponse
    """

    migrated_count: int = Field(default=0, ge=0)
    non_migratable_sessions: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class BridgeBootstrapRequest(BAMFBaseModel):
    """Bridge bootstrap request (sent on first startup to get certificate).

    The bridge sends this request before it has a certificate. It authenticates
    using a bootstrap token mounted from a Kubernetes Secret.
    """

    bridge_id: str = Field(..., min_length=1, max_length=63, description="Unique bridge identifier")
    hostname: str = Field(..., min_length=1, description="Public hostname for this bridge")
    bootstrap_token: str = Field(..., min_length=1, description="Bootstrap token from K8s Secret")


class BridgeBootstrapResponse(BAMFBaseModel):
    """Bridge bootstrap response with certificate.

    Go contract: pkg/bridge/api_client.go:Bootstrap() reads this response.
    """

    certificate: str = Field(..., description="PEM-encoded bridge certificate")
    private_key: str = Field(..., description="PEM-encoded private key")
    ca_certificate: str = Field(..., description="PEM-encoded CA certificate")
    expires_at: datetime = Field(..., description="Certificate expiration time")
    ssh_host_key: str | None = Field(
        None, description="PEM-encoded Ed25519 SSH host key for ssh-audit proxy"
    )
