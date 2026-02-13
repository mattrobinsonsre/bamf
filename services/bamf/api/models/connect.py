"""Connection/tunnel-related Pydantic models."""

from datetime import datetime

from pydantic import Field

from .common import BAMFBaseModel


class ConnectRequest(BAMFBaseModel):
    """Request to connect to a resource."""

    resource_name: str = Field(..., min_length=1, max_length=63)
    reconnect_session_id: str | None = Field(
        None,
        description="If set, reconnect an existing session through a new bridge "
        "instead of creating a new session. Used when the bridge dies "
        "mid-tunnel and the CLI/agent need to re-establish the connection.",
    )


class ConnectResponse(BAMFBaseModel):
    """Connection response with bridge info and session certificate.

    The session certificate IS the authorization — it encodes the session ID,
    resource, and bridge ID as SAN URIs. The bridge validates the cert chain
    against the BAMF CA and reads the SAN URIs to route the connection.
    """

    bridge_hostname: str = Field(..., description="Bridge hostname to connect to")
    bridge_port: int = Field(..., description="Bridge tunnel port")
    session_cert: str = Field(..., description="PEM-encoded session certificate")
    session_key: str = Field(..., description="PEM-encoded session private key")
    ca_certificate: str = Field(..., description="PEM-encoded CA certificate for verification")
    session_id: str = Field(..., description="Session identifier (also in cert SAN)")
    session_expires_at: datetime = Field(..., description="Session certificate expiry")
    resource_type: str = Field(..., description="Type of resource (ssh, postgres, etc.)")
