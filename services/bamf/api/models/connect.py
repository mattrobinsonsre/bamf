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
    protocol: str | None = Field(
        None,
        description="Override the resource type for this session. "
        "Used by web terminal to specify 'web-ssh' or 'web-db' instead "
        "of the resource's native type (e.g. 'ssh', 'postgres').",
    )
    client_edge_rtts: dict[str, int] = Field(
        default_factory=dict,
        description="Client-measured latency in milliseconds to each edge "
        "(the client-leg of measured-latency edge selection, #119). Merged "
        "with the agent-leg to pick the rendezvous edge. Empty on a cold "
        "client — the API then routes to the agent-nearest edge.",
    )


class ReevaluateRequest(BAMFBaseModel):
    """Ask whether a live tunnel should hop to a better edge (#260)."""

    session_id: str = Field(..., description="The live tunnel's session id")
    client_edge_rtts: dict[str, int] = Field(
        default_factory=dict,
        description="The client's freshly-measured per-edge latency (ms).",
    )


class ReevaluateResponse(BAMFBaseModel):
    """The hop decision for a live tunnel."""

    hop_edge: str | None = Field(
        default=None,
        description="Edge to migrate the tunnel to, or null to stay put. Applies "
        "hysteresis — only set when a meaningfully better rendezvous edge exists.",
    )


class EdgeProbeTarget(BAMFBaseModel):
    """One edge the client should latency-probe for the client-leg (#119).

    ``probe_host``/``probe_port`` is a reachable bridge ingress in that edge; a
    TCP-connect to it measures the client→edge leg. The client caches the vector
    and sends it back as ``client_edge_rtts`` on the next connect.
    """

    name: str = Field(..., description="Edge name")
    probe_host: str = Field(..., description="Bridge ingress hostname to probe")
    probe_port: int = Field(..., description="Bridge ingress port to probe")


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
    candidate_edges: list[EdgeProbeTarget] = Field(
        default_factory=list,
        description="Edges the client should latency-probe in the background to "
        "measure its client-leg (#119). Empty in single-edge deployments.",
    )
