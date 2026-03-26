"""HTTP client for calling API internal proxy endpoints.

Replaces direct Redis/DB access with single round-trip HTTP calls to the
API server's /api/v1/internal/proxy/* endpoints.
"""

from __future__ import annotations

from dataclasses import dataclass, field

import httpx
import structlog

from .config import settings

logger = structlog.get_logger(__name__)

# Shared httpx client with connection pooling
_client: httpx.AsyncClient | None = None


def _get_client() -> httpx.AsyncClient:
    global _client
    if _client is None:
        _client = httpx.AsyncClient(
            base_url=settings.api_url,
            timeout=httpx.Timeout(connect=5.0, read=30.0, write=10.0, pool=10.0),
            limits=httpx.Limits(
                max_connections=30,
                max_keepalive_connections=10,
                keepalive_expiry=30.0,
            ),
            headers={
                "Authorization": f"Bearer {settings.internal_token}",
                "Content-Type": "application/json",
            },
        )
    return _client


async def close_client() -> None:
    """Close the shared httpx client (called on shutdown)."""
    global _client
    if _client is not None:
        await _client.aclose()
        _client = None


@dataclass
class SessionInfo:
    """Session details from the API authorize response."""

    email: str
    display_name: str | None = None
    roles: list[str] = field(default_factory=list)
    kubernetes_groups: list[str] = field(default_factory=list)
    provider_name: str = ""


@dataclass
class ResourceInfo:
    """Resource details from the API authorize response."""

    name: str
    resource_type: str
    agent_id: str | None = None
    hostname: str | None = None
    port: int | None = None
    tunnel_hostname: str | None = None
    webhooks: list[dict] = field(default_factory=list)
    labels: dict[str, str] = field(default_factory=dict)


@dataclass
class RelayInfo:
    """Relay connection info from the API authorize response."""

    bridge_id: str
    bridge_relay_host: str
    agent_name: str
    connected: bool = True


@dataclass
class AuthorizeResult:
    """Result of an authorize call to the API."""

    allowed: bool
    reason: str | None = None
    login_redirect: str | None = None
    session: SessionInfo | None = None
    resource: ResourceInfo | None = None
    relay: RelayInfo | None = None
    webhook_match: dict | None = None


async def authorize(
    *,
    session_token: str | None = None,
    tunnel_hostname: str | None = None,
    resource_name: str | None = None,
    method: str = "GET",
    path: str = "/",
    source_ip: str | None = None,
) -> AuthorizeResult:
    """Authorize a proxy request via the API.

    Single round-trip replacing 6+ sequential Redis/DB lookups.
    """
    client = _get_client()
    payload = {
        "session_token": session_token,
        "tunnel_hostname": tunnel_hostname,
        "resource_name": resource_name,
        "method": method,
        "path": path,
        "source_ip": source_ip,
    }

    try:
        resp = await client.post("/api/v1/internal/proxy/authorize", json=payload)
    except (httpx.ConnectError, httpx.TimeoutException) as e:
        logger.error("API authorize call failed", error=str(e))
        return AuthorizeResult(allowed=False, reason="api_unavailable")

    if resp.status_code != 200:
        logger.error("API authorize returned error", status_code=resp.status_code)
        return AuthorizeResult(allowed=False, reason="api_error")

    data = resp.json()

    session = None
    if data.get("session"):
        s = data["session"]
        session = SessionInfo(
            email=s["email"],
            display_name=s.get("display_name"),
            roles=s.get("roles", []),
            kubernetes_groups=s.get("kubernetes_groups", []),
            provider_name=s.get("provider_name", ""),
        )

    resource = None
    if data.get("resource"):
        r = data["resource"]
        resource = ResourceInfo(
            name=r["name"],
            resource_type=r["resource_type"],
            agent_id=r.get("agent_id"),
            hostname=r.get("hostname"),
            port=r.get("port"),
            tunnel_hostname=r.get("tunnel_hostname"),
            webhooks=r.get("webhooks", []),
            labels=r.get("labels", {}),
        )

    relay = None
    if data.get("relay"):
        rl = data["relay"]
        relay = RelayInfo(
            bridge_id=rl["bridge_id"],
            bridge_relay_host=rl["bridge_relay_host"],
            agent_name=rl["agent_name"],
            connected=rl.get("connected", True),
        )

    return AuthorizeResult(
        allowed=data.get("allowed", False),
        reason=data.get("reason"),
        login_redirect=data.get("login_redirect"),
        session=session,
        resource=resource,
        relay=relay,
        webhook_match=data.get("webhook_match"),
    )


async def log_audit(
    *,
    user_email: str | None = None,
    resource_name: str,
    method: str = "GET",
    path: str = "/",
    status_code: int = 200,
    source_ip: str | None = None,
    user_agent: str | None = None,
    duration_ms: int | None = None,
    action: str = "access_granted",
    protocol: str = "http",
) -> None:
    """Log an audit event. Fire-and-forget — errors are logged but not raised."""
    client = _get_client()
    payload = {
        "user_email": user_email,
        "resource_name": resource_name,
        "method": method,
        "path": path,
        "status_code": status_code,
        "source_ip": source_ip,
        "user_agent": user_agent,
        "duration_ms": duration_ms,
        "action": action,
        "protocol": protocol,
    }

    try:
        await client.post("/api/v1/internal/proxy/audit", json=payload)
    except Exception:
        logger.warning("Failed to send audit event to API", exc_info=True)


async def store_recording(
    *,
    user_email: str,
    resource_name: str,
    recording_type: str = "http",
    data: str,
) -> None:
    """Store an HTTP exchange recording. Fire-and-forget."""
    client = _get_client()
    payload = {
        "user_email": user_email,
        "resource_name": resource_name,
        "recording_type": recording_type,
        "data": data,
    }

    try:
        await client.post("/api/v1/internal/proxy/recording", json=payload)
    except Exception:
        logger.warning("Failed to send recording to API", exc_info=True)
