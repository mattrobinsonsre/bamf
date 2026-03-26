"""Internal proxy authorization and audit endpoints.

Called by the standalone proxy service, NOT by end users. These endpoints
consolidate multiple Redis/DB lookups into single round-trips so the proxy
can remain stateless (no direct Redis/DB access).

Auth: Shared secret in Authorization: Bearer <token>, validated against
BAMF_PROXY_INTERNAL_TOKEN env var / settings.proxy_internal_token, or
against outpost internal tokens stored in the database.
"""

from __future__ import annotations

import hashlib
import ipaddress
import secrets
import time
from dataclasses import dataclass
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy import select

from bamf.api.bridge_relay import (
    assign_relay_bridge,
    build_bridge_relay_host,
    ensure_relay_connected,
)
from bamf.auth.sessions import get_session
from bamf.config import settings
from bamf.db.models import Outpost, SessionRecording, generate_uuid7
from bamf.db.session import async_session_factory, async_session_factory_read
from bamf.logging_config import get_logger
from bamf.redis.client import get_redis_client
from bamf.services.audit_service import log_audit_event
from bamf.services.rbac_service import check_access
from bamf.services.resource_catalog import (
    get_resource,
    get_resource_by_tunnel_hostname,
)

logger = get_logger(__name__)

router = APIRouter(prefix="/internal/proxy", tags=["internal-proxy"])


# ── Request / Response Models ─────────────────────────────────────────────


class AuthorizeRequest(BaseModel):
    """Proxy authorization request — single round-trip replacing 6+ lookups."""

    session_token: str | None = None
    tunnel_hostname: str | None = None
    resource_name: str | None = None
    method: str = "GET"
    path: str = "/"
    source_ip: str | None = None
    outpost_name: str | None = None  # Set from ProxyIdentity by the endpoint


class SessionInfo(BaseModel):
    """Session details returned in authorize response."""

    email: str
    display_name: str | None = None
    roles: list[str] = Field(default_factory=list)
    kubernetes_groups: list[str] = Field(default_factory=list)
    provider_name: str = ""


class ResourceInfoResponse(BaseModel):
    """Resource details returned in authorize response."""

    name: str
    resource_type: str
    agent_id: str | None = None
    hostname: str | None = None
    port: int | None = None
    tunnel_hostname: str | None = None
    webhooks: list[dict] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)


class RelayInfo(BaseModel):
    """Relay connection details returned in authorize response."""

    bridge_id: str
    bridge_relay_host: str
    agent_name: str
    connected: bool = True


class AuthorizeResponse(BaseModel):
    """Proxy authorization response — everything the proxy needs."""

    allowed: bool
    reason: str | None = None
    login_redirect: str | None = None
    session: SessionInfo | None = None
    resource: ResourceInfoResponse | None = None
    relay: RelayInfo | None = None
    webhook_match: dict | None = None


class AuditRequest(BaseModel):
    """Proxy audit event — fire-and-forget."""

    session_token: str | None = None
    user_email: str | None = None
    resource_name: str
    method: str = "GET"
    path: str = "/"
    status_code: int = 200
    source_ip: str | None = None
    user_agent: str | None = None
    duration_ms: int | None = None
    bytes_sent: int | None = None
    bytes_received: int | None = None
    action: str = "access_granted"
    protocol: str = "http"


class RecordingRequest(BaseModel):
    """HTTP exchange recording for http-audit resources."""

    session_id: str | None = None
    user_email: str
    resource_name: str
    recording_type: str = "http"
    data: str  # JSON-encoded exchange


# ── Auth dependency ───────────────────────────────────────────────────────


@dataclass
class ProxyIdentity:
    """Identity of the calling proxy, including its outpost affiliation."""

    outpost_name: str | None = None


# In-process cache for outpost token → name mapping (avoid DB lookup per request).
# Format: {token_hash: (outpost_name, cached_at_monotonic)}
_outpost_token_cache: dict[str, tuple[str, float]] = {}
_OUTPOST_TOKEN_CACHE_TTL = 60  # seconds


async def _lookup_outpost_by_internal_token(token: str) -> str | None:
    """Look up outpost name by internal token, with in-process caching."""
    token_hash = hashlib.sha256(token.encode()).hexdigest()

    # Check cache
    cached = _outpost_token_cache.get(token_hash)
    if cached:
        name, cached_at = cached
        if time.monotonic() - cached_at < _OUTPOST_TOKEN_CACHE_TTL:
            return name
        del _outpost_token_cache[token_hash]

    # DB lookup
    async with async_session_factory_read() as db:
        result = await db.execute(
            select(Outpost).where(
                Outpost.internal_token_hash == token_hash,
                Outpost.is_active == True,  # noqa: E712
            )
        )
        outpost = result.scalar_one_or_none()

    if outpost:
        _outpost_token_cache[token_hash] = (outpost.name, time.monotonic())
        return outpost.name

    return None


async def verify_internal_token(request: Request) -> ProxyIdentity:
    """Verify the proxy internal auth token.

    Checks two sources:
    1. Co-located proxy token (env var, backward compatible)
    2. Outpost internal tokens (DB hash lookup, cached)

    Returns ProxyIdentity with outpost_name for routing decisions.
    """
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization",
        )

    bearer_token = auth_header[7:]

    # Check 1: co-located proxy token (env var)
    co_located_token = settings.proxy_internal_token
    if co_located_token and secrets.compare_digest(bearer_token, co_located_token):
        return ProxyIdentity(outpost_name=settings.default_outpost_name)

    # Check 2: outpost internal token (DB lookup, cached)
    outpost_name = await _lookup_outpost_by_internal_token(bearer_token)
    if outpost_name:
        return ProxyIdentity(outpost_name=outpost_name)

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Invalid internal token",
    )


# ── Endpoints ─────────────────────────────────────────────────────────────


@router.post(
    "/authorize",
    response_model=AuthorizeResponse,
)
async def authorize(
    req: AuthorizeRequest,
    identity: ProxyIdentity = Depends(verify_internal_token),
) -> AuthorizeResponse:
    """Authorize a proxy request in a single round-trip.

    Replaces 6+ sequential Redis/DB lookups that the old embedded proxy did:
    1. get_session(token)
    2. get_resource_by_tunnel_hostname() or get_resource()
    3. check_access(db, session, resource, roles)
    4. agent status check
    5. relay bridge lookup/assignment
    6. agent name lookup
    """
    r = get_redis_client()

    # Stamp the outpost identity from the calling proxy
    req.outpost_name = identity.outpost_name

    # 1. Resolve resource
    resource = None
    if req.tunnel_hostname:
        resource = await get_resource_by_tunnel_hostname(r, req.tunnel_hostname)
    elif req.resource_name:
        resource = await get_resource(r, req.resource_name)

    if resource is None:
        return AuthorizeResponse(allowed=False, reason="resource_not_found")

    resource_resp = ResourceInfoResponse(
        name=resource.name,
        resource_type=resource.resource_type,
        agent_id=resource.agent_id,
        hostname=resource.hostname,
        port=resource.port,
        tunnel_hostname=resource.tunnel_hostname,
        webhooks=resource.webhooks,
        labels=resource.labels,
    )

    # 2. Check webhook passthrough BEFORE auth
    wh = _match_webhook(resource, req.method, req.path, req.source_ip)
    if wh is not None:
        # Webhook match — resolve relay without auth
        relay = await _resolve_relay(r, resource, req.outpost_name)
        if relay is None:
            return AuthorizeResponse(
                allowed=False,
                reason="relay_unavailable",
                resource=resource_resp,
                webhook_match=wh,
            )
        return AuthorizeResponse(
            allowed=True,
            session=None,
            resource=resource_resp,
            relay=relay,
            webhook_match=wh,
        )

    # 3. Authenticate session
    if not req.session_token:
        return AuthorizeResponse(
            allowed=False,
            reason="no_session",
            resource=resource_resp,
        )

    session = await get_session(req.session_token)
    if session is None:
        return AuthorizeResponse(
            allowed=False,
            reason="no_session",
            resource=resource_resp,
        )

    session_resp = SessionInfo(
        email=session.email,
        display_name=session.display_name,
        roles=session.roles,
        kubernetes_groups=session.kubernetes_groups,
        provider_name=session.provider_name,
    )

    # 4. RBAC check
    async with async_session_factory_read() as db:
        allowed = await check_access(db, session, resource, session.roles)

    if not allowed:
        return AuthorizeResponse(
            allowed=False,
            reason="access_denied",
            session=session_resp,
            resource=resource_resp,
        )

    # 5. Resolve relay connection
    relay = await _resolve_relay(r, resource, req.outpost_name)
    if relay is None:
        return AuthorizeResponse(
            allowed=False,
            reason="relay_unavailable",
            session=session_resp,
            resource=resource_resp,
        )

    return AuthorizeResponse(
        allowed=True,
        session=session_resp,
        resource=resource_resp,
        relay=relay,
    )


@router.post(
    "/audit",
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(verify_internal_token)],
)
async def audit(req: AuditRequest) -> dict:
    """Log an audit event from the proxy. Fire-and-forget."""
    try:
        async with async_session_factory() as db:
            details: dict = {
                "protocol": req.protocol,
                "method": req.method,
                "path": req.path,
                "status_code": req.status_code,
            }
            if req.duration_ms is not None:
                details["duration_ms"] = req.duration_ms
            if req.bytes_sent is not None:
                details["bytes_sent"] = req.bytes_sent
            if req.bytes_received is not None:
                details["bytes_received"] = req.bytes_received

            actor_type = "user" if req.user_email else "external"
            actor_id = req.user_email or req.source_ip or "unknown"

            await log_audit_event(
                db,
                event_type="access",
                action=req.action,
                actor_type=actor_type,
                actor_id=actor_id,
                target_type="resource",
                target_id=req.resource_name,
                actor_ip=req.source_ip,
                details=details,
                success=req.status_code < 500,
            )
            await db.commit()
    except Exception:
        logger.warning("Failed to log proxy audit event", exc_info=True)

    return {"status": "accepted"}


@router.post(
    "/recording",
    status_code=status.HTTP_202_ACCEPTED,
    dependencies=[Depends(verify_internal_token)],
)
async def recording(req: RecordingRequest) -> dict:
    """Store an HTTP exchange recording from the proxy."""
    try:
        now = datetime.now(UTC)
        recording_id = generate_uuid7()
        rec = SessionRecording(
            id=recording_id,
            session_id=recording_id,
            user_email=req.user_email,
            resource_name=req.resource_name,
            recording_data=req.data,
            recording_type=req.recording_type,
            started_at=now,
            ended_at=now,
        )

        async with async_session_factory() as db:
            db.add(rec)
            await db.commit()
    except Exception:
        logger.warning("Failed to store proxy recording", exc_info=True)

    return {"status": "accepted"}


# ── Helpers ───────────────────────────────────────────────────────────────


def _match_webhook(resource, method: str, path: str, client_ip: str | None) -> dict | None:
    """Check if a request matches a webhook passthrough rule.

    Returns the matched webhook config dict, or None if no match.
    Path matching is strict prefix: a webhook path of "/hook/" matches
    "/hook/" and "/hook/foo" but not "/hookx".
    """
    webhooks = getattr(resource, "webhooks", None)
    if not webhooks:
        return None

    for wh in webhooks:
        wh_path = wh.get("path", "")
        wh_methods = [m.upper() for m in wh.get("methods", [])]

        # Method check
        if method.upper() not in wh_methods:
            continue

        # Path prefix check — strict prefix match
        if not path.startswith(wh_path):
            continue

        # Source CIDR check
        source_cidrs = wh.get("source_cidrs", [])
        if source_cidrs and client_ip:
            try:
                addr = ipaddress.ip_address(client_ip)
                if not any(addr in ipaddress.ip_network(cidr) for cidr in source_cidrs):
                    continue
            except ValueError:
                continue
        elif source_cidrs and not client_ip:
            # CIDRs configured but no client IP available — deny
            continue

        return wh

    return None


async def _resolve_relay(r, resource, outpost_name: str | None = None) -> RelayInfo | None:
    """Resolve relay bridge and agent for a resource.

    Handles: agent status check, relay bridge assignment, relay_connect
    SSE signaling, and agent name lookup.

    When outpost_name is provided, uses per-outpost relay keys
    (agent:{id}:relay:{outpost_name}) to find bridges in the proxy's
    outpost. Falls back to the global relay_bridge key for backward
    compatibility with pre-outpost deployments.
    """
    agent_id = resource.agent_id
    if not agent_id:
        return None

    # Check agent is online
    agent_status = await r.get(f"agent:{agent_id}:status")
    if not agent_status:
        return None

    # Resolve relay bridge — prefer outpost-specific key, fall back to global
    relay_bridge = None
    if outpost_name:
        relay_bridge = await r.get(f"agent:{agent_id}:relay:{outpost_name}")
    if relay_bridge is None:
        relay_bridge = await r.get(f"agent:{agent_id}:relay_bridge")
    if relay_bridge is None:
        relay_bridge = await assign_relay_bridge(r, agent_id, outpost_name)
        if relay_bridge is None:
            return None
        ready = await ensure_relay_connected(r, agent_id, relay_bridge)
        if not ready:
            return None

    # Resolve agent name
    agent_name = await r.get(f"agent:{agent_id}:name")
    if not agent_name:
        agent_name = agent_id

    bridge_relay_host = build_bridge_relay_host(relay_bridge)

    return RelayInfo(
        bridge_id=relay_bridge,
        bridge_relay_host=bridge_relay_host,
        agent_name=agent_name,
        connected=True,
    )
