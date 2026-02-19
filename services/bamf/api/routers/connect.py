"""Connect router for tunnel session management.

This is the main user-facing endpoint for initiating connections to resources.
It orchestrates: RBAC check → bridge selection → session cert issuance →
Redis session storage → agent notification.

Consumers:
    Go CLI (planned):
        POST /api/v1/connect — initiates a tunnel session
    Web UI (web/src/):
        POST /api/v1/connect — initiates web app proxy session

Downstream effects:
    This endpoint publishes a JSON command to Redis pub/sub channel
    agent:{agent_id}:commands. The SSE endpoint in agents.py delivers
    this to the Go agent (pkg/agent/sse.go → pkg/agent/agent.go:handleTunnelRequest).

    Pub/sub payload shape (new connection):
        {"command": "dial", "session_id": "...", "bridge_host": "...",
         "bridge_port": 443, "resource_name": "...", "resource_type": "ssh",
         "session_cert": "-----BEGIN CERTIFICATE-----...",
         "session_key": "-----BEGIN PRIVATE KEY-----...",
         "ca_certificate": "-----BEGIN CERTIFICATE-----..."}

    Pub/sub payload shape (reconnect after bridge failure):
        {"command": "redial", "session_id": "...", "bridge_host": "...",
         "bridge_port": 443, "resource_name": "...", "resource_type": "ssh",
         "session_cert": "-----BEGIN CERTIFICATE-----...",
         "session_key": "-----BEGIN PRIVATE KEY-----...",
         "ca_certificate": "-----BEGIN CERTIFICATE-----..."}

    The session_cert/key/ca_certificate allow the agent to connect to the bridge
    with mTLS using a per-tunnel session certificate.

    Changes to this payload must be coordinated with:
        - services/bamf/api/routers/agents.py:agent_events (SSE wrapper)
        - pkg/agent/agent.go:handleTunnelRequest (consumer)
        - pkg/agent/tunnel.go:NewTunnelHandler (cert loading)
"""

import json
import re
import secrets
from datetime import UTC, datetime

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.api.dependencies import get_current_user
from bamf.api.models.connect import ConnectRequest, ConnectResponse
from bamf.auth.ca import get_ca, serialize_certificate, serialize_private_key
from bamf.auth.sessions import Session
from bamf.config import settings
from bamf.db.session import get_db
from bamf.logging_config import get_logger
from bamf.redis.client import get_redis
from bamf.services.audit_service import log_audit_event
from bamf.services.rbac_service import check_access
from bamf.services.resource_catalog import get_resource

router = APIRouter(prefix="/connect", tags=["connect"])
logger = get_logger(__name__)

# Session token TTL in Redis (30 seconds for tunnel setup; extended on establish)
SESSION_TTL_SECONDS = 30

# Reconnect TTL: longer than setup because bridge selection and agent notification
# need time after a failure event. Also accounts for agent SSE reconnect delay.
RECONNECT_TTL_SECONDS = 300

# Protocols that maintain bridge-local state and cannot survive migration.
# Only ssh-audit qualifies: the bridge terminates SSH and holds encryption
# state in-process. Database audit tunnels (postgres-audit, mysql-audit) use
# passive byte-stream tapping over a standard tunnel and ARE migratable.
NON_MIGRATABLE_PROTOCOLS = {"ssh-audit", "web-ssh", "web-db"}

# Default oversubscription factor for non-migratable session bridge selection.
# Low-ordinal bridges can accept up to this factor × targetTunnelsPerPod tunnels
# before the selector spills to higher ordinals.
NON_MIGRATABLE_OVERSUBSCRIBE_FACTOR = 1.5

# Valid protocol overrides and the native resource types they're allowed for.
_PROTOCOL_OVERRIDE_MAP: dict[str, set[str]] = {
    "web-ssh": {"ssh", "ssh-audit"},
    "web-db": {"postgres", "postgres-audit", "mysql", "mysql-audit"},
}


def _validate_protocol_override(protocol: str, native_type: str) -> None:
    """Validate that a protocol override is compatible with the resource type."""
    allowed = _PROTOCOL_OVERRIDE_MAP.get(protocol)
    if allowed is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid protocol override: {protocol}",
        )
    if native_type not in allowed:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Protocol '{protocol}' is not valid for resource type '{native_type}'",
        )


@router.post("", response_model=ConnectResponse)
async def connect_to_resource(
    request: ConnectRequest,
    db: AsyncSession = Depends(get_db),
    r: aioredis.Redis = Depends(get_redis),
    current_user: Session = Depends(get_current_user),
) -> ConnectResponse:
    """Request a connection to a resource.

    If reconnect_session_id is provided, reconnects an existing session
    through a new bridge (used when a bridge dies mid-tunnel). Otherwise,
    creates a new session with full RBAC validation.
    """
    if request.reconnect_session_id:
        return await _handle_reconnect(request, db, r, current_user)
    return await _handle_new_connection(request, db, r, current_user)


async def _handle_new_connection(
    request: ConnectRequest,
    db: AsyncSession,
    r: aioredis.Redis,
    current_user: Session,
) -> ConnectResponse:
    """Create a new tunnel session (standard flow).

    Flow:
    1. Validate the user has access to the resource (RBAC)
    2. Select the least-loaded available bridge (Redis sorted set)
    3. Issue a session certificate with SAN URIs encoding the authorization
    4. Store session in Redis for bridge validation
    5. Notify the agent via Redis pub/sub to dial the bridge
    6. Return bridge info + session cert for CLI to connect
    """
    # ── 1. Find resource (Redis — agent-reported catalog) ─────────────
    resource = await get_resource(r, request.resource_name)

    if not resource:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Resource '{request.resource_name}' not found",
        )

    # ── 2. Check access (PG — RBAC policy) ──────────────────────────────
    has_access = await check_access(db, current_user, resource, current_user.roles)
    if not has_access:
        logger.info("Access denied", user=current_user.email, resource=resource.name)
        await log_audit_event(
            db,
            event_type="access",
            action="access_denied",
            actor_type="user",
            actor_id=current_user.email,
            target_type="resource",
            target_id=resource.name,
            success=False,
            error_message="Access denied by RBAC policy",
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    # ── 3. Check agent is online ──────────────────────────────────────
    agent_id = resource.agent_id
    if not agent_id:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Resource has no agent assigned",
        )

    agent_status = await r.get(f"agent:{agent_id}:status")
    if not agent_status:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Agent is offline",
        )

    # ── 4-7. Common: bridge selection, certs, session, agent notify ───
    # Allow protocol override for web terminal sessions (web-ssh, web-db).
    # Validate that the override matches the resource's native type.
    original_resource_type = resource.resource_type
    resource_type = original_resource_type
    if request.protocol:
        _validate_protocol_override(request.protocol, original_resource_type)
        resource_type = request.protocol

    session_id = secrets.token_urlsafe(24)
    return await _issue_session(
        db=db,
        r=r,
        current_user=current_user,
        session_id=session_id,
        resource_name=resource.name,
        resource_type=resource_type,
        original_resource_type=original_resource_type,
        agent_id=agent_id,
        exclude_bridge_id=None,
        session_ttl=SESSION_TTL_SECONDS,
        command="dial",
        audit_action="access_granted",
    )


async def _handle_reconnect(
    request: ConnectRequest,
    db: AsyncSession,
    r: aioredis.Redis,
    current_user: Session,
) -> ConnectResponse:
    """Reconnect an existing session through a new bridge.

    Used when the bridge dies mid-tunnel. The reliable stream protocol
    (pkg/tunnel/reliable.go) buffers in-flight data on both CLI and agent,
    so reconnecting through a new bridge resumes the session with no data loss.

    Flow:
    1. Validate the session exists in Redis and belongs to this user
    2. Check agent is still online
    3. Select a new bridge (prefer one different from the dead bridge)
    4. Issue new session certs with the SAME session ID
    5. Update session in Redis with new bridge
    6. Notify agent via pub/sub with "redial" command
    7. Return new bridge info + certs to CLI
    """
    session_id = request.reconnect_session_id

    # ── 1. Validate existing session ──────────────────────────────────
    raw = await r.get(f"session:{session_id}")
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found or expired — start a new connection",
        )

    session_data = json.loads(raw)

    # Verify session ownership.
    if session_data.get("user_email") != current_user.email:
        logger.warning(
            "Reconnect denied: session belongs to different user",
            user=current_user.email,
            session_id=session_id,
            session_owner=session_data.get("user_email"),
        )
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session does not belong to this user",
        )

    resource_name = session_data["resource_name"]
    resource_type = session_data.get("protocol", "ssh")
    agent_id = session_data["agent_id"]
    old_bridge_id = session_data.get("bridge_id")

    # ── 2. Check agent is still online ────────────────────────────────
    agent_status = await r.get(f"agent:{agent_id}:status")
    if not agent_status:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Agent is offline — cannot reconnect",
        )

    # ── 3-7. Common: bridge selection, certs, session, agent notify ───
    # Decrement old bridge tunnel count (best-effort — bridge may be dead).
    if old_bridge_id:
        await r.zincrby("bridges:available", -1, old_bridge_id)
        await r.hincrby(f"bridge:{old_bridge_id}", "active_tunnels", -1)

    return await _issue_session(
        db=db,
        r=r,
        current_user=current_user,
        session_id=session_id,
        resource_name=resource_name,
        resource_type=resource_type,
        agent_id=agent_id,
        exclude_bridge_id=old_bridge_id,
        session_ttl=RECONNECT_TTL_SECONDS,
        command="redial",
        audit_action="session_reconnected",
    )


def _extract_ordinal(bridge_id: str) -> int:
    """Extract the StatefulSet ordinal from a bridge ID like 'bamf-bridge-0'."""
    m = re.search(r"-(\d+)$", bridge_id)
    return int(m.group(1)) if m else 0


async def _select_bridge(
    r: aioredis.Redis,
    exclude_bridge_id: str | None = None,
    *,
    prefer_low_ordinal: bool = False,
    target_tunnels_per_pod: int = 0,
    oversubscribe_factor: float = NON_MIGRATABLE_OVERSUBSCRIBE_FACTOR,
) -> tuple[str, dict[str, str]]:
    """Select the best bridge, optionally excluding one.

    When prefer_low_ordinal is True (used for non-migratable ssh-audit sessions),
    the selector biases toward the lowest-ordinal bridge that is below the
    oversubscription threshold. StatefulSet scale-down removes the highest
    ordinal first, so low-ordinal bridges are the last to be drained.

    Returns (bridge_id, bridge_info_dict).
    Raises HTTPException if no bridges are available.
    """
    # Fetch all candidates (withscores gives us tunnel counts).
    bridges_with_scores = await r.zrangebyscore(
        "bridges:available", "-inf", "+inf", start=0, num=50, withscores=True
    )
    if not bridges_with_scores:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="No bridges available",
        )

    # Filter out the excluded bridge.
    candidates = [
        (bid, int(score)) for bid, score in bridges_with_scores if bid != exclude_bridge_id
    ]
    if not candidates:
        # All candidates are the excluded bridge — use it as fallback.
        candidates = [(bridges_with_scores[0][0], int(bridges_with_scores[0][1]))]

    if prefer_low_ordinal and target_tunnels_per_pod > 0:
        # Non-migratable session: prefer lowest ordinal within oversubscription threshold.
        threshold = int(target_tunnels_per_pod * oversubscribe_factor)
        eligible = [(bid, score) for bid, score in candidates if score < threshold]
        if eligible:
            # Sort by ordinal (lowest first), then by tunnel count.
            eligible.sort(key=lambda x: (_extract_ordinal(x[0]), x[1]))
            selected = eligible[0][0]
        else:
            # All low-ordinal bridges full — fall back to least-loaded.
            candidates.sort(key=lambda x: x[1])
            selected = candidates[0][0]
    else:
        # Standard: least-loaded (already sorted by score from Redis).
        candidates.sort(key=lambda x: x[1])
        selected = candidates[0][0]

    bridge_info = await r.hgetall(f"bridge:{selected}")
    if not bridge_info:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Selected bridge is no longer available",
        )

    return selected, bridge_info


async def _issue_session(
    *,
    db: AsyncSession,
    r: aioredis.Redis,
    current_user: Session,
    session_id: str,
    resource_name: str,
    resource_type: str,
    original_resource_type: str | None = None,
    agent_id: str,
    exclude_bridge_id: str | None,
    session_ttl: int,
    command: str,
    audit_action: str,
) -> ConnectResponse:
    """Common logic for new connections and reconnects.

    Handles bridge selection, cert issuance, Redis session storage,
    agent notification, audit logging, and response construction.
    """
    # ── Bridge selection ──────────────────────────────────────────────
    bridge_id, bridge_info = await _select_bridge(
        r,
        exclude_bridge_id,
        prefer_low_ordinal=resource_type in NON_MIGRATABLE_PROTOCOLS,
        target_tunnels_per_pod=settings.target_tunnels_per_pod,
    )
    bridge_hostname = bridge_info.get("hostname", "")

    # ── Issue session certificates ────────────────────────────────────
    ca = get_ca()

    client_cert, client_key = ca.issue_session_certificate(
        session_id=session_id,
        resource_name=resource_name,
        bridge_id=bridge_id,
        subject_cn=current_user.email,
        role="client",
        ttl_seconds=session_ttl,
    )

    agent_cert, agent_key = ca.issue_session_certificate(
        session_id=session_id,
        resource_name=resource_name,
        bridge_id=bridge_id,
        subject_cn=agent_id,
        role="agent",
        ttl_seconds=session_ttl,
    )

    expires_at = client_cert.not_valid_after_utc

    # ── Store session in Redis ────────────────────────────────────────
    session_info: dict = {
        "user_email": current_user.email,
        "resource_name": resource_name,
        "agent_id": agent_id,
        "bridge_id": bridge_id,
        "protocol": resource_type,
        "status": "pending",
        "created_at": datetime.now(UTC).isoformat(),
        "expires_at": expires_at.isoformat(),
    }
    if original_resource_type:
        session_info["original_resource_type"] = original_resource_type
    session_data = json.dumps(session_info)
    await r.setex(f"session:{session_id}", session_ttl, session_data)

    # Track session in active set for dashboard queries
    await r.sadd("sessions:active", session_id)

    # Increment new bridge tunnel count.
    await r.zincrby("bridges:available", 1, bridge_id)
    await r.hincrby(f"bridge:{bridge_id}", "active_tunnels", 1)

    # ── Notify agent via Redis pub/sub ────────────────────────────────
    bridge_port = settings.bridge_tunnel_port

    # Store client creds in Redis for web terminal WebSocket reconnection.
    # Any API pod can use these to dial the same bridge on WS reconnect.
    # The API always dials the bridge from within the cluster, so use the
    # internal K8s service name (not the external hostname).
    client_cert_pem = serialize_certificate(client_cert).decode()
    client_key_pem = serialize_private_key(client_key).decode()
    api_bridge_host = f"{bridge_id}.{settings.namespace}.svc.cluster.local"
    api_bridge_port = settings.bridge_internal_tunnel_port
    await r.setex(
        f"session:{session_id}:client_creds",
        session_ttl,
        json.dumps(
            {
                "cert": client_cert_pem,
                "key": client_key_pem,
                "ca": ca.ca_cert_pem,
                "bridge_host": api_bridge_host,
                "bridge_port": api_bridge_port,
                "bridge_id": bridge_id,
            }
        ),
    )

    agent_cluster_internal = await r.get(f"agent:{agent_id}:cluster_internal")
    if agent_cluster_internal:
        agent_bridge_host = f"{bridge_id}.{settings.namespace}.svc.cluster.local"
        agent_bridge_port = settings.bridge_internal_tunnel_port
    else:
        agent_bridge_host = bridge_hostname
        agent_bridge_port = bridge_port

    await r.publish(
        f"agent:{agent_id}:commands",
        json.dumps(
            {
                "command": command,
                "session_id": session_id,
                "bridge_host": agent_bridge_host,
                "bridge_port": agent_bridge_port,
                "resource_name": resource_name,
                "resource_type": resource_type,
                "session_cert": serialize_certificate(agent_cert).decode(),
                "session_key": serialize_private_key(agent_key).decode(),
                "ca_certificate": ca.ca_cert_pem,
            }
        ),
    )

    logger.info(
        "Connection initiated",
        user=current_user.email,
        resource=resource_name,
        bridge=bridge_id,
        session_id=session_id,
        command=command,
    )

    await log_audit_event(
        db,
        event_type="access",
        action=audit_action,
        actor_type="user",
        actor_id=current_user.email,
        target_type="resource",
        target_id=resource_name,
        success=True,
        details={
            "bridge_id": bridge_id,
            "session_id": session_id,
        },
    )

    return ConnectResponse(
        bridge_hostname=bridge_hostname,
        bridge_port=bridge_port,
        session_cert=client_cert_pem,
        session_key=client_key_pem,
        ca_certificate=ca.ca_cert_pem,
        session_id=session_id,
        session_expires_at=expires_at,
        resource_type=resource_type,
    )
