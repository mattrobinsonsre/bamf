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
    This endpoint enqueues a JSON command on a reliable per-instance Redis
    list agent:{agent_id}:instance:{instance_id}:commands (via
    agent_commands.enqueue_agent_command; instance selected by
    select_agent_instance). The SSE endpoint in agents.py drains it (BLPOP)
    and delivers it to the specific Go agent instance — surviving a brief
    agent SSE reconnect rather than being lost like fire-and-forget pub/sub.

    Command payload shape (new connection):
        {"command": "dial", "session_id": "...", "bridge_host": "...",
         "bridge_port": 443, "resource_name": "...", "resource_type": "ssh",
         "session_cert": "-----BEGIN CERTIFICATE-----...",
         "session_key": "-----BEGIN PRIVATE KEY-----...",
         "ca_certificate": "-----BEGIN CERTIFICATE-----..."}

    Command payload shape (reconnect after bridge failure):
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

from bamf.api.agent_commands import build_tunnel_command, enqueue_agent_command
from bamf.api.dependencies import get_current_user
from bamf.api.models.connect import (
    ConnectRequest,
    ConnectResponse,
    EdgeProbeTarget,
    ReevaluateRequest,
    ReevaluateResponse,
)
from bamf.auth.ca import get_ca, serialize_certificate, serialize_private_key
from bamf.auth.sessions import Session
from bamf.config import settings
from bamf.db.session import get_db
from bamf.logging_config import get_logger
from bamf.redis.client import get_redis
from bamf.redis_keys import tunnel_session_creds_key, tunnel_session_key
from bamf.services.audit_service import log_audit_event
from bamf.services.bridge_routing import resolve_agent_bridge_endpoint
from bamf.services.edge_selection import (
    EdgeCandidate,
    get_agent_edge_rtts,
    hop_target,
    select_edge,
)
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


@router.post("/reevaluate", response_model=ReevaluateResponse)
async def reevaluate_session_edge(
    request: ReevaluateRequest,
    r: aioredis.Redis = Depends(get_redis),
    current_user: Session = Depends(get_current_user),
) -> ReevaluateResponse:
    """Ask whether a live tunnel should proactively hop to a better edge (#260).

    Read-only: computes the current best rendezvous edge from the agent-leg
    (Redis) and the client's freshly-measured client-leg, and returns a hop
    target only when it beats the session's current edge by the hysteresis
    margin. No side effects — the CLI acts on the answer by driving the normal
    reconnect (which re-homes both ends, #256). The caller enforces hop-once.
    """
    raw = await r.get(tunnel_session_key(request.session_id))
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found or expired",
        )
    session_data = json.loads(raw)
    if session_data.get("user_email") != current_user.email:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session does not belong to this user",
        )

    current_edge = session_data.get("edge_name")
    agent_id = session_data.get("agent_id")
    if not current_edge or not agent_id:
        return ReevaluateResponse(hop_edge=None)

    agent_rtts = await get_agent_edge_rtts(r, agent_id)
    client_rtts = request.client_edge_rtts
    edges = set(agent_rtts) | set(client_rtts) | {current_edge}
    candidates = [
        EdgeCandidate(
            name=edge,
            has_capacity=await r.zcard(f"bridges:available:{edge}") > 0,
            agent_rtt_ms=agent_rtts.get(edge),
            client_rtt_ms=client_rtts.get(edge),
        )
        for edge in edges
    ]
    return ReevaluateResponse(hop_edge=hop_target(current_edge, candidates))


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

    # ── 4b. Measure-then-commit for recorded / non-migratable sessions ───
    # ssh-audit (and web terminal) sessions terminate at the bridge, so they
    # cannot hop to a better edge later (#260) — a cold client would otherwise be
    # stuck on the agent-nearest *guess* for the session's whole life. When the
    # client can retry (probe_retry_supported), ask it to measure its client-leg
    # and pick the true rendezvous edge before we commit: trade a little setup
    # latency for a permanent optimal placement. Only fires for a non-pinned,
    # non-migratable resource with no client-leg yet and ≥2 edges to choose
    # between; migratable sessions keep the optimistic guess (they hop to fix it).
    if (
        request.probe_retry_supported
        and not resource.edge
        and resource_type in NON_MIGRATABLE_PROTOCOLS
        and not request.client_edge_rtts
    ):
        candidate_edges = await _build_candidate_edges(r, agent_id)
        if candidate_edges:  # ≥2 edges (single-edge → nothing to choose → skip)
            return ConnectResponse(
                bridge_hostname="",
                bridge_port=0,
                session_cert="",
                session_key="",
                ca_certificate="",
                session_id="",
                session_expires_at=datetime.now(UTC),
                resource_type=resource_type,
                candidate_edges=candidate_edges,
                probe_required=True,
            )

    # ── 5. Determine edge for bridge selection ───────────────────
    # Priority: resource pin > measured agent-nearest guess > default.
    # A non-pinned tunnel opens on the edge nearest the *agent* — the leg we
    # already measured for free (#246). This is the optimistic-connect "guess"
    # of measured-latency selection (#119); the client-leg and the seamless hop
    # to the true rendezvous edge follow in later steps. Falls back to the
    # configured default when there is no measurement or no edge with capacity.
    if resource.edge:
        edge_name = resource.edge
    else:
        edge_name = (
            await _select_edge_for_agent(r, agent_id, request.client_edge_rtts)
            or settings.default_edge_name
        )

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
        edge_name=edge_name,
    )


async def _select_edge_for_agent(
    r: aioredis.Redis,
    agent_id: str,
    client_rtts: dict[str, int] | None = None,
) -> str | None:
    """Pick the rendezvous edge for a tunnel among those with a live bridge.

    Combines the agent-leg RTT table (#246, from Redis) with the client-leg
    ``client_rtts`` the CLI measured and sent on this request, and returns the
    edge minimizing ``client + agent`` (:func:`select_edge`). With no client
    legs this degrades to the agent-nearest optimistic-connect guess (#119).

    Returns None when neither leg names any edge, or no measured edge has bridge
    capacity, so the caller falls back to the configured default edge.
    Conservative by design: a non-default edge is only ever chosen when it is
    measured and confirmed to have capacity.
    """
    agent_rtts = await get_agent_edge_rtts(r, agent_id)
    client_rtts = client_rtts or {}
    edges = set(agent_rtts) | set(client_rtts)
    if not edges:
        return None

    candidates = [
        EdgeCandidate(
            name=edge,
            has_capacity=await r.zcard(f"bridges:available:{edge}") > 0,
            agent_rtt_ms=agent_rtts.get(edge),
            client_rtt_ms=client_rtts.get(edge),
        )
        for edge in edges
    ]
    return select_edge(candidates, default_edge=settings.default_edge_name)


async def _build_candidate_edges(r: aioredis.Redis, agent_id: str) -> list[EdgeProbeTarget]:
    """List the edges the client should latency-probe for its client-leg (#119).

    Candidates are the edges the agent relays to (has a measured agent-leg, #246)
    that also have a live bridge; each carries that bridge's public ingress to
    TCP-probe. Returns [] when there is fewer than one alternative to probe
    (single-edge deployments), so a client with one choice never probes.
    """
    agent_rtts = await get_agent_edge_rtts(r, agent_id)
    targets: list[EdgeProbeTarget] = []
    for edge in sorted(agent_rtts):
        bridges = await r.zrangebyscore(f"bridges:available:{edge}", "-inf", "+inf", start=0, num=1)
        if not bridges:
            continue
        info = await r.hgetall(f"bridge:{bridges[0]}")
        host = info.get("hostname")
        if host:
            targets.append(
                EdgeProbeTarget(name=edge, probe_host=host, probe_port=settings.bridge_tunnel_port)
            )
    return targets if len(targets) >= 2 else []


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
    raw = await r.get(tunnel_session_key(session_id))
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
    edge_name = session_data.get("edge_name")

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
        if edge_name:
            await r.zincrby(f"bridges:available:{edge_name}", -1, old_bridge_id)
        await r.hincrby(f"bridge:{old_bridge_id}", "active_tunnels", -1)

    # Re-home the reconnect to the current best edge (#119, step 4a). The CLI
    # sends its measured client-leg on every connect, so a reconnect — which is
    # already re-establishing the tunnel — lands on the true client+agent
    # rendezvous edge instead of pinning to the edge the session first opened on.
    # No fresh measurements (or no better edge) → keep the session's prior edge.
    if request.client_edge_rtts:
        rehomed_edge = await _select_edge_for_agent(r, agent_id, request.client_edge_rtts)
        if rehomed_edge:
            edge_name = rehomed_edge

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
        edge_name=edge_name,
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
    edge_name: str | None = None,
) -> tuple[str, dict[str, str]]:
    """Select the best bridge, optionally excluding one.

    When edge_name is provided, selects from the per-edge sorted
    set (bridges:available:{edge_name}). Falls back to the global
    bridges:available set if no per-edge bridges are found.

    When prefer_low_ordinal is True (used for non-migratable ssh-audit sessions),
    the selector biases toward the lowest-ordinal bridge that is below the
    oversubscription threshold. StatefulSet scale-down removes the highest
    ordinal first, so low-ordinal bridges are the last to be drained.

    Returns (bridge_id, bridge_info_dict).
    Raises HTTPException if no bridges are available.
    """
    # Fetch all candidates (withscores gives us tunnel counts).
    # Try edge-specific pool first, then global.
    bridges_with_scores = None
    if edge_name:
        bridges_with_scores = await r.zrangebyscore(
            f"bridges:available:{edge_name}",
            "-inf",
            "+inf",
            start=0,
            num=50,
            withscores=True,
        )
    if not bridges_with_scores:
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
    edge_name: str | None = None,
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
        edge_name=edge_name,
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
        resource_type=resource_type,
        ttl_seconds=session_ttl,
    )

    agent_cert, agent_key = ca.issue_session_certificate(
        session_id=session_id,
        resource_name=resource_name,
        bridge_id=bridge_id,
        subject_cn=agent_id,
        role="agent",
        resource_type=resource_type,
        ttl_seconds=session_ttl,
    )

    expires_at = client_cert.not_valid_after_utc

    # ── Select agent instance for targeted command routing ───────────
    from bamf.services.agent_instances import increment_instance_tunnels, select_agent_instance

    instance_id = await select_agent_instance(r, agent_id)
    if not instance_id:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="No live agent instances available",
        )

    # ── Store session in Redis ────────────────────────────────────────
    # instance_id is included in the session JSON so tunnel_closed can
    # decrement the correct instance's tunnel count on cleanup.
    session_info: dict = {
        "user_email": current_user.email,
        "resource_name": resource_name,
        "agent_id": agent_id,
        "bridge_id": bridge_id,
        "instance_id": instance_id,
        "protocol": resource_type,
        "status": "pending",
        "created_at": datetime.now(UTC).isoformat(),
        "expires_at": expires_at.isoformat(),
    }
    if original_resource_type:
        session_info["original_resource_type"] = original_resource_type
    # Record the edge the SELECTED bridge is actually in, not the requested
    # edge_name — bridge selection may have fallen back to the global pool when
    # the requested edge had no capacity (#266). We store EXACTLY what the
    # per-edge increment below touches (the bridge's own edge, or nothing), so
    # the reconnect's decrement always lands on the same set. This is also the
    # edge the tunnel truly lives on (what re-homing / reevaluate compare
    # against). No fallback to edge_name: adding the bridge to the requested
    # edge's pool would advertise capacity that isn't there.
    bridge_edge = bridge_info.get("edge")
    if bridge_edge:
        session_info["edge_name"] = bridge_edge
    session_data = json.dumps(session_info)
    await r.setex(tunnel_session_key(session_id), session_ttl, session_data)

    # Track session in active set for dashboard queries
    await r.sadd("sessions:active", session_id)

    # Increment new bridge tunnel count (per-edge set matches what the session
    # stored, so the reconnect decrement lands on the same set).
    await r.zincrby("bridges:available", 1, bridge_id)
    if bridge_edge:
        await r.zincrby(f"bridges:available:{bridge_edge}", 1, bridge_id)
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
        tunnel_session_creds_key(session_id),
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

    agent_bridge_host, agent_bridge_port = await resolve_agent_bridge_endpoint(
        r, agent_id, bridge_id, bridge_hostname
    )

    # Enqueue the command on the selected instance's reliable delivery queue so
    # it survives a brief agent SSE reconnect (see agent_commands).
    await enqueue_agent_command(
        r,
        agent_id,
        instance_id,
        build_tunnel_command(
            command=command,
            session_id=session_id,
            bridge_host=agent_bridge_host,
            bridge_port=agent_bridge_port,
            resource_name=resource_name,
            resource_type=resource_type,
            session_cert=serialize_certificate(agent_cert).decode(),
            session_key=serialize_private_key(agent_key).decode(),
            ca_certificate=ca.ca_cert_pem,
        ),
    )

    # Increment instance tunnel count for load-balancing selection
    await increment_instance_tunnels(r, agent_id, instance_id)

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
        candidate_edges=await _build_candidate_edges(r, agent_id),
    )
