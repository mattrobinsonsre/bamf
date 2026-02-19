"""Internal routes for bridge management.

These endpoints are called by Go bridge servers, not by end users.
Bridge state is entirely in Redis — no PostgreSQL tables involved.

Redis key patterns:
    bridge:{id}              → hash {hostname, status, active_tunnels, registered_at}
    bridge:{id}:tunnels      → counter (used by sorted set score)
    bridges:available        → sorted set by tunnel count (for least-loaded selection)

Consumers:
    Go bridge (pkg/bridge/api_client.go):
        POST /api/v1/internal/bridges/register        — RegisterBridge()
        POST /api/v1/internal/bridges/{id}/status      — UpdateBridgeStatus()
        POST /api/v1/internal/bridges/{id}/heartbeat   — SendHeartbeat()
        POST /api/v1/internal/sessions/validate        — ValidateSession()
        POST /api/v1/internal/tunnels/establish         — GetAgentConnection()
        POST /api/v1/internal/tunnels/established       — NotifyTunnelEstablished()
        POST /api/v1/internal/tunnels/closed            — NotifyTunnelClosed()
        POST /api/v1/internal/sessions/{id}/recording   — UploadSessionRecording()

Changes to request/response shapes must be coordinated with the Go
bridge code. See contract comments on individual endpoints.
"""

import json
import time

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.api.dependencies import BridgeIdentity, get_bridge_identity
from bamf.api.models.bridges import (
    BridgeBootstrapRequest,
    BridgeBootstrapResponse,
    BridgeHeartbeatRequest,
    BridgeRegisterRequest,
    BridgeStatusRequest,
    DrainRequest,
    DrainResponse,
    SessionRecordingUpload,
    SessionValidateRequest,
    SessionValidateResponse,
    TunnelClosedNotification,
    TunnelEstablishedNotification,
    TunnelEstablishRequest,
    TunnelEstablishResponse,
)
from bamf.api.models.common import SuccessResponse
from bamf.auth.ca import get_ca, get_ssh_host_key_pem, serialize_certificate, serialize_private_key
from bamf.config import settings
from bamf.db.models import SessionRecording
from bamf.db.session import get_db
from bamf.logging_config import get_logger
from bamf.redis.client import get_redis
from bamf.services.audit_service import log_audit_event

router = APIRouter(prefix="/internal", tags=["internal"])
logger = get_logger(__name__)

# Bridge key TTL — if a bridge misses heartbeats for this long, it's gone.
# Heartbeats are every 10s; 3 missed heartbeats = 30s. Use 60s for safety.
BRIDGE_TTL_SECONDS = 60


# ── Bridge Bootstrap ─────────────────────────────────────────────────────


@router.post("/bridges/bootstrap", response_model=BridgeBootstrapResponse)
async def bootstrap_bridge(
    request: BridgeBootstrapRequest,
) -> BridgeBootstrapResponse:
    """Bootstrap a bridge with a certificate.

    Called by bridges on first startup before they have a certificate.
    Authenticates using a bootstrap token mounted from a Kubernetes Secret.

    The bootstrap token is configured via BAMF_BRIDGE_BOOTSTRAP_TOKEN env var.
    In production, this should be a random secret generated per deployment.

    Go contract: pkg/bridge/api_client.go:Bootstrap() sends
    {bridge_id, hostname, bootstrap_token} and receives certificate material.
    """
    # Validate bootstrap token
    expected_token = settings.bridge_bootstrap_token
    if not expected_token:
        logger.error("Bridge bootstrap token not configured")
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Bridge bootstrap not configured",
        )

    if request.bootstrap_token != expected_token:
        logger.warning(
            "Invalid bridge bootstrap token",
            bridge_id=request.bridge_id,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid bootstrap token",
        )

    # Issue bridge certificate — include external, per-pod, and headless FQDNs
    # so agents and the API can connect via any internal hostname.
    dns_names = [request.hostname]
    internal_fqdn = f"{request.bridge_id}.{settings.namespace}.svc.cluster.local"
    if internal_fqdn != request.hostname:
        dns_names.append(internal_fqdn)
    # Headless service FQDN — used by API proxy for relay connections
    if settings.bridge_headless_service:
        headless_fqdn = (
            f"{request.bridge_id}.{settings.bridge_headless_service}"
            f".{settings.namespace}.svc.cluster.local"
        )
        dns_names.append(headless_fqdn)

    ca = get_ca()
    cert, key = ca.issue_service_certificate(
        service_name=request.bridge_id,
        service_type="bridge",
        dns_names=dns_names,
    )

    logger.info(
        "Bridge bootstrapped",
        bridge_id=request.bridge_id,
        hostname=request.hostname,
        expires_at=cert.not_valid_after_utc.isoformat(),
    )

    return BridgeBootstrapResponse(
        certificate=serialize_certificate(cert).decode(),
        private_key=serialize_private_key(key).decode(),
        ca_certificate=ca.ca_cert_pem,
        expires_at=cert.not_valid_after_utc,
        ssh_host_key=get_ssh_host_key_pem(),
    )


# ── Bridge Lifecycle ─────────────────────────────────────────────────────


@router.post("/bridges/register", response_model=SuccessResponse)
async def register_bridge(
    request: BridgeRegisterRequest,
    r: aioredis.Redis = Depends(get_redis),
    bridge: BridgeIdentity = Depends(get_bridge_identity),
) -> SuccessResponse:
    """Register a bridge on startup.

    Creates Redis hash for the bridge and adds it to the available set.

    Go contract: pkg/bridge/api_client.go:RegisterBridge() sends
    {bridge_id, hostname} as JSON body with X-Bamf-Client-Cert header.
    """
    bridge_key = f"bridge:{request.bridge_id}"

    await r.hset(
        bridge_key,
        mapping={
            "hostname": request.hostname,
            "status": "ready",
            "active_tunnels": "0",
            "registered_at": str(time.time()),
        },
    )
    await r.expire(bridge_key, BRIDGE_TTL_SECONDS)

    # Add to available bridges sorted set (score = 0 active tunnels)
    await r.zadd("bridges:available", {request.bridge_id: 0})

    logger.info("Bridge registered", bridge_id=request.bridge_id, hostname=request.hostname)
    return SuccessResponse(message="Registered")


@router.post("/bridges/{bridge_id}/status", response_model=SuccessResponse)
async def update_bridge_status(
    bridge_id: str,
    request: BridgeStatusRequest,
    r: aioredis.Redis = Depends(get_redis),
    bridge: BridgeIdentity = Depends(get_bridge_identity),
) -> SuccessResponse:
    """Update bridge status (e.g., 'draining' on graceful shutdown).

    Go contract: pkg/bridge/api_client.go:UpdateBridgeStatus() sends
    {status} as JSON body with X-Bamf-Client-Cert header.
    """
    bridge_key = f"bridge:{bridge_id}"

    exists = await r.exists(bridge_key)
    if not exists:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Bridge not found")

    await r.hset(bridge_key, "status", request.status)

    # Remove from available set if draining/offline
    if request.status != "ready":
        await r.zrem("bridges:available", bridge_id)
    else:
        # Re-add if going back to ready
        tunnels = int(await r.hget(bridge_key, "active_tunnels") or "0")
        await r.zadd("bridges:available", {bridge_id: tunnels})

    logger.info("Bridge status updated", bridge_id=bridge_id, status=request.status)
    return SuccessResponse(message="Status updated")


@router.post("/bridges/{bridge_id}/heartbeat", response_model=SuccessResponse)
async def bridge_heartbeat(
    bridge_id: str,
    request: BridgeHeartbeatRequest,
    r: aioredis.Redis = Depends(get_redis),
    bridge: BridgeIdentity = Depends(get_bridge_identity),
) -> SuccessResponse:
    """Bridge heartbeat — refreshes TTL and updates tunnel count.

    Go contract: pkg/bridge/api_client.go:SendHeartbeat() sends
    {active_tunnels} as JSON body with X-Bamf-Client-Cert header.
    """
    bridge_key = f"bridge:{bridge_id}"

    exists = await r.exists(bridge_key)
    if not exists:
        # Re-register the bridge — hash expired (API restart, Redis flush, etc.)
        # The bridge is clearly alive since it's sending heartbeats.
        logger.info("Bridge hash expired, re-registering", bridge_id=bridge_id)
        await r.hset(
            bridge_key,
            mapping={
                "hostname": request.hostname or bridge_id,
                "status": "ready",
                "active_tunnels": str(request.active_tunnels),
                "registered_at": str(time.time()),
            },
        )

    # Update tunnel count and refresh TTL
    await r.hset(bridge_key, "active_tunnels", str(request.active_tunnels))
    await r.expire(bridge_key, BRIDGE_TTL_SECONDS)

    # Update sorted set score
    bridge_status = await r.hget(bridge_key, "status")
    if bridge_status == "ready":
        await r.zadd("bridges:available", {bridge_id: request.active_tunnels})

    return SuccessResponse(message="OK")


# ── Session Validation ───────────────────────────────────────────────────


@router.post("/sessions/validate", response_model=SessionValidateResponse)
async def validate_session(
    request: SessionValidateRequest,
    r: aioredis.Redis = Depends(get_redis),
    bridge: BridgeIdentity = Depends(get_bridge_identity),
) -> SessionValidateResponse:
    """Validate a session token.

    Called by the bridge when a client connects. The session was stored
    in Redis by the connect endpoint.

    Go contract: pkg/bridge/api_client.go:ValidateSession() sends
    {session_token} with X-Bamf-Client-Cert header and reads the full
    SessionValidateResponse.
    """
    session_key = f"session:{request.session_token}"
    session_data = await r.get(session_key)

    if not session_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found or expired",
        )

    session = json.loads(session_data)

    return SessionValidateResponse(
        token=request.session_token,
        user_email=session["user_email"],
        resource_name=session["resource_name"],
        agent_id=session["agent_id"],
        protocol=session["protocol"],
        created_at=session["created_at"],
        expires_at=session["expires_at"],
    )


# ── Tunnel Lifecycle ─────────────────────────────────────────────────────


@router.post("/tunnels/establish", response_model=TunnelEstablishResponse)
async def establish_tunnel(
    request: TunnelEstablishRequest,
    r: aioredis.Redis = Depends(get_redis),
    bridge: BridgeIdentity = Depends(get_bridge_identity),
) -> TunnelEstablishResponse:
    """Get agent connection info to establish a tunnel.

    Called by the bridge after validating the client's session.
    Returns the target agent and resource details.

    Go contract: pkg/bridge/api_client.go:GetAgentConnection() sends
    {session_token, agent_id} with X-Bamf-Client-Cert header and reads
    the response into AgentConnectionInfo struct.
    """
    # Look up session for resource/agent details
    session_key = f"session:{request.session_token}"
    session_data = await r.get(session_key)

    if not session_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found or expired",
        )

    session = json.loads(session_data)

    # Look up agent connection info from Redis
    agent_key = f"agent:{request.agent_id}:connection"
    agent_conn = await r.hgetall(agent_key)

    if not agent_conn:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Agent not connected",
        )

    return TunnelEstablishResponse(
        agent_id=request.agent_id,
        agent_name=agent_conn.get("name", ""),
        resource_name=session["resource_name"],
        resource_type=session["protocol"],
        target_host=agent_conn.get("target_host", ""),
        target_port=int(agent_conn.get("target_port", "0")),
        tunnel_token=request.session_token,
    )


@router.post("/tunnels/established", response_model=SuccessResponse)
async def tunnel_established(
    request: TunnelEstablishedNotification,
    r: aioredis.Redis = Depends(get_redis),
    db: AsyncSession = Depends(get_db),
    bridge: BridgeIdentity = Depends(get_bridge_identity),
) -> SuccessResponse:
    """Notification that a tunnel has been established.

    Updates session status, increments bridge tunnel count, and writes an
    audit event recording who connected to what.

    Go contract: pkg/bridge/api_client.go:NotifyTunnelEstablished() sends
    {session_token, tunnel_id} with X-Bamf-Client-Cert header.
    """
    session_key = f"session:{request.session_token}"
    session_data = await r.get(session_key)

    user_email = None
    resource_name = None
    protocol = None

    if session_data:
        session = json.loads(session_data)
        user_email = session.get("user_email")
        resource_name = session.get("resource_name")
        protocol = session.get("protocol")
        session["status"] = "established"
        session["tunnel_id"] = request.tunnel_id
        session["established_at"] = time.time()
        # Extend TTL now that tunnel is active (24h max session)
        await r.setex(session_key, 86400, json.dumps(session))

    # Audit: record that a connection was established
    await log_audit_event(
        db,
        event_type="access",
        action="session_started",
        actor_type="user",
        actor_id=user_email,
        target_type="resource",
        target_id=resource_name,
        details={
            "protocol": protocol,
            "bridge_id": bridge.bridge_id,
            "tunnel_id": request.tunnel_id,
            "session_id": request.session_token,
        },
        success=True,
    )
    await db.commit()

    logger.info(
        "Tunnel established",
        session_token=request.session_token[:8] + "...",
        tunnel_id=request.tunnel_id,
        user_email=user_email,
        resource_name=resource_name,
    )

    return SuccessResponse(message="OK")


@router.post("/tunnels/closed", response_model=SuccessResponse)
async def tunnel_closed(
    request: TunnelClosedNotification,
    r: aioredis.Redis = Depends(get_redis),
    db: AsyncSession = Depends(get_db),
    bridge: BridgeIdentity = Depends(get_bridge_identity),
) -> SuccessResponse:
    """Notification that a tunnel has closed.

    Cleans up session state and writes an audit event with connection
    duration and bytes transferred.

    Go contract: pkg/bridge/api_client.go:NotifyTunnelClosed() sends
    {session_token, tunnel_id, bytes_sent, bytes_received} with
    X-Bamf-Client-Cert header.
    """
    user_email = None
    resource_name = None
    protocol = None
    duration_seconds = None

    # Look up session info for audit
    if request.session_token:
        session_key = f"session:{request.session_token}"
        session_data = await r.get(session_key)
        if session_data:
            session = json.loads(session_data)
            user_email = session.get("user_email")
            resource_name = session.get("resource_name")
            protocol = session.get("protocol")
            established_at = session.get("established_at")
            if established_at:
                duration_seconds = round(time.time() - float(established_at), 1)
            # Clean up session from Redis
            await r.delete(session_key)

        # Remove from active sessions index
        if request.session_token:
            await r.srem("sessions:active", request.session_token)

        # Clean up client credentials (used for web terminal reconnection)
        if request.session_token:
            await r.delete(f"session:{request.session_token}:client_creds")

    # Audit: record that a connection ended
    details: dict = {
        "protocol": protocol,
        "bridge_id": bridge.bridge_id,
        "tunnel_id": request.tunnel_id,
        "session_id": request.session_token,
        "bytes_sent": request.bytes_sent,
        "bytes_received": request.bytes_received,
    }
    if duration_seconds is not None:
        details["duration_seconds"] = duration_seconds

    await log_audit_event(
        db,
        event_type="access",
        action="session_ended",
        actor_type="user",
        actor_id=user_email,
        target_type="resource",
        target_id=resource_name,
        details=details,
        success=True,
    )
    await db.commit()

    logger.info(
        "Tunnel closed",
        tunnel_id=request.tunnel_id,
        user_email=user_email,
        resource_name=resource_name,
        bytes_sent=request.bytes_sent,
        bytes_received=request.bytes_received,
        duration_seconds=duration_seconds,
    )

    return SuccessResponse(message="OK")


# ── Bridge Drain ────────────────────────────────────────────────────


# Only ssh-audit is non-migratable. Database audit tunnels (postgres-audit,
# mysql-audit) use passive byte-stream tapping over a standard tunnel and
# ARE migratable — only the parser state is lost during reconnect.
NON_MIGRATABLE_PROTOCOLS = {"ssh-audit"}


@router.post("/bridges/{bridge_id}/drain", response_model=DrainResponse)
async def drain_bridge(
    bridge_id: str,
    request: DrainRequest,
    r: aioredis.Redis = Depends(get_redis),
    db: AsyncSession = Depends(get_db),
    bridge: BridgeIdentity = Depends(get_bridge_identity),
) -> DrainResponse:
    """Drain tunnels from a bridge during graceful shutdown.

    For each tunnel on the draining bridge:
    - Non-migratable protocols (ssh-audit): skip, return in non_migratable_sessions
    - Migratable protocols: select a new bridge, issue new session certs with the
      SAME session ID, and send a 'redial' command to the agent via Redis pub/sub.

    Go contract: pkg/bridge/api_client.go:RequestDrain() sends
    {tunnels: [{session_token, protocol}]} with X-Bamf-Client-Cert header.
    """
    from bamf.api.routers.connect import _issue_session

    migrated_count = 0
    non_migratable_sessions: list[str] = []
    errors: list[str] = []

    for tunnel_info in request.tunnels:
        session_token = tunnel_info.session_token
        protocol = tunnel_info.protocol

        # Non-migratable: skip migration, keep on current bridge
        if protocol in NON_MIGRATABLE_PROTOCOLS:
            non_migratable_sessions.append(session_token)
            continue

        # Look up session data in Redis
        raw = await r.get(f"session:{session_token}")
        if not raw:
            errors.append(f"Session {session_token[:8]}... not found")
            continue

        session_data = json.loads(raw)
        agent_id = session_data.get("agent_id")
        resource_name = session_data.get("resource_name")
        resource_type = session_data.get("protocol", "ssh")
        user_email = session_data.get("user_email")

        if not agent_id:
            errors.append(f"Session {session_token[:8]}... has no agent_id")
            continue

        # Check agent is still online
        agent_status = await r.get(f"agent:{agent_id}:status")
        if not agent_status:
            errors.append(f"Agent {agent_id} offline for session {session_token[:8]}...")
            continue

        # Decrement old bridge tunnel count
        await r.zincrby("bridges:available", -1, bridge_id)
        await r.hincrby(f"bridge:{bridge_id}", "active_tunnels", -1)

        try:
            # Create a minimal Session-like object for _issue_session
            from datetime import UTC, datetime

            from bamf.auth.sessions import Session

            now = datetime.now(UTC).isoformat()
            fake_session = Session(
                email=user_email or "",
                display_name="",
                roles=[],
                provider_name="internal",
                created_at=now,
                expires_at=now,
                last_active_at=now,
                token="drain-internal",
            )

            await _issue_session(
                db=db,
                r=r,
                current_user=fake_session,
                session_id=session_token,
                resource_name=resource_name,
                resource_type=resource_type,
                agent_id=agent_id,
                exclude_bridge_id=bridge_id,
                session_ttl=300,  # 5 minutes for reconnect
                command="redial",
                audit_action="session_migrated",
            )
            migrated_count += 1
        except Exception as e:
            errors.append(f"Failed to migrate {session_token[:8]}...: {e!s}")

    logger.info(
        "Bridge drain processed",
        bridge_id=bridge_id,
        migrated=migrated_count,
        non_migratable=len(non_migratable_sessions),
        errors=len(errors),
    )

    return DrainResponse(
        migrated_count=migrated_count,
        non_migratable_sessions=non_migratable_sessions,
        errors=errors,
    )


# ── Session Recordings ──────────────────────────────────────────────────


@router.post("/sessions/{session_id}/recording", response_model=SuccessResponse)
async def upload_session_recording(
    session_id: str,
    request: SessionRecordingUpload,
    r: aioredis.Redis = Depends(get_redis),
    db: AsyncSession = Depends(get_db),
    bridge: BridgeIdentity = Depends(get_bridge_identity),
) -> SuccessResponse:
    """Upload an SSH session recording from the bridge.

    Called by the bridge after an ssh-audit session completes. The bridge
    sends the asciicast v2 recording data for storage in PostgreSQL.

    Go contract: pkg/bridge/api_client.go:UploadSessionRecording() sends
    {format, data} with X-Bamf-Client-Cert header.
    """
    import uuid as _uuid

    # Look up session info from Redis (may already be cleaned up)
    user_email = "unknown"
    resource_name = "unknown"
    session_key = f"session:{session_id}"
    session_data = await r.get(session_key)
    if session_data:
        session = json.loads(session_data)
        user_email = session.get("user_email", "unknown")
        resource_name = session.get("resource_name", "unknown")

    # Infer recording_type from format if not explicitly set
    recording_type = request.recording_type
    if not recording_type:
        recording_type = "terminal" if request.format == "asciicast-v2" else "queries"

    # Store recording in PostgreSQL
    recording = SessionRecording(
        session_id=_uuid.UUID(session_id) if len(session_id) == 36 else _uuid.uuid4(),
        user_email=user_email,
        resource_name=resource_name,
        recording_data=request.data,
        recording_type=recording_type,
    )
    db.add(recording)

    # Audit: record that a session recording was stored
    await log_audit_event(
        db,
        event_type="access",
        action="recording_stored",
        actor_type="system",
        actor_id=bridge.bridge_id,
        target_type="resource",
        target_id=resource_name,
        details={
            "session_id": session_id,
            "user_email": user_email,
            "format": request.format,
            "size_bytes": len(request.data),
        },
        success=True,
    )
    await db.commit()

    logger.info(
        "Session recording stored",
        session_id=session_id[:16] + "...",
        user_email=user_email,
        resource_name=resource_name,
        size_bytes=len(request.data),
    )

    return SuccessResponse(message="Recording stored")
