"""Agent management routes.

Handles agent registration (join), heartbeat, status updates, certificate
renewal, and SSE event delivery. Agent identity is stored in PostgreSQL;
runtime state (labels, resources, online/offline status) in Redis.

Consumers:
    Go agent (pkg/agent/api_client.go):
        POST /api/v1/agents/join           — Join()
        POST /api/v1/agents/{id}/heartbeat — Heartbeat()
        POST /api/v1/agents/{id}/status    — UpdateStatus()
        POST /api/v1/agents/{id}/renew     — RenewCertificate()
    Go agent (pkg/agent/sse.go):
        GET  /api/v1/agents/{id}/events    — SSEClient.Connect()
    Web UI (web/src/app/):
        GET  /api/v1/agents                — agents list page
        GET  /api/v1/agents/{id}           — agent detail

Changes to request/response shapes must be coordinated with the Go
agent code. See contract comments on individual endpoints.
"""

import hashlib
import json
import time
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from uuid import UUID

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.responses import StreamingResponse

from bamf.api.dependencies import (
    AgentIdentity,
    get_agent_identity,
    require_admin,
    require_admin_or_audit,
)
from bamf.api.models.agents import (
    AgentRegisterRequest,
    AgentRegisterResponse,
    AgentResponse,
)
from bamf.api.models.common import BAMFBaseModel, CursorPage, PaginationParams, SuccessResponse
from bamf.auth.ca import (
    get_ca,
    get_certificate_fingerprint,
    serialize_certificate,
    serialize_private_key,
)
from bamf.auth.sessions import Session
from bamf.db.models import Agent, JoinToken
from bamf.db.session import get_db, get_db_read
from bamf.logging_config import get_logger
from bamf.redis.client import get_redis
from bamf.services.audit_service import log_audit_event
from bamf.services.resource_catalog import (
    ResourceInfo,
    get_agent_labels,
    get_agent_resource_count,
    set_agent_labels,
    set_agent_resources,
    set_tunnel_hostnames,
)

router = APIRouter(prefix="/agents", tags=["agents"])
logger = get_logger(__name__)

# Agent heartbeat TTL in Redis (3 missed heartbeats at 60s interval = 180s)
AGENT_TTL_SECONDS = 180


async def resolve_agent_id(agent_id_or_name: str, db: AsyncSession) -> tuple[UUID, Agent]:
    """Resolve an agent identifier (UUID or name) to a UUID and Agent record.

    The Go agent may pass either its UUID or its name (from certificate CN).
    This helper accepts both forms for flexibility.

    Returns:
        Tuple of (agent UUID, Agent model) if found.

    Raises:
        HTTPException 404 if agent not found.
    """
    # Try parsing as UUID first
    try:
        agent_uuid = UUID(agent_id_or_name)
        result = await db.execute(select(Agent).where(Agent.id == agent_uuid))
        agent = result.scalar_one_or_none()
        if agent:
            return agent_uuid, agent
    except ValueError:
        pass  # Not a valid UUID, try as name

    # Try looking up by name
    result = await db.execute(select(Agent).where(Agent.name == agent_id_or_name))
    agent = result.scalar_one_or_none()
    if agent:
        return agent.id, agent

    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Agent not found: {agent_id_or_name}",
    )


# ── Heartbeat request/resource models ─────────────────────────────────


class HeartbeatResource(BAMFBaseModel):
    """A resource reported by an agent in its heartbeat.

    Go contract: maps to heartbeatResource struct in pkg/agent/api_client.go.
    """

    name: str
    resource_type: str
    labels: dict[str, str] = Field(default_factory=dict)
    hostname: str | None = None
    port: int | None = None
    tunnel_hostname: str | None = None


class AgentHeartbeatRequest(BAMFBaseModel):
    """Agent heartbeat request with resource and label reporting.

    Go contract: maps to heartbeatRequest struct in pkg/agent/api_client.go.
    The agent sends resources and labels on every heartbeat tick (default 60s).
    """

    resources: list[HeartbeatResource] = Field(default_factory=list)
    labels: dict[str, str] = Field(default_factory=dict)
    cluster_internal: bool = False


# ── Agent Join (Registration) ────────────────────────────────────────────


@router.post("/join", response_model=AgentRegisterResponse, status_code=status.HTTP_201_CREATED)
async def join_agent(
    request: AgentRegisterRequest,
    db: AsyncSession = Depends(get_db),
    r: aioredis.Redis = Depends(get_redis),
) -> AgentRegisterResponse:
    """Register an agent using a join token.

    Validates the join token, creates the agent in PG, issues a service
    certificate, and sets initial runtime state in Redis.

    Go contract: pkg/agent/api_client.go:Join() reads agent_id, certificate,
    private_key, and ca_certificate from the response JSON. The private_key
    is saved to disk and used for TLS auth + X-Bamf-Client-Cert header.
    """
    # Hash the token to look up in DB
    token_hash = hashlib.sha256(request.join_token.encode()).hexdigest()

    result = await db.execute(select(JoinToken).where(JoinToken.token_hash == token_hash))
    token = result.scalar_one_or_none()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid join token",
        )

    # Validate token state
    now = datetime.now(UTC)

    if token.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Join token has been revoked",
        )

    if token.expires_at < now:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Join token has expired",
        )

    if token.max_uses is not None and token.use_count >= token.max_uses:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Join token has reached maximum uses",
        )

    # Check if agent name already exists
    existing = await db.execute(select(Agent).where(Agent.name == request.name))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Agent with name '{request.name}' already exists",
        )

    # Merge labels: token labels + request labels (request overrides)
    labels = {**token.agent_labels, **request.labels}

    # Issue service certificate for the agent
    ca = get_ca()
    cert, key = ca.issue_service_certificate(
        service_name=request.name,
        service_type="agent",
    )

    # Create agent in PG (durable identity — no labels, those go to Redis)
    agent = Agent(
        name=request.name,
        certificate_fingerprint=get_certificate_fingerprint(cert),
        certificate_expires_at=cert.not_valid_after_utc,
    )
    db.add(agent)

    # Increment token use count
    token.use_count += 1

    await db.flush()

    # Set initial runtime state in Redis
    agent_key = f"agent:{agent.id}:status"
    await r.setex(agent_key, AGENT_TTL_SECONDS, "online")

    # Store labels in Redis
    await set_agent_labels(r, str(agent.id), labels, AGENT_TTL_SECONDS)

    logger.info(
        "Agent registered",
        agent_id=str(agent.id),
        agent_name=agent.name,
        join_token=token.name,
        labels=labels,
    )

    await log_audit_event(
        db,
        event_type="agent",
        action="agent_joined",
        actor_type="agent",
        actor_id=request.name,
        target_type="join_token",
        target_id=token.name,
        success=True,
        details={"labels": labels},
    )

    return AgentRegisterResponse(
        agent_id=agent.id,
        certificate=serialize_certificate(cert).decode(),
        private_key=serialize_private_key(key).decode(),
        certificate_expires_at=cert.not_valid_after_utc,
        ca_certificate=ca.ca_cert_pem,
    )


# ── Agent Heartbeat & Status ────────────────────────────────────────────


@router.post("/{agent_id}/heartbeat", response_model=SuccessResponse)
async def agent_heartbeat(
    agent_id: str,
    body: AgentHeartbeatRequest | None = None,
    db: AsyncSession = Depends(get_db),
    r: aioredis.Redis = Depends(get_redis),
) -> SuccessResponse:
    """Agent heartbeat — refreshes TTL in Redis and updates resource catalog.

    The agent_id can be either a UUID or the agent name (for Go agent compatibility
    when loading cached certificates where the CN contains the name).
    """
    resolved_id, agent = await resolve_agent_id(agent_id, db)
    agent_id_str = str(resolved_id)
    agent_key = f"agent:{agent_id_str}:status"

    # Set/refresh the status key with TTL
    await r.setex(agent_key, AGENT_TTL_SECONDS, "online")

    # Store agent name for relay URL resolution (agent uses name as relay pool key)
    await r.setex(f"agent:{agent_id_str}:name", AGENT_TTL_SECONDS, agent.name)

    # Update last heartbeat timestamp
    await r.set(f"agent:{agent_id_str}:last_heartbeat", str(time.time()))

    # Update labels, resources, and cluster_internal if provided
    if body:
        if body.labels:
            await set_agent_labels(r, agent_id_str, body.labels, AGENT_TTL_SECONDS)

        if body.resources:
            resource_infos = [
                ResourceInfo(
                    name=res.name,
                    resource_type=res.resource_type,
                    labels=res.labels,
                    agent_id=agent_id_str,
                    hostname=res.hostname,
                    port=res.port,
                    tunnel_hostname=res.tunnel_hostname,
                )
                for res in body.resources
            ]
            await set_agent_resources(r, agent_id_str, resource_infos, AGENT_TTL_SECONDS)
            await set_tunnel_hostnames(r, resource_infos, AGENT_TTL_SECONDS)

            # Refresh relay bridge assignment TTL for agents with HTTP resources
            has_http = any(res.resource_type in ("http", "https") for res in body.resources)
            if has_http:
                relay_bridge = await r.get(f"agent:{agent_id_str}:relay_bridge")
                if relay_bridge:
                    # Refresh TTL so it stays alive as long as the agent is healthy
                    await r.expire(f"agent:{agent_id_str}:relay_bridge", AGENT_TTL_SECONDS)

        # Store cluster_internal flag so connect endpoint can route appropriately
        if body.cluster_internal:
            await r.setex(f"agent:{agent_id_str}:cluster_internal", AGENT_TTL_SECONDS, "1")
        else:
            await r.delete(f"agent:{agent_id_str}:cluster_internal")

    return SuccessResponse(message="OK")


@router.post("/{agent_id}/status", response_model=SuccessResponse)
async def update_agent_status(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    r: aioredis.Redis = Depends(get_redis),
) -> SuccessResponse:
    """Update agent status.

    The agent_id can be either a UUID or the agent name.
    """
    resolved_id, _ = await resolve_agent_id(agent_id, db)
    agent_key = f"agent:{resolved_id}:status"
    await r.setex(agent_key, AGENT_TTL_SECONDS, "online")

    return SuccessResponse(message="OK")


# ── Certificate Renewal ────────────────────────────────────────────────


@router.post("/{agent_id}/renew", response_model=AgentRegisterResponse)
async def renew_agent_certificate(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    agent_identity: AgentIdentity = Depends(get_agent_identity),
) -> AgentRegisterResponse:
    """Renew an agent's certificate before it expires.

    Go contract: The agent calls this when its certificate is approaching
    expiry (e.g., 30 days before expiration for 1-year certs). The agent
    authenticates with its current valid certificate via X-Bamf-Client-Cert.

    The response has the same shape as the join response, so the agent can
    use the same code to save the new certificate.

    Args:
        agent_id: Agent UUID or name (must match the certificate's CN).
    """
    # Resolve agent ID and verify it exists
    resolved_id, agent = await resolve_agent_id(agent_id, db)

    # Verify the certificate CN matches the agent
    if agent_identity.name != agent.name:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Certificate CN '{agent_identity.name}' does not match agent '{agent.name}'",
        )

    # Issue a new certificate
    ca = get_ca()
    cert, key = ca.issue_service_certificate(
        service_name=agent.name,
        service_type="agent",
    )

    # Update the database with new certificate info
    agent.certificate_fingerprint = get_certificate_fingerprint(cert)
    agent.certificate_expires_at = cert.not_valid_after_utc
    await db.flush()

    logger.info(
        "Agent certificate renewed",
        agent_id=str(resolved_id),
        agent_name=agent.name,
        old_expires=agent_identity.expires_at.isoformat(),
        new_expires=cert.not_valid_after_utc.isoformat(),
    )

    await log_audit_event(
        db,
        event_type="agent",
        action="certificate_renewed",
        actor_type="agent",
        actor_id=agent.name,
        target_type="agent",
        target_id=str(resolved_id),
        success=True,
        details={
            "old_expires": agent_identity.expires_at.isoformat(),
            "new_expires": cert.not_valid_after_utc.isoformat(),
        },
    )

    return AgentRegisterResponse(
        agent_id=resolved_id,
        certificate=serialize_certificate(cert).decode(),
        private_key=serialize_private_key(key).decode(),
        certificate_expires_at=cert.not_valid_after_utc,
        ca_certificate=ca.ca_cert_pem,
    )


# ── Agent Listing (for admin users) ─────────────────────────────────────


@router.get("", response_model=CursorPage[AgentResponse])
async def list_agents(
    pagination: PaginationParams = Depends(),
    label: list[str] | None = Query(default=None, description="Filter by labels (key=value)"),
    db: AsyncSession = Depends(get_db_read),
    r: aioredis.Redis = Depends(get_redis),
    current_user: Session = Depends(require_admin_or_audit),
) -> CursorPage[AgentResponse]:
    """List all agents with their runtime state from Redis."""
    query = select(Agent).order_by(Agent.name).limit(pagination.limit + 1)

    if pagination.cursor:
        import base64

        cursor_name = base64.b64decode(pagination.cursor).decode()
        query = query.where(Agent.name > cursor_name)

    result = await db.execute(query)
    agents = list(result.scalars().all())

    has_more = len(agents) > pagination.limit
    if has_more:
        agents = agents[: pagination.limit]

    # Parse label filters
    label_filters: dict[str, str] = {}
    if label:
        for lbl in label:
            if "=" in lbl:
                key, value = lbl.split("=", 1)
                label_filters[key] = value

    # Enrich with Redis runtime state and filter by labels
    items = []
    for agent in agents:
        agent_id_str = str(agent.id)
        agent_status = await r.get(f"agent:{agent_id_str}:status") or "offline"
        last_hb_str = await r.get(f"agent:{agent_id_str}:last_heartbeat")
        last_heartbeat = datetime.fromtimestamp(float(last_hb_str), tz=UTC) if last_hb_str else None
        connected_bridge = await r.get(f"agent:{agent_id_str}:bridge")
        agent_labels = await get_agent_labels(r, agent_id_str)
        resource_count = await get_agent_resource_count(r, agent_id_str)

        # Filter by labels (from Redis)
        if label_filters:
            if not all(agent_labels.get(k) == v for k, v in label_filters.items()):
                continue

        items.append(
            AgentResponse.from_db(
                agent,
                resource_count=resource_count,
                labels=agent_labels,
                status=agent_status,
                last_heartbeat=last_heartbeat,
                connected_bridge_id=connected_bridge,
            )
        )

    next_cursor = None
    if has_more and agents:
        import base64

        next_cursor = base64.b64encode(agents[-1].name.encode()).decode()

    return CursorPage(items=items, next_cursor=next_cursor, has_more=has_more)


@router.get("/{agent_id}", response_model=AgentResponse)
async def get_agent(
    agent_id: str,
    db: AsyncSession = Depends(get_db_read),
    r: aioredis.Redis = Depends(get_redis),
    current_user: Session = Depends(require_admin_or_audit),
) -> AgentResponse:
    """Get a single agent with runtime state.

    The agent_id can be either a UUID or the agent name.
    """
    _, agent = await resolve_agent_id(agent_id, db)
    agent_id_str = str(agent.id)
    agent_status = await r.get(f"agent:{agent_id_str}:status") or "offline"
    last_hb_str = await r.get(f"agent:{agent_id_str}:last_heartbeat")
    last_heartbeat = datetime.fromtimestamp(float(last_hb_str), tz=UTC) if last_hb_str else None
    connected_bridge = await r.get(f"agent:{agent_id_str}:bridge")
    agent_labels = await get_agent_labels(r, agent_id_str)
    resource_count = await get_agent_resource_count(r, agent_id_str)

    return AgentResponse.from_db(
        agent,
        resource_count=resource_count,
        labels=agent_labels,
        status=agent_status,
        last_heartbeat=last_heartbeat,
        connected_bridge_id=connected_bridge,
    )


@router.delete("/{agent_id}", response_model=SuccessResponse)
async def delete_agent(
    agent_id: str,
    db: AsyncSession = Depends(get_db),
    r: aioredis.Redis = Depends(get_redis),
    current_user: Session = Depends(require_admin),
) -> SuccessResponse:
    """Delete an agent and revoke its certificate.

    This removes the agent's durable identity from PostgreSQL and clears all
    runtime state from Redis. Any active connections will fail on their next
    heartbeat or API call because the agent no longer exists.

    The agent will need to re-register with a new join token to reconnect.

    Web UI: Called from agents page delete button.
    """
    resolved_id, agent = await resolve_agent_id(agent_id, db)
    agent_id_str = str(resolved_id)
    agent_name = agent.name

    # Send revoke event to kick the agent off its SSE connection
    # The agent will receive this and should disconnect
    await r.publish(
        f"agent:{agent_id_str}:commands",
        json.dumps({"command": "revoke", "reason": "Agent deleted by administrator"}),
    )

    # Clear all Redis state for this agent
    keys_to_delete = [
        f"agent:{agent_id_str}:status",
        f"agent:{agent_id_str}:last_heartbeat",
        f"agent:{agent_id_str}:bridge",
        f"agent:{agent_id_str}:labels",
        f"agent:{agent_id_str}:resources",
    ]
    for key in keys_to_delete:
        await r.delete(key)

    # Delete from PostgreSQL
    await db.delete(agent)

    logger.info(
        "Agent deleted",
        agent_id=agent_id_str,
        agent_name=agent_name,
        deleted_by=current_user.email,
    )

    await log_audit_event(
        db,
        event_type="agent",
        action="agent_deleted",
        actor_type="user",
        actor_id=current_user.email,
        target_type="agent",
        target_id=agent_name,
        success=True,
        details={"agent_id": agent_id_str},
    )

    return SuccessResponse(message=f"Agent '{agent_name}' deleted")


# ── SSE Event Stream ──────────────────────────────────────────────────


@router.get("/{agent_id}/events")
async def agent_events(
    agent_id: str,
    db: AsyncSession = Depends(get_db_read),
    r: aioredis.Redis = Depends(get_redis),
) -> StreamingResponse:
    """SSE stream for delivering tunnel commands to agents.

    Go contract: pkg/agent/sse.go SSEClient.Connect() maintains a persistent
    connection to this endpoint. The agent reads SSE events with:
        event: tunnel_request
        data: {"command":"dial","session_id":"...","bridge_host":"...","bridge_port":3022,
               "resource_name":"...","resource_type":"ssh",
               "session_cert":"-----BEGIN CERTIFICATE-----...",
               "session_key":"-----BEGIN PRIVATE KEY-----...",
               "ca_certificate":"-----BEGIN CERTIFICATE-----..."}

    The session_cert/key/ca_certificate are needed for the agent to connect to
    the bridge with mTLS. Each tunnel gets a unique session cert with SAN URIs
    encoding session_id, resource_name, and bridge_id for authorization.

    The data payload matches what connect.py publishes to Redis pub/sub channel
    agent:{agent_id}:commands. See services/bamf/api/routers/connect.py:178-198.

    Keepalive heartbeats are sent every 30s:
        event: heartbeat
        data: {}

    The agent also sends these headers (which this endpoint should accept):
        Accept: text/event-stream
        User-Agent: bamf-agent/dev
        X-Bamf-Client-Cert: <base64-encoded PEM cert>

    The agent_id can be either a UUID or the agent name (for Go agent compatibility
    when loading cached certificates where the CN contains the name).
    """
    resolved_id, _ = await resolve_agent_id(agent_id, db)
    agent_id_str = str(resolved_id)

    async def event_generator() -> AsyncGenerator[str]:
        from bamf.api.app import shutdown_event

        # Subscribe to the agent's command channel
        pubsub = r.pubsub()
        await pubsub.subscribe(f"agent:{agent_id_str}:commands")

        try:
            keepalive_counter = 0

            while not shutdown_event.is_set():
                # Check for pub/sub messages with 1s timeout, then send
                # keepalive if no message arrived within 30s.
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=1.0)

                if message and message["type"] == "message":
                    data = message["data"]
                    if isinstance(data, bytes):
                        data = data.decode()
                    # Determine SSE event type from the command field
                    event_type = "tunnel_request"
                    try:
                        parsed = json.loads(data)
                        cmd = parsed.get("command", "")
                        if cmd == "relay_connect":
                            event_type = "relay_connect"
                        elif cmd == "revoke":
                            event_type = "revoke"
                    except (json.JSONDecodeError, TypeError):
                        pass
                    yield f"event: {event_type}\ndata: {data}\n\n"
                    keepalive_counter = 0
                else:
                    keepalive_counter += 1
                    # Send heartbeat every ~30 iterations (30s at 1s poll)
                    if keepalive_counter >= 30:
                        yield "event: heartbeat\ndata: {}\n\n"
                        keepalive_counter = 0
        finally:
            await pubsub.unsubscribe(f"agent:{agent_id_str}:commands")
            await pubsub.close()

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable nginx/traefik buffering
        },
    )
