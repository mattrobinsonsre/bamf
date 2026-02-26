"""Kubernetes proxy router.

Proxies kubectl/k8s client requests to Kubernetes clusters through the
bridge relay + agent. The agent uses K8s impersonation to authenticate
on behalf of the user.

Flow:
1. kubectl sends request to /api/v1/kube/{resource_name}/{path}
2. This router authenticates via Bearer token (session)
3. RBAC check against the resource
4. Resolve kubernetes_groups from session
5. Forward to bridge relay with X-Forwarded-Email and X-Forwarded-K8s-Groups
6. Agent reads those headers, sets Impersonate-User/Group, forwards to K8s API
"""

from __future__ import annotations

import asyncio
import time

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.websockets import WebSocket

from bamf.api.bridge_relay import (
    assign_relay_bridge,
    build_bridge_relay_url,
    dial_bridge_relay,
    ensure_relay_connected,
    forward_to_bridge,
)
from bamf.api.dependencies import get_current_user
from bamf.api.proxy.websocket import ws_handshake, ws_relay
from bamf.auth.sessions import Session, get_session
from bamf.db.session import async_session_factory, get_db_read
from bamf.logging_config import get_logger
from bamf.redis.client import get_redis_client
from bamf.services.audit_service import log_audit_event
from bamf.services.rbac_service import check_access
from bamf.services.resource_catalog import get_resource

router = APIRouter(prefix="/kube", tags=["kube"])
logger = get_logger(__name__)


@router.api_route(
    "/{resource_name}/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)
async def kube_proxy(
    resource_name: str,
    path: str,
    request: Request,
    current_user: Session = Depends(get_current_user),
    db: AsyncSession = Depends(get_db_read),
) -> Response:
    """Proxy a Kubernetes API request through bridge relay to agent."""
    r = get_redis_client()

    # Look up resource
    resource = await get_resource(r, resource_name)
    if not resource:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Resource '{resource_name}' not found",
        )

    if resource.resource_type != "kubernetes":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Resource '{resource_name}' is not a Kubernetes resource",
        )

    # RBAC check
    allowed = await check_access(db, current_user, resource, current_user.roles)
    if not allowed:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    # Resolve kubernetes_groups from session
    k8s_groups = current_user.kubernetes_groups
    if not k8s_groups:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No Kubernetes groups configured for your roles",
        )

    agent_id = resource.agent_id
    if not agent_id:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Resource has no agent",
        )

    # Check agent is online
    agent_status = await r.get(f"agent:{agent_id}:status")
    if not agent_status:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Agent is offline",
        )

    # Resolve relay bridge — get or assign
    relay_bridge = await r.get(f"agent:{agent_id}:relay_bridge")
    needs_relay_connect = relay_bridge is None

    if needs_relay_connect:
        relay_bridge = await assign_relay_bridge(r, agent_id)
        if relay_bridge is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="No bridges available",
            )
        ready = await ensure_relay_connected(r, agent_id, relay_bridge)
        if not ready:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Relay connection timed out — please retry",
            )

    # Resolve agent name for relay URL
    agent_name = await r.get(f"agent:{agent_id}:name")
    if not agent_name:
        agent_name = agent_id

    # Path is just the K8s API path, no /kube/ prefix.
    # The /kube/{resource_name} prefix is for BAMF's API routing only; the agent
    # forwards the remaining path directly to the K8s API server.
    bridge_url = build_bridge_relay_url(relay_bridge, agent_name, f"/{path}", request.url.query)

    # Determine target
    target_protocol = "https"
    target_host = resource.hostname or "kubernetes.default.svc"
    target_port = resource.port or 6443

    # Build headers for the bridge relay
    headers = dict(request.headers)
    # Remove hop-by-hop headers
    for h in ("host", "connection", "transfer-encoding", "upgrade"):
        headers.pop(h, None)

    # Set target and identity headers
    headers["X-Bamf-Target"] = f"{target_protocol}://{target_host}:{target_port}"
    headers["X-Forwarded-Email"] = current_user.email
    headers["X-Forwarded-K8s-Groups"] = ",".join(k8s_groups)

    # Read request body
    body = await request.body()

    # Forward to bridge (with retry on 502)
    resp = await forward_to_bridge(request.method, bridge_url, headers, body)

    # Retry up to 2 times on 502 (relay dropped or stale assignment)
    for _attempt in range(2):
        if resp is None or resp.status_code != 502:
            break
        await ensure_relay_connected(r, agent_id, relay_bridge)
        resp = await forward_to_bridge(request.method, bridge_url, headers, body)

    if resp is None:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Bridge connection failed",
        )

    if resp.status_code == 502:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Relay connection not available — please retry",
        )

    # Return K8s API response as-is (no header rewriting needed)
    resp_headers = dict(resp.headers)
    # Strip hop-by-hop and framing headers from response.
    # content-length/content-encoding must be stripped because httpx may
    # decompress the body (resp.content is decompressed) while headers
    # still reflect the compressed transfer. Starlette sets these correctly
    # from the actual body.
    for h in ("transfer-encoding", "connection", "content-length", "content-encoding"):
        resp_headers.pop(h, None)

    return Response(
        content=resp.content,
        status_code=resp.status_code,
        headers=resp_headers,
    )


@router.websocket("/{resource_name}/{path:path}")
async def kube_proxy_ws(
    websocket: WebSocket,
    resource_name: str,
    path: str,
) -> None:
    """Proxy a Kubernetes WebSocket request (kubectl exec/attach) through bridge relay."""
    r = get_redis_client()

    # Authenticate via Bearer token in headers or query param
    session = await _authenticate_kube_ws(websocket)
    if session is None:
        await websocket.close(code=1008, reason="Authentication required")
        return

    # Look up resource
    resource = await get_resource(r, resource_name)
    if not resource:
        await websocket.close(code=1008, reason=f"Resource '{resource_name}' not found")
        return

    if resource.resource_type != "kubernetes":
        await websocket.close(code=1008, reason=f"Resource '{resource_name}' is not Kubernetes")
        return

    # RBAC check
    from bamf.db.session import async_session_factory_read

    async with async_session_factory_read() as db:
        allowed = await check_access(db, session, resource, session.roles)
    if not allowed:
        await websocket.close(code=1003, reason="Access denied")
        return

    # Resolve kubernetes_groups
    k8s_groups = session.kubernetes_groups
    if not k8s_groups:
        await websocket.close(code=1003, reason="No Kubernetes groups configured")
        return

    agent_id = resource.agent_id
    if not agent_id:
        await websocket.close(code=1011, reason="Resource has no agent")
        return

    # Check agent is online
    agent_status = await r.get(f"agent:{agent_id}:status")
    if not agent_status:
        await websocket.close(code=1011, reason="Agent is offline")
        return

    # Resolve relay bridge
    relay_bridge = await r.get(f"agent:{agent_id}:relay_bridge")
    if relay_bridge is None:
        relay_bridge = await assign_relay_bridge(r, agent_id)
        if relay_bridge is None:
            await websocket.close(code=1011, reason="No bridges available")
            return
        ready = await ensure_relay_connected(r, agent_id, relay_bridge)
        if not ready:
            await websocket.close(code=1011, reason="Relay connection timed out")
            return

    # Resolve agent name
    agent_name = await r.get(f"agent:{agent_id}:name")
    if not agent_name:
        agent_name = agent_id

    # Determine target
    target_protocol = "https"
    target_host = resource.hostname or "kubernetes.default.svc"
    target_port = resource.port or 6443

    # Open raw TCP to bridge
    try:
        reader, writer = await dial_bridge_relay(relay_bridge)
    except Exception as e:
        logger.error("Kube WS: failed to connect to bridge", error=str(e))
        await websocket.close(code=1011, reason="Bridge connection failed")
        return

    # Build relay path
    relay_path = f"/relay/{agent_name}/{path}"
    if websocket.url.query:
        relay_path += f"?{websocket.url.query}"

    # Build headers
    ws_headers: dict[str, str] = {
        "Host": f"{target_host}:{target_port}",
        "X-Bamf-Target": f"{target_protocol}://{target_host}:{target_port}",
        "X-Forwarded-Email": session.email,
        "X-Forwarded-K8s-Groups": ",".join(k8s_groups),
    }

    # Forward K8s subprotocols (e.g., v4.channel.k8s.io)
    subprotocols = []
    if "sec-websocket-protocol" in websocket.headers:
        subprotocols = [p.strip() for p in websocket.headers["sec-websocket-protocol"].split(",")]

    try:
        ws_conn, negotiated = await ws_handshake(
            reader,
            writer,
            relay_path,
            ws_headers,
            subprotocols,
        )
    except RuntimeError as e:
        logger.error("Kube WS: upgrade handshake failed", error=str(e))
        writer.close()
        await websocket.close(code=1011, reason="Upstream upgrade failed")
        return

    # Accept the ASGI WebSocket
    accept_kwargs: dict = {}
    if negotiated:
        accept_kwargs["subprotocol"] = negotiated
    await websocket.accept(**accept_kwargs)

    logger.info(
        "Kube WebSocket proxy established",
        resource=resource_name,
        user=session.email,
        subprotocol=negotiated,
    )

    # Determine client IP for audit
    client_ip = websocket.client.host if websocket.client else None

    # Audit: log WebSocket connection start
    asyncio.create_task(
        _log_kube_ws_audit(
            user_email=session.email,
            resource_name=resource_name,
            path=path,
            action="access_granted",
            client_ip=client_ip,
        )
    )

    t0 = time.monotonic()

    # Relay frames
    try:
        await ws_relay(websocket, reader, writer, ws_conn)
    except Exception:
        logger.debug("Kube WebSocket relay ended", resource=resource_name)
    finally:
        writer.close()
        duration_ms = round((time.monotonic() - t0) * 1000)
        asyncio.create_task(
            _log_kube_ws_audit(
                user_email=session.email,
                resource_name=resource_name,
                path=path,
                action="websocket_closed",
                client_ip=client_ip,
                duration_ms=duration_ms,
            )
        )


async def _authenticate_kube_ws(websocket: WebSocket) -> Session | None:
    """Authenticate a Kubernetes WebSocket request.

    kubectl sends Bearer token in the Authorization header.
    Also supports token as a query parameter for browser-based tools.
    """
    # 1. Authorization header
    auth_header = websocket.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        return await get_session(auth_header[7:])

    # 2. Query parameter
    token = websocket.query_params.get("token")
    if token:
        return await get_session(token)

    return None


async def _log_kube_ws_audit(
    *,
    user_email: str,
    resource_name: str,
    path: str,
    action: str,
    client_ip: str | None,
    duration_ms: int | None = None,
) -> None:
    """Log an audit event for a Kubernetes WebSocket connection."""
    details: dict = {
        "protocol": "websocket",
        "path": path,
    }
    if duration_ms is not None:
        details["duration_ms"] = duration_ms
    try:
        async with async_session_factory() as db:
            await log_audit_event(
                db,
                event_type="access",
                action=action,
                actor_type="user",
                actor_id=user_email,
                target_type="resource",
                target_id=resource_name,
                actor_ip=client_ip,
                details=details,
                success=True,
            )
            await db.commit()
    except Exception:
        logger.warning(
            "Failed to log kube WebSocket audit event",
            user_email=user_email,
            resource_name=resource_name,
            exc_info=True,
        )
