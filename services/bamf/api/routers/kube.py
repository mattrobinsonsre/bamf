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
import json

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.api.dependencies import get_current_user
from bamf.auth.ca import get_ca
from bamf.auth.sessions import Session
from bamf.config import settings
from bamf.db.session import get_db_read
from bamf.logging_config import get_logger
from bamf.redis.client import get_redis_client
from bamf.services.rbac_service import check_access
from bamf.services.resource_catalog import get_resource

router = APIRouter(prefix="/kube", tags=["kube"])
logger = get_logger(__name__)

# Bridge internal relay port
BRIDGE_INTERNAL_PORT = 8080

# How long to wait for relay connection after sending relay_connect
RELAY_CONNECT_WAIT_SECONDS = 5


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
        relay_bridge = await _assign_relay_bridge(r, agent_id)
        if relay_bridge is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="No bridges available",
            )
        await _send_relay_connect(r, agent_id, relay_bridge)

    # Resolve agent name for relay URL
    agent_name = await r.get(f"agent:{agent_id}:name")
    if not agent_name:
        agent_name = agent_id

    # Build bridge internal URL — path is just the K8s API path, no /kube/ prefix.
    # The /kube/{resource_name} prefix is for BAMF's API routing only; the agent
    # forwards the remaining path directly to the K8s API server.
    headless_svc = settings.bridge_headless_service
    bridge_url = (
        f"http://{relay_bridge}.{headless_svc}.{settings.namespace}.svc.cluster.local"
        f":{BRIDGE_INTERNAL_PORT}/relay/{agent_name}/{path}"
    )
    if request.url.query:
        bridge_url += f"?{request.url.query}"

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

    # Forward to bridge
    resp = await _forward_to_bridge(request.method, bridge_url, headers, body)

    # If 502 and we didn't just send relay_connect, try reconnect
    if resp is not None and resp.status_code == 502 and not needs_relay_connect:
        await _send_relay_connect(r, agent_id, relay_bridge)
        await asyncio.sleep(RELAY_CONNECT_WAIT_SECONDS)
        resp = await _forward_to_bridge(request.method, bridge_url, headers, body)

    # If we just triggered relay_connect and first attempt failed, wait and retry
    if resp is not None and resp.status_code == 502 and needs_relay_connect:
        await asyncio.sleep(RELAY_CONNECT_WAIT_SECONDS)
        resp = await _forward_to_bridge(request.method, bridge_url, headers, body)

    if resp is None:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Bridge connection failed",
        )

    if resp.status_code == 502:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Relay connection not available — try again shortly",
        )

    # Return K8s API response as-is (no header rewriting needed)
    resp_headers = dict(resp.headers)
    # Strip hop-by-hop headers from response
    for h in ("transfer-encoding", "connection"):
        resp_headers.pop(h, None)

    return Response(
        content=resp.content,
        status_code=resp.status_code,
        headers=resp_headers,
    )


async def _forward_to_bridge(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes,
) -> httpx.Response | None:
    """Forward an HTTP request to the bridge relay endpoint."""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            return await client.request(
                method=method,
                url=url,
                headers=headers,
                content=body,
            )
    except httpx.ConnectError:
        logger.warning("Bridge connection failed", url=url)
        return None
    except httpx.TimeoutException:
        logger.warning("Bridge request timed out", url=url)
        return None


async def _assign_relay_bridge(r, agent_id: str) -> str | None:
    """Assign a bridge for the agent's relay connection."""
    bridges = await r.zrangebyscore("bridges:available", "-inf", "+inf", start=0, num=1)
    if not bridges:
        return None

    bridge_id = bridges[0]
    await r.setex(f"agent:{agent_id}:relay_bridge", 180, bridge_id)
    logger.info("Assigned relay bridge", agent_id=agent_id, bridge_id=bridge_id)
    return bridge_id


async def _send_relay_connect(r, agent_id: str, bridge_id: str) -> None:
    """Send a relay_connect SSE event to the agent via Redis pub/sub."""
    agent_cluster_internal = await r.get(f"agent:{agent_id}:cluster_internal")
    bridge_info = await r.hgetall(f"bridge:{bridge_id}")
    bridge_hostname = bridge_info.get("hostname", bridge_id)

    if agent_cluster_internal:
        bridge_host = f"{bridge_id}.{settings.namespace}.svc.cluster.local"
        bridge_port = settings.bridge_internal_tunnel_port
    else:
        bridge_host = bridge_hostname
        bridge_port = settings.bridge_tunnel_port

    ca = get_ca()

    await r.publish(
        f"agent:{agent_id}:commands",
        json.dumps(
            {
                "command": "relay_connect",
                "bridge_host": bridge_host,
                "bridge_port": bridge_port,
                "ca_certificate": ca.ca_cert_pem,
            }
        ),
    )

    logger.info(
        "Sent relay_connect to agent",
        agent_id=agent_id,
        bridge_host=bridge_host,
        bridge_port=bridge_port,
    )
