"""Kubernetes proxy router for the standalone proxy service.

Refactored from bamf.api.routers.kube to use api_client instead of direct
Redis/DB access. All auth, RBAC, resource resolution, and relay setup
are delegated to the API via a single authorize() call.

Flow:
1. kubectl sends request to /api/v1/kube/{resource_name}/{path}
2. This router authenticates via Bearer token (session)
3. Single authorize() call handles RBAC + relay setup
4. Forward to bridge relay with X-Forwarded-Email and X-Forwarded-K8s-Groups
5. Agent reads those headers, sets Impersonate-User/Group, forwards to K8s API
"""

from __future__ import annotations

import asyncio
import time

import httpx
import structlog
from fastapi import APIRouter, HTTPException, Request, Response, status
from starlette.websockets import WebSocket

from . import api_client
from .config import settings
from .websocket import ws_handshake, ws_relay

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/kube", tags=["kube"])

# Bridge internal relay port
BRIDGE_INTERNAL_PORT = settings.bridge_internal_port

# Shared httpx client for bridge relay requests
_kube_client: httpx.AsyncClient | None = None


def _get_kube_client() -> httpx.AsyncClient:
    global _kube_client
    if _kube_client is None:
        _kube_client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=300.0, write=30.0, pool=10.0),
            limits=httpx.Limits(
                max_connections=30,
                max_keepalive_connections=10,
                keepalive_expiry=30.0,
            ),
        )
    return _kube_client


@router.api_route(
    "/{resource_name}/{path:path}",
    methods=["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"],
)
async def kube_proxy(
    resource_name: str,
    path: str,
    request: Request,
) -> Response:
    """Proxy a Kubernetes API request through bridge relay to agent."""
    # Extract session token from Authorization header
    session_token = _extract_bearer_token(request)
    if not session_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )

    client_ip = request.client.host if request.client else None

    # Single authorize call to the API
    auth = await api_client.authorize(
        session_token=session_token,
        resource_name=resource_name,
        method=request.method,
        path=f"/{path}",
        source_ip=client_ip,
    )

    if not auth.allowed:
        if auth.reason == "resource_not_found":
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Resource '{resource_name}' not found",
            )
        if auth.reason == "no_session":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        if auth.reason == "access_denied":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied",
            )
        if auth.reason == "relay_unavailable":
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Relay connection not available — please retry",
            )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Proxy error: {auth.reason}",
        )

    resource = auth.resource
    session = auth.session
    relay = auth.relay

    if resource.resource_type != "kubernetes":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Resource '{resource_name}' is not a Kubernetes resource",
        )

    # Resolve kubernetes_groups from session
    k8s_groups = session.kubernetes_groups
    if not k8s_groups:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No Kubernetes groups configured for your roles",
        )

    # Build bridge relay URL
    bridge_url = _build_bridge_relay_url(
        relay.bridge_relay_host, relay.agent_name, f"/{path}", request.url.query
    )

    # Determine target
    target_protocol = "https"
    target_host = resource.hostname or "kubernetes.default.svc"
    target_port = resource.port or 6443

    # Build headers for the bridge relay
    headers = dict(request.headers)
    for h in ("host", "connection", "transfer-encoding", "upgrade"):
        headers.pop(h, None)

    headers["X-Bamf-Target"] = f"{target_protocol}://{target_host}:{target_port}"
    headers["X-Forwarded-Email"] = session.email
    headers["X-Forwarded-K8s-Groups"] = ",".join(k8s_groups)

    body = await request.body()

    # Forward to bridge (with retry on 502)
    client = _get_kube_client()
    resp = await _forward(client, request.method, bridge_url, headers, body)

    for _attempt in range(2):
        if resp is None or resp.status_code != 502:
            break
        # Re-authorize to trigger relay reconnect
        await api_client.authorize(
            session_token=session_token,
            resource_name=resource_name,
            method="GET",
            path="/",
        )
        resp = await _forward(client, request.method, bridge_url, headers, body)

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
    for h in ("transfer-encoding", "connection", "content-length", "content-encoding"):
        resp_headers.pop(h, None)

    return Response(
        content=resp.content,
        status_code=resp.status_code,
        headers=resp_headers,
    )


async def kube_proxy_ws(
    websocket: WebSocket,
    resource_name: str,
    path: str,
) -> None:
    """Proxy a Kubernetes WebSocket request (kubectl exec/attach) through bridge relay."""
    # Authenticate via Bearer token
    session_token = _extract_ws_bearer_token(websocket)
    if not session_token:
        await websocket.close(code=1008, reason="Authentication required")
        return

    client_ip = websocket.client.host if websocket.client else None

    auth = await api_client.authorize(
        session_token=session_token,
        resource_name=resource_name,
        method="WEBSOCKET",
        path=f"/{path}",
        source_ip=client_ip,
    )

    if not auth.allowed:
        reason = auth.reason or "unauthorized"
        if reason == "resource_not_found":
            await websocket.close(code=1008, reason=f"Resource '{resource_name}' not found")
        elif reason == "no_session":
            await websocket.close(code=1008, reason="Authentication required")
        elif reason == "access_denied":
            await websocket.close(code=1003, reason="Access denied")
        else:
            await websocket.close(code=1011, reason=reason)
        return

    resource = auth.resource
    session = auth.session
    relay = auth.relay

    if resource.resource_type != "kubernetes":
        await websocket.close(code=1008, reason=f"Resource '{resource_name}' is not Kubernetes")
        return

    k8s_groups = session.kubernetes_groups
    if not k8s_groups:
        await websocket.close(code=1003, reason="No Kubernetes groups configured")
        return

    # Determine target
    target_protocol = "https"
    target_host = resource.hostname or "kubernetes.default.svc"
    target_port = resource.port or 6443

    # Open raw TCP to bridge
    try:
        reader, writer = await asyncio.open_connection(
            relay.bridge_relay_host, BRIDGE_INTERNAL_PORT
        )
    except Exception as e:
        logger.error("Kube WS: failed to connect to bridge", error=str(e))
        await websocket.close(code=1011, reason="Bridge connection failed")
        return

    # Build relay path
    relay_path = f"/relay/{relay.agent_name}/{path}"
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
            reader, writer, relay_path, ws_headers, subprotocols,
        )
    except RuntimeError as e:
        logger.error("Kube WS: upgrade handshake failed", error=str(e))
        writer.close()
        await websocket.close(code=1011, reason="Upstream upgrade failed")
        return

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

    # Audit: log WebSocket connection start
    asyncio.create_task(
        api_client.log_audit(
            user_email=session.email,
            resource_name=resource_name,
            method="WEBSOCKET",
            path=path,
            status_code=101,
            source_ip=client_ip,
            protocol="websocket",
        )
    )

    t0 = time.monotonic()

    try:
        await ws_relay(websocket, reader, writer, ws_conn)
    except Exception:
        logger.debug("Kube WebSocket relay ended", resource=resource_name)
    finally:
        writer.close()
        duration_ms = round((time.monotonic() - t0) * 1000)
        asyncio.create_task(
            api_client.log_audit(
                user_email=session.email,
                resource_name=resource_name,
                method="WEBSOCKET",
                path=path,
                status_code=101,
                source_ip=client_ip,
                duration_ms=duration_ms,
                action="websocket_closed",
                protocol="websocket",
            )
        )


# ── Helpers ──────────────────────────────────────────────────────────────


def _extract_bearer_token(request: Request) -> str | None:
    """Extract Bearer token from Authorization header."""
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return None


def _extract_ws_bearer_token(websocket: WebSocket) -> str | None:
    """Extract Bearer token from WebSocket headers or query params."""
    auth_header = websocket.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return websocket.query_params.get("token")


def _build_bridge_relay_url(
    bridge_relay_host: str,
    agent_name: str,
    path: str,
    query: str | None = None,
) -> str:
    """Build the internal bridge relay URL."""
    url = f"http://{bridge_relay_host}:{BRIDGE_INTERNAL_PORT}/relay/{agent_name}{path}"
    if query:
        url += f"?{query}"
    return url


async def _forward(
    client: httpx.AsyncClient,
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes,
) -> httpx.Response | None:
    """Forward a request to the bridge relay.

    The URL is constructed from bridge_relay_host, which comes from the
    internal API authorize response (trusted service), not from user input.
    """
    try:
        return await client.request(method=method, url=url, headers=headers, content=body)  # codeql[py/ssrf] URL is from trusted internal API, not user input
    except (httpx.ConnectError, httpx.TimeoutException) as e:
        logger.warning("Bridge connection failed", url=url, error=str(e))
        return None
