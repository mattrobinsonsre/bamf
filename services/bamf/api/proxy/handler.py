"""HTTP reverse proxy handler for web application access.

Intercepts requests to *.{tunnel_domain} and proxies them through the
bridge relay to agents. Handles auth, RBAC, header rewriting, and
on-demand relay connection establishment.

Two authentication methods are supported:
- **Session cookie** (``bamf_session``): For browsers accessing web apps.
  Missing/invalid cookie triggers a redirect to the login page.
- **Bearer token** (``Authorization: Bearer {token}``): For kubectl, CLI,
  and other programmatic clients. Missing/invalid token returns 401.

Flow:
1. Extract tunnel hostname from Host header
2. Look up resource by tunnel hostname (Redis reverse index)
3. Authenticate (cookie or Bearer token → Redis session)
4. RBAC check
5. Resolve agent → relay bridge
6. If no relay bridge, assign one and send relay_connect SSE event
7. Rewrite request headers
8. Forward to bridge internal endpoint: http://{bridge}:8080/relay/{agent_id}/{path}
9. Rewrite response headers
10. Return response to browser
"""
# Proxy design: docs/guides/web-apps.md

from __future__ import annotations

import asyncio
import json
from urllib.parse import quote

import httpx
from fastapi import Request, Response
from starlette.responses import RedirectResponse
from starlette.responses import Response as StarletteResponse

from bamf.auth.ca import get_ca
from bamf.auth.sessions import Session, get_session
from bamf.config import settings
from bamf.logging_config import get_logger
from bamf.redis.client import get_redis_client
from bamf.services.resource_catalog import get_resource_by_tunnel_hostname

from .rewrite import rewrite_request_headers, rewrite_response_headers

logger = get_logger(__name__)

# How long to wait for a relay connection to establish after sending relay_connect
RELAY_CONNECT_WAIT_SECONDS = 5

# Bridge internal health/relay port
BRIDGE_INTERNAL_PORT = 8080

# Session cookie name — set on the parent domain so it covers both
# bamf.example.com and *.tunnel.bamf.example.com
SESSION_COOKIE_NAME = "bamf_session"


async def proxy_middleware(request: Request, call_next):
    """Starlette middleware that intercepts proxy requests.

    If the Host header matches *.{tunnel_domain}, handle as a proxy request.
    Otherwise, pass through to normal API/web routes.
    """
    tunnel_domain = settings.tunnel_domain
    if not tunnel_domain:
        return await call_next(request)

    host = request.headers.get("host", "")
    # Strip port if present (e.g., "test-http.tunnel.bamf.local:8443")
    hostname = host.split(":")[0]

    if not hostname.endswith(f".{tunnel_domain}"):
        return await call_next(request)

    # This is a proxy request
    return await handle_proxy_request(request)


async def handle_proxy_request(request: Request) -> Response:
    """Handle a proxied HTTP request to a web application."""
    r = get_redis_client()
    tunnel_domain = settings.tunnel_domain

    # Extract tunnel hostname from Host header
    hostname = request.headers.get("host", "").split(":")[0]
    tunnel_hostname = hostname.removesuffix(f".{tunnel_domain}")

    # Look up resource by tunnel hostname
    resource = await get_resource_by_tunnel_hostname(r, tunnel_hostname)
    if not resource:
        return StarletteResponse(
            content=f"No resource found for '{tunnel_hostname}'",
            status_code=404,
        )

    # Authenticate: try Bearer token first, then session cookie.
    # Browser requests get a redirect to login on failure; API clients get 401.
    session = await _authenticate(request)
    if session is None:
        return _auth_error_response(request)

    # RBAC check (simplified — check access inline)
    # TODO: use rbac_service.check_access() with full DB session
    # For now, allow all authenticated users (matching the plan's initial scope)

    agent_id = resource.agent_id
    if not agent_id:
        return StarletteResponse(content="Resource has no agent", status_code=503)

    # Check agent is online
    agent_status = await r.get(f"agent:{agent_id}:status")
    if not agent_status:
        return StarletteResponse(content="Agent is offline", status_code=503)

    # Resolve relay bridge — get or assign
    relay_bridge = await r.get(f"agent:{agent_id}:relay_bridge")
    needs_relay_connect = relay_bridge is None

    if needs_relay_connect:
        relay_bridge = await _assign_relay_bridge(r, agent_id)
        if relay_bridge is None:
            return StarletteResponse(content="No bridges available", status_code=503)
        await _send_relay_connect(r, agent_id, relay_bridge)

    # Resolve agent name for relay URL — the bridge relay pool is keyed by
    # agent name (cert CN), not UUID.
    agent_name = await r.get(f"agent:{agent_id}:name")
    if not agent_name:
        agent_name = agent_id  # Fallback to UUID

    # Build bridge internal URL using headless service DNS:
    # {pod-name}.{headless-svc}.{namespace}.svc.cluster.local:8080
    headless_svc = settings.bridge_headless_service
    bridge_url = (
        f"http://{relay_bridge}.{headless_svc}.{settings.namespace}.svc.cluster.local"
        f":{BRIDGE_INTERNAL_PORT}/relay/{agent_name}{request.url.path}"
    )
    if request.url.query:
        bridge_url += f"?{request.url.query}"

    # Determine target
    target_protocol = "http"
    target_host = resource.hostname or "localhost"
    target_port = resource.port or 80

    # Rewrite request headers
    client_ip = request.client.host if request.client else "unknown"
    raw_headers = dict(request.headers)
    rewritten = rewrite_request_headers(
        headers=raw_headers,
        tunnel_hostname=tunnel_hostname,
        tunnel_domain=tunnel_domain,
        target_host=target_host,
        target_port=target_port,
        target_protocol=target_protocol,
        user_email=session.email,
        user_roles=session.roles,
        client_ip=client_ip,
    )

    # Read request body
    body = await request.body()

    # Forward to bridge relay endpoint
    resp = await _forward_to_bridge(
        method=request.method,
        url=bridge_url,
        headers=rewritten,
        body=body,
    )

    # If 502 and we didn't just send relay_connect, try once more
    if resp is not None and resp.status_code == 502 and not needs_relay_connect:
        # Relay connection may have been idle-reaped — trigger reconnect
        await _send_relay_connect(r, agent_id, relay_bridge)
        await asyncio.sleep(RELAY_CONNECT_WAIT_SECONDS)
        resp = await _forward_to_bridge(
            method=request.method,
            url=bridge_url,
            headers=rewritten,
            body=body,
        )

    # If we just triggered relay_connect and first attempt failed, wait and retry
    if resp is not None and resp.status_code == 502 and needs_relay_connect:
        await asyncio.sleep(RELAY_CONNECT_WAIT_SECONDS)
        resp = await _forward_to_bridge(
            method=request.method,
            url=bridge_url,
            headers=rewritten,
            body=body,
        )

    if resp is None:
        return StarletteResponse(content="Bridge connection failed", status_code=502)

    if resp.status_code == 502:
        return StarletteResponse(
            content="Relay connection not available — try again shortly",
            status_code=503,
            headers={"Retry-After": "5"},
        )

    # Rewrite response headers
    resp_headers = dict(resp.headers)
    rewritten_resp = rewrite_response_headers(
        headers=resp_headers,
        tunnel_hostname=tunnel_hostname,
        tunnel_domain=tunnel_domain,
        target_host=target_host,
        target_port=target_port,
        target_protocol=target_protocol,
    )

    return Response(
        content=resp.content,
        status_code=resp.status_code,
        headers=rewritten_resp,
    )


async def _authenticate(request: Request) -> Session | None:
    """Authenticate a proxy request via Bearer token or session cookie.

    Returns the Session if valid, None otherwise.
    Priority: Bearer token > session cookie.
    """
    # 1. Try Bearer token (kubectl, CLI, programmatic clients)
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        return await get_session(token)

    # 2. Try session cookie (browsers)
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        return await get_session(token)

    return None


def _is_browser_request(request: Request) -> bool:
    """Heuristic: returns True if the request likely comes from a browser.

    Browsers send Accept headers containing text/html. API clients like
    kubectl, curl (default), and httpx send different Accept values.
    """
    accept = request.headers.get("accept", "")
    return "text/html" in accept


def _auth_error_response(request: Request) -> Response:
    """Return the appropriate error for an unauthenticated proxy request.

    Browsers: redirect to login page with ?redirect back to the original URL.
    API clients: 401 with WWW-Authenticate header.
    """
    if _is_browser_request(request):
        # Reconstruct the original URL the browser was trying to reach.
        # request.url reports http:// because Istio terminates TLS before
        # forwarding to the API pod.  Use the Host header (preserved by
        # Istio) and force https:// since all proxy traffic arrives via the
        # HTTPS gateway listener.
        host = request.headers.get("host", "")
        original_url = f"https://{host}{request.url.path}"
        if request.url.query:
            original_url += f"?{request.url.query}"
        # Redirect to the BAMF login page. callback_base_url is the
        # externally-reachable API/UI URL (e.g., https://bamf.local:8443).
        login_url = (
            f"{settings.auth.callback_base_url}/login" f"?redirect={quote(original_url, safe='')}"
        )
        return RedirectResponse(url=login_url, status_code=302)

    return StarletteResponse(
        content="Authorization required",
        status_code=401,
        headers={"WWW-Authenticate": "Bearer"},
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
    """Assign a bridge for the agent's relay connection.

    Picks the least-loaded bridge from the sorted set and stores
    the assignment in Redis.
    """
    bridges = await r.zrangebyscore("bridges:available", "-inf", "+inf", start=0, num=1)
    if not bridges:
        return None

    bridge_id = bridges[0]

    # Store assignment with agent TTL (refreshed on heartbeat)
    await r.setex(f"agent:{agent_id}:relay_bridge", 180, bridge_id)

    logger.info("Assigned relay bridge", agent_id=agent_id, bridge_id=bridge_id)
    return bridge_id


async def _send_relay_connect(r, agent_id: str, bridge_id: str) -> None:
    """Send a relay_connect SSE event to the agent via Redis pub/sub."""
    # Determine bridge host for the agent
    agent_cluster_internal = await r.get(f"agent:{agent_id}:cluster_internal")
    bridge_info = await r.hgetall(f"bridge:{bridge_id}")
    bridge_hostname = bridge_info.get("hostname", bridge_id)

    if agent_cluster_internal:
        bridge_host = f"{bridge_id}.{settings.namespace}.svc.cluster.local"
        bridge_port = settings.bridge_internal_tunnel_port
    else:
        bridge_host = bridge_hostname
        bridge_port = settings.bridge_tunnel_port

    # Include CA cert so the agent can verify the bridge's certificate.
    # The agent may have joined with a previous CA — always send the current one.
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
