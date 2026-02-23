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
import time
from datetime import UTC, datetime
from urllib.parse import quote

import httpx
from fastapi import Request, Response
from starlette.responses import RedirectResponse, StreamingResponse
from starlette.responses import Response as StarletteResponse
from starlette.websockets import WebSocket

from bamf.api.bridge_relay import (
    RELAY_CONNECT_WAIT_SECONDS,
    assign_relay_bridge,
    build_bridge_relay_url,
    dial_bridge_relay,
    send_relay_connect,
)
from bamf.auth.sessions import Session, get_session
from bamf.config import settings
from bamf.db.models import SessionRecording, generate_uuid7
from bamf.db.session import async_session_factory, async_session_factory_read
from bamf.logging_config import get_logger
from bamf.redis.client import get_redis_client
from bamf.services.audit_service import log_audit_event
from bamf.services.rbac_service import check_access
from bamf.services.resource_catalog import get_resource_by_tunnel_hostname

from .redact import redact_body, redact_headers, redact_query
from .rewrite import rewrite_request_headers, rewrite_response_headers
from .websocket import ws_handshake, ws_relay

logger = get_logger(__name__)

# Session cookie name — set on the parent domain so it covers both
# bamf.example.com and *.tunnel.bamf.example.com
SESSION_COOKIE_NAME = "bamf_session"

# HTTP audit recording constants
HTTP_RECORDING_BODY_MAX = 256 * 1024  # 256KB cap per body
_BINARY_CONTENT_TYPES = frozenset(
    {
        "image/",
        "audio/",
        "video/",
        "font/",
        "application/octet-stream",
        "application/zip",
        "application/gzip",
        "application/pdf",
        "application/wasm",
    }
)


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

    # RBAC check — verify user's roles grant access to this resource
    async with async_session_factory_read() as db:
        allowed = await check_access(db, session, resource, session.roles)
    if not allowed:
        logger.info(
            "Proxy access denied",
            user=session.email,
            resource=resource.name,
            tunnel_hostname=tunnel_hostname,
        )
        if _is_browser_request(request):
            return StarletteResponse(
                content="Access denied — you do not have permission to access this resource",
                status_code=403,
            )
        return StarletteResponse(content="Access denied", status_code=403)

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
        relay_bridge = await assign_relay_bridge(r, agent_id)
        if relay_bridge is None:
            return StarletteResponse(content="No bridges available", status_code=503)
        await send_relay_connect(r, agent_id, relay_bridge)

    # Resolve agent name for relay URL — the bridge relay pool is keyed by
    # agent name (cert CN), not UUID.
    agent_name = await r.get(f"agent:{agent_id}:name")
    if not agent_name:
        agent_name = agent_id  # Fallback to UUID

    bridge_url = build_bridge_relay_url(
        relay_bridge, agent_name, request.url.path, request.url.query
    )

    # Determine target
    target_protocol = "http"
    target_host = resource.hostname or "localhost"
    target_port = resource.port or 80

    # Rewrite request headers
    client_ip = request.client.host if request.client else None
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
        kubernetes_groups=session.kubernetes_groups,
    )

    # Read request body
    body = await request.body()

    # Forward to bridge relay endpoint (timed for http-audit)
    t0 = time.monotonic()

    # For streaming responses, use httpx streaming to avoid buffering
    resp = await _forward_with_retry(
        request.method,
        bridge_url,
        rewritten,
        body,
        r=r,
        agent_id=agent_id,
        relay_bridge=relay_bridge,
        needs_relay_connect=needs_relay_connect,
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

    elapsed_ms = round((time.monotonic() - t0) * 1000)

    # Audit: log the proxied HTTP request
    client_ip = request.client.host if request.client else None
    asyncio.create_task(
        _log_proxy_audit(
            user_email=session.email,
            resource_name=resource.name,
            method=request.method,
            path=request.url.path,
            status_code=resp.status_code,
            client_ip=client_ip,
        )
    )

    # Check if this is a streaming response (SSE, chunked without Content-Length)
    content_type = resp.headers.get("content-type", "")
    is_streaming = "text/event-stream" in content_type or (
        resp.headers.get("transfer-encoding", "").lower() == "chunked"
        and "content-length" not in resp.headers
    )

    if is_streaming:
        # Return a streaming response — iterate over chunks
        return StreamingResponse(
            content=resp.aiter_bytes(),
            status_code=resp.status_code,
            headers=rewritten_resp,
            media_type=content_type.split(";")[0].strip() if content_type else None,
        )

    # Buffered response — read full body
    await resp.aread()

    # Full HTTP recording for http-audit resources
    if resource.resource_type == "http-audit":
        asyncio.create_task(
            _store_http_recording(
                user_email=session.email,
                resource_name=resource.name,
                request=request,
                request_body=body,
                raw_request_headers=raw_headers,
                response=resp,
                duration_ms=elapsed_ms,
            )
        )

    return Response(
        content=resp.content,
        status_code=resp.status_code,
        headers=rewritten_resp,
    )


async def _forward_with_retry(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes,
    *,
    r,
    agent_id: str,
    relay_bridge: str,
    needs_relay_connect: bool,
) -> httpx.Response | None:
    """Forward to bridge with retry logic, returning a streaming-capable response.

    Uses httpx stream mode so the caller can choose to iterate the body
    (for SSE/chunked) or read it all at once (for buffered responses).
    """
    client = httpx.AsyncClient(timeout=httpx.Timeout(connect=5.0, read=300.0, write=30.0, pool=5.0))

    async def _do_stream() -> httpx.Response | None:
        try:
            resp = await client.send(
                client.build_request(method=method, url=url, headers=headers, content=body),
                stream=True,
            )
            return resp
        except httpx.ConnectError:
            logger.warning("Bridge connection failed", url=url)
            return None
        except httpx.TimeoutException:
            logger.warning("Bridge request timed out", url=url)
            return None

    resp = await _do_stream()

    # If 502 and we didn't just send relay_connect, try once more
    if resp is not None and resp.status_code == 502 and not needs_relay_connect:
        await resp.aclose()
        await send_relay_connect(r, agent_id, relay_bridge)
        await asyncio.sleep(RELAY_CONNECT_WAIT_SECONDS)
        resp = await _do_stream()

    # If we just triggered relay_connect and first attempt failed, wait and retry
    if resp is not None and resp.status_code == 502 and needs_relay_connect:
        await resp.aclose()
        await asyncio.sleep(RELAY_CONNECT_WAIT_SECONDS)
        resp = await _do_stream()

    return resp


async def handle_proxy_websocket(websocket: WebSocket) -> None:
    """Handle a WebSocket proxy request to a web application.

    The browser sends a WebSocket upgrade to *.tunnel.domain. We authenticate,
    check RBAC, then open a raw TCP connection to the bridge and relay
    WebSocket frames bidirectionally using wsproto.
    """
    r = get_redis_client()
    tunnel_domain = settings.tunnel_domain

    # Extract tunnel hostname from Host header
    host = websocket.headers.get("host", "")
    hostname = host.split(":")[0]

    if not tunnel_domain or not hostname.endswith(f".{tunnel_domain}"):
        await websocket.close(code=1008, reason="Not a proxy request")
        return

    tunnel_hostname = hostname.removesuffix(f".{tunnel_domain}")

    # Look up resource
    resource = await get_resource_by_tunnel_hostname(r, tunnel_hostname)
    if not resource:
        await websocket.close(code=1008, reason=f"No resource for '{tunnel_hostname}'")
        return

    # Authenticate: try Bearer token from query param, then session cookie
    session = await _authenticate_websocket(websocket)
    if session is None:
        await websocket.close(code=1008, reason="Authentication required")
        return

    # RBAC check
    async with async_session_factory_read() as db:
        allowed = await check_access(db, session, resource, session.roles)
    if not allowed:
        await websocket.close(code=1003, reason="Access denied")
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
        await send_relay_connect(r, agent_id, relay_bridge)
        await asyncio.sleep(RELAY_CONNECT_WAIT_SECONDS)

    # Resolve agent name
    agent_name = await r.get(f"agent:{agent_id}:name")
    if not agent_name:
        agent_name = agent_id

    # Determine target
    target_protocol = "http"
    target_host = resource.hostname or "localhost"
    target_port = resource.port or 80

    target_origin = f"{target_protocol}://{target_host}"
    if target_port and target_port not in (80, 443):
        target_origin += f":{target_port}"

    # Open raw TCP to bridge internal relay port
    try:
        reader, writer = await dial_bridge_relay(relay_bridge)
    except Exception as e:
        logger.error("WebSocket: failed to connect to bridge", error=str(e))
        await websocket.close(code=1011, reason="Bridge connection failed")
        return

    # Build relay path
    path = websocket.url.path
    if websocket.url.query:
        path += f"?{websocket.url.query}"
    relay_path = f"/relay/{agent_name}{path}"

    # Build headers for the upgrade request through the bridge
    ws_headers: dict[str, str] = {}
    if target_port and target_port not in (80, 443):
        ws_headers["Host"] = f"{target_host}:{target_port}"
    else:
        ws_headers["Host"] = target_host
    ws_headers["X-Bamf-Target"] = target_origin
    ws_headers["X-Bamf-Resource"] = tunnel_hostname
    ws_headers["X-Forwarded-Host"] = f"{tunnel_hostname}.{tunnel_domain}"
    ws_headers["X-Forwarded-Proto"] = "https"
    ws_headers["X-Forwarded-User"] = session.email
    ws_headers["X-Forwarded-Email"] = session.email
    ws_headers["X-Forwarded-Roles"] = ",".join(session.roles)
    if session.kubernetes_groups:
        ws_headers["X-Forwarded-Groups"] = ",".join(session.kubernetes_groups)

    # Forward Sec-WebSocket-Protocol from browser if present
    subprotocols = []
    if "sec-websocket-protocol" in websocket.headers:
        subprotocols = [p.strip() for p in websocket.headers["sec-websocket-protocol"].split(",")]

    try:
        negotiated = await ws_handshake(
            reader,
            writer,
            relay_path,
            ws_headers,
            subprotocols,
        )
    except RuntimeError as e:
        logger.error("WebSocket: upgrade handshake failed", error=str(e))
        writer.close()
        await websocket.close(code=1011, reason="Upstream upgrade failed")
        return

    # Accept the ASGI WebSocket
    accept_kwargs: dict = {}
    if negotiated:
        accept_kwargs["subprotocol"] = negotiated
    await websocket.accept(**accept_kwargs)

    logger.info(
        "WebSocket proxy established",
        tunnel_hostname=tunnel_hostname,
        user=session.email,
        subprotocol=negotiated,
    )

    # Determine client IP for audit
    client_ip = websocket.client.host if websocket.client else None

    # Audit: log WebSocket connection start
    asyncio.create_task(
        _log_proxy_audit(
            user_email=session.email,
            resource_name=resource.name,
            method="WEBSOCKET",
            path=websocket.url.path,
            status_code=101,
            client_ip=client_ip,
        )
    )

    t0 = time.monotonic()

    # Relay frames
    try:
        await ws_relay(websocket, reader, writer)
    except Exception:
        logger.debug("WebSocket relay ended", tunnel_hostname=tunnel_hostname)
    finally:
        writer.close()
        duration_ms = round((time.monotonic() - t0) * 1000)
        asyncio.create_task(
            _log_ws_close_audit(
                user_email=session.email,
                resource_name=resource.name,
                path=websocket.url.path,
                client_ip=client_ip,
                duration_ms=duration_ms,
            )
        )


async def _authenticate_websocket(websocket: WebSocket) -> Session | None:
    """Authenticate a WebSocket proxy request.

    Tries: Bearer token from query param, then session cookie.
    """
    # 1. Try token from query parameter (kubectl, programmatic clients)
    token = websocket.query_params.get("token")
    if token:
        return await get_session(token)

    # 2. Try Bearer token from Authorization header
    auth_header = websocket.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        return await get_session(auth_header[7:])

    # 3. Try session cookie
    cookie_token = websocket.cookies.get(SESSION_COOKIE_NAME)
    if cookie_token:
        return await get_session(cookie_token)

    return None


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
            f"{settings.auth.callback_base_url}/login?redirect={quote(original_url, safe='')}"
        )
        return RedirectResponse(url=login_url, status_code=302)

    return StarletteResponse(
        content="Authorization required",
        status_code=401,
        headers={"WWW-Authenticate": "Bearer"},
    )


async def _log_proxy_audit(
    *,
    user_email: str,
    resource_name: str,
    method: str,
    path: str,
    status_code: int,
    client_ip: str | None,
) -> None:
    """Log an audit event for a proxied HTTP request.

    Runs as a background task so it doesn't slow down the response.
    """
    try:
        async with async_session_factory() as db:
            await log_audit_event(
                db,
                event_type="access",
                action="access_granted",
                actor_type="user",
                actor_id=user_email,
                target_type="resource",
                target_id=resource_name,
                actor_ip=client_ip,
                details={
                    "protocol": "http",
                    "method": method,
                    "path": path,
                    "status_code": status_code,
                },
                success=status_code < 500,
            )
            await db.commit()
    except Exception:
        logger.warning(
            "Failed to log proxy audit event",
            user_email=user_email,
            resource_name=resource_name,
            exc_info=True,
        )


async def _log_ws_close_audit(
    *,
    user_email: str,
    resource_name: str,
    path: str,
    client_ip: str | None,
    duration_ms: int,
) -> None:
    """Log an audit event when a WebSocket proxy connection closes."""
    try:
        async with async_session_factory() as db:
            await log_audit_event(
                db,
                event_type="access",
                action="websocket_closed",
                actor_type="user",
                actor_id=user_email,
                target_type="resource",
                target_id=resource_name,
                actor_ip=client_ip,
                details={
                    "protocol": "websocket",
                    "path": path,
                    "duration_ms": duration_ms,
                },
                success=True,
            )
            await db.commit()
    except Exception:
        logger.warning(
            "Failed to log WebSocket close audit event",
            user_email=user_email,
            resource_name=resource_name,
            exc_info=True,
        )


def _is_binary_content_type(content_type: str) -> bool:
    """Return True if the content type indicates binary data."""
    ct = content_type.lower().split(";")[0].strip()
    return any(ct.startswith(prefix) for prefix in _BINARY_CONTENT_TYPES)


def _capture_body(body: bytes, content_type: str) -> dict:
    """Capture body for HTTP recording, respecting size cap and binary detection."""
    if _is_binary_content_type(content_type):
        return {"body": None, "body_size": len(body), "body_truncated": False}

    if len(body) > HTTP_RECORDING_BODY_MAX:
        return {
            "body": body[:HTTP_RECORDING_BODY_MAX].decode("utf-8", errors="replace"),
            "body_truncated": True,
        }

    return {
        "body": body.decode("utf-8", errors="replace") if body else "",
        "body_truncated": False,
    }


async def _store_http_recording(
    *,
    user_email: str,
    resource_name: str,
    request: Request,
    request_body: bytes,
    raw_request_headers: dict[str, str],
    response: httpx.Response,
    duration_ms: int,
) -> None:
    """Store a full HTTP exchange recording for http-audit resources.

    Runs as a background task so it doesn't slow down the response.
    """
    try:
        req_ct = raw_request_headers.get("content-type", "")
        resp_ct = response.headers.get("content-type", "")

        # Filter out proxy-internal and hop-by-hop headers from recorded headers
        skip_headers = {"host", "connection", "transfer-encoding", "keep-alive"}
        req_headers = redact_headers(
            {k: v for k, v in raw_request_headers.items() if k.lower() not in skip_headers}
        )
        resp_headers = redact_headers(
            {k: v for k, v in response.headers.items() if k.lower() not in skip_headers}
        )

        req_body_info = _capture_body(request_body, req_ct)
        if req_body_info.get("body"):
            req_body_info["body"] = redact_body(req_body_info["body"], req_ct)

        resp_body_info = _capture_body(response.content, resp_ct)
        if resp_body_info.get("body"):
            resp_body_info["body"] = redact_body(resp_body_info["body"], resp_ct)

        query = redact_query(request.url.query or "")

        exchange = {
            "version": 1,
            "request": {
                "method": request.method,
                "path": request.url.path,
                "query": query,
                "headers": req_headers,
                **req_body_info,
            },
            "response": {
                "status": response.status_code,
                "headers": resp_headers,
                **resp_body_info,
            },
            "timing": {
                "duration_ms": duration_ms,
            },
        }

        now = datetime.now(UTC)
        recording_id = generate_uuid7()
        recording = SessionRecording(
            id=recording_id,
            session_id=recording_id,  # HTTP recordings are per-request; session_id = id
            user_email=user_email,
            resource_name=resource_name,
            recording_data=json.dumps(exchange),
            recording_type="http",
            started_at=now,
            ended_at=now,
        )

        async with async_session_factory() as db:
            db.add(recording)
            await db.commit()
    except Exception:
        logger.warning(
            "Failed to store HTTP recording",
            user_email=user_email,
            resource_name=resource_name,
            exc_info=True,
        )
