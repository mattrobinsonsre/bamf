"""HTTP reverse proxy handler for web application access.

Refactored from bamf.api.proxy.handler to use the API client instead of
direct Redis/DB access. All auth, RBAC, resource resolution, and relay
setup are delegated to the API via a single authorize() call.
"""

from __future__ import annotations

import asyncio
import json
import time
from urllib.parse import quote

import httpx
import structlog
from fastapi import Request, Response
from starlette.responses import RedirectResponse, StreamingResponse
from starlette.responses import Response as StarletteResponse
from starlette.websockets import WebSocket

from . import api_client
from .config import settings
from .redact import redact_body, redact_headers, redact_query
from .rewrite import (
    rewrite_request_headers,
    rewrite_response_headers,
    rewrite_set_cookie,
    rewrite_webhook_request_headers,
)
from .websocket import ws_handshake, ws_relay

logger = structlog.get_logger(__name__)

SESSION_COOKIE_NAME = "bamf_session"

# Bridge internal relay port
BRIDGE_INTERNAL_PORT = settings.bridge_internal_port

# Shared httpx client for bridge relay requests
_proxy_client: httpx.AsyncClient | None = None


def _get_proxy_client() -> httpx.AsyncClient:
    global _proxy_client
    if _proxy_client is None:
        _proxy_client = httpx.AsyncClient(
            timeout=httpx.Timeout(connect=5.0, read=300.0, write=30.0, pool=10.0),
            limits=httpx.Limits(
                max_connections=30,
                max_keepalive_connections=10,
                keepalive_expiry=30.0,
            ),
        )
    return _proxy_client


# HTTP audit recording constants
HTTP_RECORDING_BODY_MAX = 256 * 1024
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
    """Starlette middleware that intercepts proxy requests."""
    tunnel_domain = settings.tunnel_domain
    if not tunnel_domain:
        return await call_next(request)

    host = request.headers.get("host", "")
    hostname = host.split(":")[0]

    if not hostname.endswith(f".{tunnel_domain}"):
        return await call_next(request)

    # WebSocket upgrades pass through to route matching
    if request.headers.get("upgrade", "").lower() == "websocket":
        return await call_next(request)

    return await handle_proxy_request(request)


async def handle_proxy_request(request: Request) -> Response:
    """Handle a proxied HTTP request to a web application."""
    tunnel_domain = settings.tunnel_domain

    hostname = request.headers.get("host", "").split(":")[0]
    tunnel_hostname = hostname.removesuffix(f".{tunnel_domain}")

    # Extract session token
    session_token = _extract_session_token(request)

    client_ip = request.client.host if request.client else None

    # Single authorize call to the API
    auth = await api_client.authorize(
        session_token=session_token,
        tunnel_hostname=tunnel_hostname,
        method=request.method,
        path=request.url.path,
        source_ip=client_ip,
    )

    if not auth.allowed:
        if auth.reason == "resource_not_found":
            return StarletteResponse(
                content=f"No resource found for '{tunnel_hostname}'",
                status_code=404,
            )

        # Webhook match but relay unavailable
        if auth.webhook_match and auth.reason == "relay_unavailable":
            return StarletteResponse(
                content="Relay connection not available — please retry",
                status_code=503,
                headers={"Retry-After": "2"},
            )

        if auth.reason == "no_session":
            return _auth_error_response(request)

        if auth.reason == "access_denied":
            if _is_browser_request(request):
                return StarletteResponse(
                    content="Access denied — you do not have permission to access this resource",
                    status_code=403,
                )
            return StarletteResponse(content="Access denied", status_code=403)

        if auth.reason == "relay_unavailable":
            return StarletteResponse(
                content="Relay connection not available — please retry",
                status_code=503,
                headers={"Retry-After": "2"},
            )

        # Generic error
        return StarletteResponse(
            content=f"Proxy error: {auth.reason}",
            status_code=502,
        )

    # Handle webhook passthrough
    if auth.webhook_match:
        return await _handle_webhook_request(request, auth, tunnel_hostname, tunnel_domain)

    # Authenticated request
    resource = auth.resource
    session = auth.session
    relay = auth.relay

    bridge_url = _build_bridge_relay_url(
        relay.bridge_relay_host, relay.agent_name, request.url.path, request.url.query
    )

    target_protocol = "http"
    target_host = resource.hostname or "localhost"
    target_port = resource.port or 80

    # Rewrite request headers
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
        display_name=session.display_name,
        kubernetes_groups=session.kubernetes_groups,
        session_token=session_token,
    )

    body = await request.body()

    t0 = time.monotonic()

    resp = await _forward_with_retry(
        request.method,
        bridge_url,
        rewritten,
        body,
        auth=auth,
    )

    if resp is None:
        return StarletteResponse(content="Bridge connection failed", status_code=502)

    if resp.status_code == 502:
        return StarletteResponse(
            content="Relay connection not available — try again shortly",
            status_code=503,
            headers={"Retry-After": "5"},
        )

    set_cookies = [v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie"]
    resp_headers = {k: v for k, v in resp.headers.items() if k.lower() != "set-cookie"}
    rewritten_resp = rewrite_response_headers(
        headers=resp_headers,
        tunnel_hostname=tunnel_hostname,
        tunnel_domain=tunnel_domain,
        target_host=target_host,
        target_port=target_port,
        target_protocol=target_protocol,
    )

    elapsed_ms = round((time.monotonic() - t0) * 1000)

    # Fire-and-forget audit
    asyncio.create_task(
        api_client.log_audit(
            user_email=session.email,
            resource_name=resource.name,
            method=request.method,
            path=request.url.path,
            status_code=resp.status_code,
            source_ip=client_ip,
        )
    )

    content_type = resp.headers.get("content-type", "")
    is_sse = "text/event-stream" in content_type

    if is_sse:
        return StreamingResponse(
            content=_stream_and_close(resp),
            status_code=resp.status_code,
            headers=rewritten_resp,
            media_type="text/event-stream",
        )

    await resp.aread()
    await resp.aclose()

    # HTTP recording for http-audit resources
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

    response = Response(
        content=resp.content,
        status_code=resp.status_code,
        headers=rewritten_resp,
    )
    for cookie in set_cookies:
        response.headers.append(
            "set-cookie",
            rewrite_set_cookie(cookie, target_host, tunnel_hostname, tunnel_domain),
        )
    return response


async def _forward_with_retry(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes,
    *,
    auth: api_client.AuthorizeResult,
) -> httpx.Response | None:
    """Forward to bridge with retry logic."""
    client = _get_proxy_client()

    pool_exhausted = False

    async def _do_stream() -> httpx.Response | None:
        nonlocal pool_exhausted
        try:
            resp = await client.send(
                client.build_request(method=method, url=url, headers=headers, content=body),
                stream=True,
            )
            return resp
        except httpx.ConnectError:
            logger.warning("Bridge connection failed", url=url)
            return None
        except httpx.PoolTimeout:
            logger.warning("Bridge connection pool exhausted", url=url)
            pool_exhausted = True
            return None
        except httpx.TimeoutException:
            logger.warning("Bridge request timed out", url=url)
            return None

    resp = await _do_stream()

    if pool_exhausted:
        global _proxy_client
        if _proxy_client is not None:
            old_client = _proxy_client
            _proxy_client = None
            asyncio.create_task(_close_client(old_client))

    # Retry up to 2 times on failure
    for _attempt in range(2):
        should_retry = resp is None or resp.status_code == 502
        if not should_retry:
            break
        if resp is not None:
            await resp.aclose()
        # Re-authorize to ensure relay is connected
        # (the API's authorize endpoint handles relay_connect internally)
        await api_client.authorize(
            session_token=None,  # Webhook or already-authed
            tunnel_hostname=auth.resource.tunnel_hostname if auth.resource else None,
            resource_name=auth.resource.name if auth.resource else None,
            method="GET",
            path="/",
        )
        resp = await _do_stream()

    return resp


async def _close_client(client: httpx.AsyncClient) -> None:
    try:
        await client.aclose()
    except Exception:  # noqa: BLE001 — best-effort cleanup, errors are not actionable
        pass


async def _stream_and_close(resp: httpx.Response):
    try:
        async for chunk in resp.aiter_bytes():
            yield chunk
    finally:
        await resp.aclose()


async def handle_proxy_websocket(websocket: WebSocket) -> None:
    """Handle a WebSocket proxy request to a web application."""
    tunnel_domain = settings.tunnel_domain

    host = websocket.headers.get("host", "")
    hostname = host.split(":")[0]

    if not tunnel_domain or not hostname.endswith(f".{tunnel_domain}"):
        await websocket.close(code=1008, reason="Not a proxy request")
        return

    tunnel_hostname = hostname.removesuffix(f".{tunnel_domain}")

    # Extract session token from WebSocket
    session_token = _extract_ws_session_token(websocket)
    client_ip = websocket.client.host if websocket.client else None

    auth = await api_client.authorize(
        session_token=session_token,
        tunnel_hostname=tunnel_hostname,
        method="WEBSOCKET",
        path=websocket.url.path,
        source_ip=client_ip,
    )

    if not auth.allowed:
        reason = auth.reason or "unauthorized"
        if reason == "resource_not_found":
            await websocket.close(code=1008, reason=f"No resource for '{tunnel_hostname}'")
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

    target_protocol = "http"
    target_host = resource.hostname or "localhost"
    target_port = resource.port or 80

    target_origin = f"{target_protocol}://{target_host}"
    if target_port and target_port not in (80, 443):
        target_origin += f":{target_port}"

    # Open raw TCP to bridge
    try:
        reader, writer = await asyncio.open_connection(
            relay.bridge_relay_host, BRIDGE_INTERNAL_PORT
        )
    except Exception as e:
        logger.error("WebSocket: failed to connect to bridge", error=str(e))
        await websocket.close(code=1011, reason="Bridge connection failed")
        return

    # Build relay path
    path = websocket.url.path
    if websocket.url.query:
        path += f"?{websocket.url.query}"
    relay_path = f"/relay/{relay.agent_name}{path}"

    # Build headers
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
    if session.display_name:
        ws_headers["X-Forwarded-Preferred-Username"] = session.display_name
    ws_headers["X-Forwarded-Roles"] = ",".join(session.roles)
    if session.kubernetes_groups:
        ws_headers["X-Forwarded-Groups"] = ",".join(session.kubernetes_groups)
    if session_token:
        ws_headers["X-Bamf-Session-Token"] = session_token

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
        logger.error("WebSocket: upgrade handshake failed", error=str(e))
        writer.close()
        await websocket.close(code=1011, reason="Upstream upgrade failed")
        return

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

    # Audit
    asyncio.create_task(
        api_client.log_audit(
            user_email=session.email,
            resource_name=resource.name,
            method="WEBSOCKET",
            path=websocket.url.path,
            status_code=101,
            source_ip=client_ip,
        )
    )

    t0 = time.monotonic()

    try:
        await ws_relay(websocket, reader, writer, ws_conn)
    except Exception:
        logger.debug("WebSocket relay ended", tunnel_hostname=tunnel_hostname)
    finally:
        writer.close()
        duration_ms = round((time.monotonic() - t0) * 1000)
        asyncio.create_task(
            api_client.log_audit(
                user_email=session.email,
                resource_name=resource.name,
                method="WEBSOCKET",
                path=websocket.url.path,
                status_code=101,
                source_ip=client_ip,
                duration_ms=duration_ms,
                action="websocket_closed",
                protocol="websocket",
            )
        )


def _extract_session_token(request: Request) -> str | None:
    """Extract session token from Bearer header or cookie."""
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return request.cookies.get(SESSION_COOKIE_NAME)


def _extract_ws_session_token(websocket: WebSocket) -> str | None:
    """Extract session token from WebSocket request."""
    token = websocket.query_params.get("token")
    if token:
        return token
    auth_header = websocket.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return websocket.cookies.get(SESSION_COOKIE_NAME)


def _is_browser_request(request: Request) -> bool:
    accept = request.headers.get("accept", "")
    return "text/html" in accept


def _auth_error_response(request: Request) -> Response:
    if _is_browser_request(request):
        host = request.headers.get("host", "")
        original_url = f"https://{host}{request.url.path}"
        if request.url.query:
            original_url += f"?{request.url.query}"
        login_url = f"{settings.callback_base_url}/login?redirect={quote(original_url, safe='')}"
        return RedirectResponse(url=login_url, status_code=302)

    return StarletteResponse(
        content="Authorization required",
        status_code=401,
        headers={"WWW-Authenticate": "Bearer"},
    )


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


async def _handle_webhook_request(
    request: Request,
    auth: api_client.AuthorizeResult,
    tunnel_hostname: str,
    tunnel_domain: str,
) -> Response:
    """Handle a webhook passthrough request."""
    resource = auth.resource
    relay = auth.relay

    bridge_url = _build_bridge_relay_url(
        relay.bridge_relay_host, relay.agent_name, request.url.path, request.url.query
    )

    target_protocol = "http"
    target_host = resource.hostname or "localhost"
    target_port = resource.port or 80

    client_ip = request.client.host if request.client else None
    raw_headers = dict(request.headers)
    rewritten = rewrite_webhook_request_headers(
        headers=raw_headers,
        tunnel_hostname=tunnel_hostname,
        tunnel_domain=tunnel_domain,
        target_host=target_host,
        target_port=target_port,
        target_protocol=target_protocol,
        client_ip=client_ip,
    )

    body = await request.body()

    resp = await _forward_with_retry(
        request.method,
        bridge_url,
        rewritten,
        body,
        auth=auth,
    )

    if resp is None:
        return StarletteResponse(content="Bridge connection failed", status_code=502)

    if resp.status_code == 502:
        return StarletteResponse(
            content="Relay connection not available — try again shortly",
            status_code=503,
            headers={"Retry-After": "5"},
        )

    set_cookies = [v for k, v in resp.headers.multi_items() if k.lower() == "set-cookie"]
    resp_headers = {k: v for k, v in resp.headers.items() if k.lower() != "set-cookie"}
    rewritten_resp = rewrite_response_headers(
        headers=resp_headers,
        tunnel_hostname=tunnel_hostname,
        tunnel_domain=tunnel_domain,
        target_host=target_host,
        target_port=target_port,
        target_protocol=target_protocol,
    )

    # Audit
    asyncio.create_task(
        api_client.log_audit(
            resource_name=resource.name,
            method=request.method,
            path=request.url.path,
            status_code=resp.status_code,
            source_ip=client_ip,
            action="webhook_passthrough",
        )
    )

    content_type = resp.headers.get("content-type", "")
    is_sse = "text/event-stream" in content_type

    if is_sse:
        return StreamingResponse(
            content=_stream_and_close(resp),
            status_code=resp.status_code,
            headers=rewritten_resp,
            media_type="text/event-stream",
        )

    await resp.aread()
    await resp.aclose()

    response = Response(
        content=resp.content,
        status_code=resp.status_code,
        headers=rewritten_resp,
    )
    for cookie in set_cookies:
        response.headers.append(
            "set-cookie",
            rewrite_set_cookie(cookie, target_host, tunnel_hostname, tunnel_domain),
        )
    return response


def _is_binary_content_type(content_type: str) -> bool:
    ct = content_type.lower().split(";")[0].strip()
    return any(ct.startswith(prefix) for prefix in _BINARY_CONTENT_TYPES)


def _capture_body(body: bytes, content_type: str) -> dict:
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
    """Store a full HTTP exchange recording for http-audit resources."""
    try:
        req_ct = raw_request_headers.get("content-type", "")
        resp_ct = response.headers.get("content-type", "")

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

        await api_client.store_recording(
            user_email=user_email,
            resource_name=resource_name,
            recording_type="http",
            data=json.dumps(exchange),
        )
    except Exception:
        logger.warning(
            "Failed to store HTTP recording",
            user_email=user_email,
            resource_name=resource_name,
            exc_info=True,
        )
