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
from starlette.responses import RedirectResponse
from starlette.responses import Response as StarletteResponse

from bamf.api.bridge_relay import (
    RELAY_CONNECT_WAIT_SECONDS,
    assign_relay_bridge,
    build_bridge_relay_url,
    forward_to_bridge,
    send_relay_connect,
)
from bamf.auth.sessions import Session, get_session
from bamf.config import settings
from bamf.db.models import SessionRecording, generate_uuid7
from bamf.db.session import async_session_factory
from bamf.logging_config import get_logger
from bamf.redis.client import get_redis_client
from bamf.services.audit_service import log_audit_event
from bamf.services.resource_catalog import get_resource_by_tunnel_hostname

from .redact import redact_body, redact_headers, redact_query
from .rewrite import rewrite_request_headers, rewrite_response_headers

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
    )

    # Read request body
    body = await request.body()

    # Forward to bridge relay endpoint (timed for http-audit)
    t0 = time.monotonic()
    resp = await forward_to_bridge(
        method=request.method,
        url=bridge_url,
        headers=rewritten,
        body=body,
    )

    # If 502 and we didn't just send relay_connect, try once more
    if resp is not None and resp.status_code == 502 and not needs_relay_connect:
        # Relay connection may have been idle-reaped — trigger reconnect
        await send_relay_connect(r, agent_id, relay_bridge)
        await asyncio.sleep(RELAY_CONNECT_WAIT_SECONDS)
        resp = await forward_to_bridge(
            method=request.method,
            url=bridge_url,
            headers=rewritten,
            body=body,
        )

    # If we just triggered relay_connect and first attempt failed, wait and retry
    if resp is not None and resp.status_code == 502 and needs_relay_connect:
        await asyncio.sleep(RELAY_CONNECT_WAIT_SECONDS)
        resp = await forward_to_bridge(
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
