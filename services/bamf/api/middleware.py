"""API self-audit middleware.

Records all BAMF API request/response exchanges in http-exchange-v1 format,
stored in the audit_logs table with event_type="api". Uses the central
redaction module to ensure sensitive data is never persisted.
"""

from __future__ import annotations

import asyncio
import time

from fastapi import Request, Response
from starlette.responses import StreamingResponse

from bamf.config import settings
from bamf.db.session import async_session_factory
from bamf.logging_config import get_logger
from bamf.services.audit_service import log_audit_event

from .proxy.redact import redact_body, redact_headers, redact_query

logger = get_logger(__name__)

# Paths excluded from API audit (high-frequency, no security value)
_EXCLUDED_PREFIXES = (
    "/health",
    "/ready",
    "/api/docs",
    "/api/redoc",
    "/api/openapi.json",
    "/metrics",
)


def _is_excluded(path: str) -> bool:
    """Return True if the path should be excluded from API audit."""
    return any(path.startswith(prefix) for prefix in _EXCLUDED_PREFIXES)


async def api_audit_middleware(request: Request, call_next):
    """Middleware that records API request/response exchanges for audit.

    Skips excluded paths (health, docs, metrics) and proxy requests
    (which have their own audit in the proxy handler).
    """
    if not settings.audit.api_audit_enabled:
        return await call_next(request)

    if _is_excluded(request.url.path):
        return await call_next(request)

    # Skip proxy requests — they are audited by the proxy handler.
    # Proxy requests have Host headers matching *.tunnel_domain.
    tunnel_domain = settings.tunnel_domain
    if tunnel_domain:
        hostname = request.headers.get("host", "").split(":")[0]
        if hostname.endswith(f".{tunnel_domain}"):
            return await call_next(request)

    # Capture request body
    body = await request.body()
    t0 = time.monotonic()

    response = await call_next(request)

    # Capture response body — StreamingResponse needs wrapping
    resp_body = b""
    if isinstance(response, StreamingResponse):
        chunks: list[bytes] = []

        async def body_iterator():
            async for chunk in response.body_iterator:
                if isinstance(chunk, str):
                    chunk = chunk.encode("utf-8")
                chunks.append(chunk)
                yield chunk

        response.body_iterator = body_iterator()
        # We need to actually consume the iterator to capture the body.
        # The response will be sent to the client as it streams; we
        # capture chunks in the iterator wrapper above. However, the
        # middleware return sends the response before we can read chunks.
        # Instead, schedule the audit as a background task that fires
        # after the response is fully sent.
        elapsed_ms = round((time.monotonic() - t0) * 1000)

        async def _audit_after_stream():
            # Wait briefly for the stream to complete
            await asyncio.sleep(0.1)
            resp_bytes = b"".join(chunks)
            await _store_api_audit(
                request=request,
                request_body=body,
                response=response,
                response_body=resp_bytes,
                elapsed_ms=elapsed_ms,
            )

        asyncio.create_task(_audit_after_stream())
        return response

    # Non-streaming response — body is available directly
    if hasattr(response, "body"):
        resp_body = response.body
    elapsed_ms = round((time.monotonic() - t0) * 1000)

    asyncio.create_task(
        _store_api_audit(
            request=request,
            request_body=body,
            response=response,
            response_body=resp_body,
            elapsed_ms=elapsed_ms,
        )
    )

    return response


def _extract_actor(request: Request) -> str:
    """Extract the actor identity from the request.

    Checks for authenticated user in request state (set by auth dependencies),
    falls back to "anonymous".
    """
    # FastAPI auth dependencies typically store user info in request.state
    if hasattr(request.state, "user_email"):
        return request.state.user_email

    # Try Authorization header to identify bearer token users
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        return "authenticated"

    return "anonymous"


def _build_exchange(
    request: Request,
    request_body: bytes,
    response: Response,
    response_body: bytes,
    elapsed_ms: int,
) -> dict:
    """Build an http-exchange-v1 format dict with redaction applied."""
    max_bytes = settings.audit.api_audit_body_max_bytes

    # Request headers — redact sensitive values
    req_headers = redact_headers(dict(request.headers))

    # Response headers — redact sensitive values
    resp_headers = redact_headers(dict(response.headers) if hasattr(response, "headers") else {})

    # Request body — redact sensitive fields
    req_body_str = ""
    req_body_truncated = False
    if request_body:
        if len(request_body) > max_bytes:
            req_body_str = request_body[:max_bytes].decode("utf-8", errors="replace")
            req_body_truncated = True
        else:
            req_body_str = request_body.decode("utf-8", errors="replace")

        req_ct = request.headers.get("content-type", "")
        if req_body_str:
            req_body_str = redact_body(req_body_str, req_ct)

    # Response body — redact sensitive fields
    resp_body_str = ""
    resp_body_truncated = False
    if response_body:
        if len(response_body) > max_bytes:
            resp_body_str = response_body[:max_bytes].decode("utf-8", errors="replace")
            resp_body_truncated = True
        else:
            resp_body_str = response_body.decode("utf-8", errors="replace")

        resp_ct = ""
        if hasattr(response, "headers"):
            resp_ct = response.headers.get("content-type", "")
        if resp_body_str:
            resp_body_str = redact_body(resp_body_str, resp_ct)

    # Query string — redact sensitive params
    query = redact_query(request.url.query or "")

    return {
        "version": 1,
        "request": {
            "method": request.method,
            "path": request.url.path,
            "query": query,
            "headers": req_headers,
            "body": req_body_str,
            "body_truncated": req_body_truncated,
        },
        "response": {
            "status": response.status_code,
            "headers": resp_headers,
            "body": resp_body_str,
            "body_truncated": resp_body_truncated,
        },
        "timing": {
            "duration_ms": elapsed_ms,
        },
    }


async def _store_api_audit(
    *,
    request: Request,
    request_body: bytes,
    response: Response,
    response_body: bytes,
    elapsed_ms: int,
) -> None:
    """Store an API audit event in the audit_logs table.

    Runs as a background task so it doesn't slow down the response.
    """
    try:
        exchange = _build_exchange(
            request=request,
            request_body=request_body,
            response=response,
            response_body=response_body,
            elapsed_ms=elapsed_ms,
        )

        actor = _extract_actor(request)
        client_ip = request.client.host if request.client else None
        user_agent = request.headers.get("user-agent")

        async with async_session_factory() as db:
            await log_audit_event(
                db,
                event_type="api",
                action="request",
                actor_type="user",
                actor_id=actor,
                actor_ip=client_ip,
                actor_user_agent=user_agent,
                target_type="endpoint",
                target_id=f"{request.method} {request.url.path}",
                details={"exchange": exchange},
                success=response.status_code < 500,
            )
            await db.commit()
    except Exception:
        logger.warning(
            "Failed to store API audit event",
            path=request.url.path,
            exc_info=True,
        )
