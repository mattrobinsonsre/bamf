"""Redis-backed sliding-window rate limiter middleware.

Multi-replica safe — uses Redis INCR + EXPIRE for distributed counting.
Fails open if Redis is unavailable. Tiers:

- Auth endpoints (``/api/v1/auth/*``): always the strict ``auth`` limit,
  regardless of caller — brute-force / password-guessing defence on login.
- Authenticated (any ``Authorization`` header, ``X-Bamf-Client-Cert`` header,
  or ``bamf_session`` cookie present): ``authenticated`` limit. Presence is
  enough to separate interactive/machine traffic from anonymous — the real
  credential check happens in the downstream auth dependency.
- Unauthenticated: the base ``requests_per_minute`` limit.

A per-tier limit of 0 means "unlimited" (skip the bucket).
"""

import time
from collections.abc import Callable

from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from bamf.logging_config import get_logger

logger = get_logger(__name__)

_EXEMPT_PATHS = frozenset({"/health", "/ready", "/metrics"})
_AUTH_PREFIXES = ("/api/v1/auth/",)


def _is_auth_path(path: str) -> bool:
    return any(path.startswith(p) for p in _AUTH_PREFIXES)


def _get_client_ip(request: Request, trusted_proxy_hops: int = 1) -> str:
    """Client IP for rate-limit keying, resolved from X-Forwarded-For.

    XFF is ``client, proxy1, ..., proxyN`` where each proxy appends the address
    it received the request from — so the entries appended by our own trusted
    proxies are the RIGHTMOST ones, and anything a client sends arrives on the
    LEFT. Taking ``[0]`` (leftmost) is attacker-controlled: rotating a spoofed
    XFF value lands every request in a fresh bucket and defeats the limiter
    (including the auth-tier brute-force defence). Instead we count
    ``trusted_proxy_hops`` in from the right — the IP our outermost trusted proxy
    observed. Default 1 = a single ingress in front of the API.
    """
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        parts = [p.strip() for p in forwarded.split(",") if p.strip()]
        if parts:
            idx = min(max(trusted_proxy_hops, 1), len(parts))
            return parts[-idx]
    if request.client:
        return request.client.host
    return "unknown"


class RateLimitMiddleware:
    """Sliding-window rate limiter (pure ASGI middleware)."""

    def __init__(
        self,
        app: ASGIApp,
        requests_per_minute: int = 100,
        authenticated_requests_per_minute: int = 1000,
        auth_requests_per_minute: int = 10,
        trusted_proxy_hops: int = 1,
        get_redis: Callable | None = None,
    ) -> None:
        self.app = app
        self.requests_per_minute = requests_per_minute
        self.authenticated_requests_per_minute = authenticated_requests_per_minute
        self.auth_requests_per_minute = auth_requests_per_minute
        self.trusted_proxy_hops = trusted_proxy_hops
        self._get_redis = get_redis

    def _resolve_redis(self):  # type: ignore[no-untyped-def]
        if self._get_redis is not None:
            return self._get_redis()
        from bamf.redis.client import get_redis_client

        return get_redis_client()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if path in _EXEMPT_PATHS:
            await self.app(scope, receive, send)
            return

        request = Request(scope)

        if _is_auth_path(path):
            limit, prefix = self.auth_requests_per_minute, "auth"
        elif (
            request.headers.get("authorization")
            or request.headers.get("x-bamf-client-cert")
            or "bamf_session" in request.cookies
        ):
            limit, prefix = self.authenticated_requests_per_minute, "authn"
        else:
            limit, prefix = self.requests_per_minute, "anon"

        # 0 means unlimited for this tier.
        if limit <= 0:
            await self.app(scope, receive, send)
            return

        try:
            redis = self._resolve_redis()
        except RuntimeError:
            await self.app(scope, receive, send)  # Redis not initialized — fail open
            return

        client_ip = _get_client_ip(request, self.trusted_proxy_hops)
        window_id = int(time.time()) // 60  # 60-second buckets
        key = f"bamf:ratelimit:{prefix}:{client_ip}:{window_id}"

        try:
            pipe = redis.pipeline(transaction=False)
            pipe.incr(key)
            pipe.expire(key, 120)  # 2-minute TTL for cleanup
            results = await pipe.execute()
            count = results[0]
        except Exception:
            logger.warning("rate limit Redis error, failing open", exc_info=True)
            await self.app(scope, receive, send)
            return

        if count > limit:
            retry_after = 60 - (int(time.time()) % 60)
            response = JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded"},
                headers={"Retry-After": str(retry_after)},
            )
            await response(scope, receive, send)
            return

        async def send_with_headers(message: dict) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.append((b"x-ratelimit-limit", str(limit).encode()))
                headers.append((b"x-ratelimit-remaining", str(max(0, limit - count)).encode()))
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_with_headers)
