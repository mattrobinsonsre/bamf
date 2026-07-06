"""Tests for the Redis-backed rate limiter middleware."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from bamf.api.rate_limit import RateLimitMiddleware, _get_client_ip


def _request_with_xff(xff: str | None, peer: str = "10.0.0.254") -> Request:
    headers = [(b"x-forwarded-for", xff.encode())] if xff is not None else []
    return Request({"type": "http", "headers": headers, "client": (peer, 0)})


def _make_redis(count: int):
    """Redis mock whose INCR pipeline resolves to `count`."""
    redis = MagicMock()
    pipe = MagicMock()
    pipe.execute = AsyncMock(return_value=[count, True])
    redis.pipeline = MagicMock(return_value=pipe)
    return redis


def _app(redis, **limits) -> Starlette:
    async def ok(_request):
        return PlainTextResponse("ok")

    app = Starlette(
        routes=[
            Route("/x", ok),
            Route("/api/v1/auth/login", ok, methods=["POST"]),
            Route("/health", ok),
        ]
    )
    app.add_middleware(RateLimitMiddleware, get_redis=lambda: redis, **limits)
    return app


async def _get(app, path, method="GET"):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        return await c.request(method, path)


def test_client_ip_ignores_spoofed_leftmost_xff():
    """A client-supplied leftmost X-Forwarded-For must NOT become the rate-limit
    key — otherwise rotating it defeats the limiter (incl. auth brute-force)."""
    # Ingress appends the real peer on the right; leftmost is attacker-controlled.
    req = _request_with_xff("1.2.3.4, 203.0.113.7")
    assert _get_client_ip(req, trusted_proxy_hops=1) == "203.0.113.7"
    # Rotating the spoofed leftmost value does not change the resolved IP.
    req2 = _request_with_xff("9.9.9.9, 203.0.113.7")
    assert _get_client_ip(req2, trusted_proxy_hops=1) == "203.0.113.7"


def test_client_ip_honours_trusted_hops():
    """With two trusted proxies, count two in from the right."""
    req = _request_with_xff("spoof, real-client, ingress")
    assert _get_client_ip(req, trusted_proxy_hops=2) == "real-client"


def test_client_ip_single_entry_and_fallback():
    assert _get_client_ip(_request_with_xff("203.0.113.7")) == "203.0.113.7"
    # No XFF → fall back to the socket peer.
    assert _get_client_ip(_request_with_xff(None, peer="198.51.100.9")) == "198.51.100.9"
    # More trusted hops than entries → clamp to the leftmost available.
    assert _get_client_ip(_request_with_xff("only-one"), trusted_proxy_hops=5) == "only-one"


@pytest.mark.asyncio
async def test_spoofed_xff_shares_one_bucket():
    """End-to-end: requests differing only in spoofed leftmost XFF hit the same
    Redis bucket (same key), so the limiter counts them together."""
    redis = _make_redis(1)
    keys: list[str] = []
    pipe = redis.pipeline.return_value
    pipe.incr = MagicMock(side_effect=lambda k: keys.append(k))
    app = _app(redis, requests_per_minute=5, trusted_proxy_hops=1)
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://t") as c:
        await c.get("/x", headers={"x-forwarded-for": "1.1.1.1, 203.0.113.7"})
        await c.get("/x", headers={"x-forwarded-for": "2.2.2.2, 203.0.113.7"})
    assert len(keys) == 2
    assert keys[0] == keys[1], keys  # same client-IP component → same bucket


@pytest.mark.asyncio
async def test_under_limit_passes():
    r = await _get(_app(_make_redis(1), requests_per_minute=5), "/x")
    assert r.status_code == 200
    assert r.headers["x-ratelimit-limit"] == "5"
    assert r.headers["x-ratelimit-remaining"] == "4"


@pytest.mark.asyncio
async def test_over_limit_429():
    r = await _get(_app(_make_redis(6), requests_per_minute=5), "/x")
    assert r.status_code == 429
    assert "retry-after" in {k.lower() for k in r.headers}


@pytest.mark.asyncio
async def test_exempt_path_bypasses():
    # count far over the limit, but /health is exempt.
    r = await _get(_app(_make_redis(999), requests_per_minute=1), "/health")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_auth_path_uses_strict_limit():
    # base limit would allow (100), but the strict auth bucket (2) rejects at 3.
    app = _app(_make_redis(3), requests_per_minute=100, auth_requests_per_minute=2)
    r = await _get(app, "/api/v1/auth/login", method="POST")
    assert r.status_code == 429


@pytest.mark.asyncio
async def test_zero_limit_is_unlimited():
    r = await _get(_app(_make_redis(10_000), requests_per_minute=0), "/x")
    assert r.status_code == 200


@pytest.mark.asyncio
async def test_fail_open_on_redis_error():
    redis = MagicMock()
    pipe = MagicMock()
    pipe.execute = AsyncMock(side_effect=Exception("redis down"))
    redis.pipeline = MagicMock(return_value=pipe)
    r = await _get(_app(redis, requests_per_minute=1), "/x")
    assert r.status_code == 200
