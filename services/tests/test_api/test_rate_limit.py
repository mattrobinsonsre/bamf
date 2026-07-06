"""Tests for the Redis-backed rate limiter middleware."""

from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import ASGITransport, AsyncClient
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route

from bamf.api.rate_limit import RateLimitMiddleware


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
