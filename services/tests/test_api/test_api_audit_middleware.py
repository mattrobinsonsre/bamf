"""Tests for the API self-audit middleware's response-body capture.

Regression coverage for #172: the streaming-response audit must capture the
FULL body on actual stream completion (or the exact bytes sent on client
disconnect), never a prefix truncated by a fixed `sleep(0.1)` timer.
"""

from __future__ import annotations

import asyncio

import pytest
from starlette.requests import Request
from starlette.responses import StreamingResponse

from bamf.api import middleware


def _scope(
    method: str = "GET", path: str = "/api/v1/users", host: str = "bamf.example.com"
) -> dict:
    """Minimal ASGI http scope for a Starlette Request the middleware accepts."""
    return {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": b"",
        "server": ("bamf.example.com", 443),
        "client": ("10.0.0.1", 12345),
        "headers": [(b"host", host.encode()), (b"user-agent", b"pytest")],
    }


def _capture_store(captured: dict):
    """Patch replacement for _store_api_audit that records the captured body."""

    async def fake_store(*, request, request_body, response, response_body, elapsed_ms):
        captured["response_body"] = response_body
        captured["elapsed_ms"] = elapsed_ms

    return fake_store


@pytest.mark.asyncio
async def test_streaming_audit_captures_full_body_after_slow_stream(monkeypatch):
    """#172: a response that streams for >100ms must be audited in full.

    An asyncio.Event holds the stream open past the old 0.1s timer. The buggy
    timer-based audit fired mid-stream with only the first chunk; the fixed
    iterator-completion audit fires once the stream truly finishes, with all of
    it.
    """
    captured: dict = {}
    monkeypatch.setattr(middleware, "_store_api_audit", _capture_store(captured))

    release = asyncio.Event()

    async def slow_stream():
        yield b"chunk-0"
        await release.wait()
        yield b"chunk-1"
        yield b"chunk-2"

    async def call_next(_request):
        return StreamingResponse(slow_stream(), status_code=200)

    request = Request(scope=_scope())
    request._body = b""

    response = await middleware.api_audit_middleware(request, call_next)

    # Consume the wrapped iterator the way the ASGI server would.
    consumed: list[bytes] = []

    async def consume():
        async for chunk in response.body_iterator:
            consumed.append(chunk)

    task = asyncio.create_task(consume())

    # Exceed the old 0.1s timer while the stream is still blocked at chunk-0.
    # The buggy audit would have fired here with a truncated body.
    await asyncio.sleep(0.15)
    assert "response_body" not in captured, "audit fired mid-stream (timer bug)"

    release.set()
    await task
    await asyncio.sleep(0)  # let the audit background task run

    assert b"".join(consumed) == b"chunk-0chunk-1chunk-2"
    assert captured["response_body"] == b"chunk-0chunk-1chunk-2"


@pytest.mark.asyncio
async def test_streaming_audit_captures_exact_bytes_on_client_disconnect(monkeypatch):
    """On disconnect (GeneratorExit) the audit records exactly the bytes sent."""
    captured: dict = {}
    monkeypatch.setattr(middleware, "_store_api_audit", _capture_store(captured))

    async def stream():
        yield b"partial"
        yield b"never-sent"

    async def call_next(_request):
        return StreamingResponse(stream(), status_code=200)

    request = Request(scope=_scope())
    request._body = b""

    response = await middleware.api_audit_middleware(request, call_next)

    agen = response.body_iterator
    first = await agen.__anext__()
    assert first == b"partial"
    await agen.aclose()  # simulate the client going away mid-stream
    await asyncio.sleep(0.01)  # let the audit task run

    assert captured["response_body"] == b"partial"


@pytest.mark.asyncio
async def test_non_streaming_audit_captures_body(monkeypatch):
    """Plain (non-streaming) responses are audited with their full body."""
    from starlette.responses import Response

    captured: dict = {}
    monkeypatch.setattr(middleware, "_store_api_audit", _capture_store(captured))

    async def call_next(_request):
        return Response(content=b'{"ok": true}', status_code=200, media_type="application/json")

    request = Request(scope=_scope())
    request._body = b""

    await middleware.api_audit_middleware(request, call_next)
    await asyncio.sleep(0)  # let the audit background task run

    assert captured["response_body"] == b'{"ok": true}'
