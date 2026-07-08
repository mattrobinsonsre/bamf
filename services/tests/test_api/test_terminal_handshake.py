"""Tests for the bridge-first web-terminal handshake (issue #233).

The security-critical property: credentials are forwarded to the bridge ONLY
after it emits "auth-required" (a fresh session). On "resumed" (a reattach) no
credentials are ever sent, so an SSH key / DB password can never be injected
into a live session — regardless of what the browser sent.
"""

from __future__ import annotations

import asyncio
import json
import struct

import pytest

from bamf.api.routers import terminal
from bamf.api.routers.terminal import (
    FRAME_DATA,
    FRAME_STATUS,
    STATUS_AUTH_REQUIRED,
    STATUS_READY,
    STATUS_RESUMED,
    _terminal_handshake,
)


def _frame(frame_type: int, payload: bytes) -> bytes:
    return bytes([frame_type]) + struct.pack("!H", len(payload)) + payload


def _status(s: str) -> bytes:
    return _frame(FRAME_STATUS, s.encode())


class FakeReader:
    """Serves pre-encoded bridge frames to _read_frame's readexactly()."""

    def __init__(self, data: bytes):
        self._data = data
        self._pos = 0

    async def readexactly(self, n: int) -> bytes:
        if self._pos + n > len(self._data):
            raise asyncio.IncompleteReadError(self._data[self._pos :], n)
        chunk = self._data[self._pos : self._pos + n]
        self._pos += n
        return chunk


class FakeWS:
    def __init__(self):
        self.sent: list[str] = []
        self.closed: tuple[int, str] | None = None

    async def send_text(self, text: str) -> None:
        self.sent.append(text)

    async def close(self, code: int = 1000, reason: str = "") -> None:
        self.closed = (code, reason)


@pytest.fixture
def creds_spy(monkeypatch):
    """Record every _send_credentials_to_bridge call (and forward nothing)."""
    calls: list[dict] = []

    async def fake_send(writer, msg, resource_type, *, audit=False):
        calls.append({"resource_type": resource_type, "audit": audit})

    monkeypatch.setattr(terminal, "_send_credentials_to_bridge", fake_send)
    return calls


@pytest.mark.asyncio
async def test_resumed_never_sends_credentials(creds_spy):
    """#233 core guard: a 'resumed' session must NOT receive credentials."""
    reader = FakeReader(_status(STATUS_RESUMED))
    ws = FakeWS()

    status = await _terminal_handshake(
        ws,
        reader,
        writer=object(),
        msg={"key": "SECRET-PEM"},
        resource_type="web-ssh",
        is_audit=False,
    )

    assert status == STATUS_RESUMED
    assert creds_spy == [], "credentials must never be sent into a resumed session"
    assert ws.closed is None


@pytest.mark.asyncio
async def test_auth_required_sends_credentials_then_ready(creds_spy):
    """A fresh session: bridge asks (auth-required), relay sends creds, gets ready."""
    reader = FakeReader(_status(STATUS_AUTH_REQUIRED) + _status(STATUS_READY))
    ws = FakeWS()

    status = await _terminal_handshake(
        ws, reader, writer=object(), msg={"key": "SECRET"}, resource_type="web-ssh", is_audit=True
    )

    assert status == STATUS_READY
    assert len(creds_spy) == 1, "credentials sent exactly once on a fresh session"
    assert creds_spy[0]["audit"] is True
    assert ws.closed is None


@pytest.mark.asyncio
async def test_error_first_forwards_and_closes_without_creds(creds_spy):
    """An error before auth-required forwards to the browser and sends no creds."""
    reader = FakeReader(_status("error:boom"))
    ws = FakeWS()

    status = await _terminal_handshake(
        ws, reader, writer=object(), msg={"key": "S"}, resource_type="web-ssh", is_audit=False
    )

    assert status is None
    assert creds_spy == []
    assert json.loads(ws.sent[0]) == {"type": "error", "message": "boom"}
    assert ws.closed[0] == 4005


@pytest.mark.asyncio
async def test_auth_required_then_auth_failure_forwards_error(creds_spy):
    """Fresh session where the bridge rejects the credentials: error is forwarded."""
    reader = FakeReader(_status(STATUS_AUTH_REQUIRED) + _status("error:auth failed"))
    ws = FakeWS()

    status = await _terminal_handshake(
        ws, reader, writer=object(), msg={"key": "S"}, resource_type="web-ssh", is_audit=False
    )

    assert status is None
    assert len(creds_spy) == 1  # creds were sent, then the bridge failed auth
    assert json.loads(ws.sent[0]) == {"type": "error", "message": "auth failed"}
    assert ws.closed[0] == 4005


@pytest.mark.asyncio
async def test_non_status_first_frame_closes(creds_spy):
    """A non-status opening frame is a protocol violation → close, no creds."""
    reader = FakeReader(_frame(FRAME_DATA, b"garbage"))
    ws = FakeWS()

    status = await _terminal_handshake(
        ws, reader, writer=object(), msg={}, resource_type="web-ssh", is_audit=False
    )

    assert status is None
    assert creds_spy == []
    assert ws.closed[0] == 4004
