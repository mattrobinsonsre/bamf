"""Tests for the WebSocket proxy relay module."""

import asyncio
import re

import pytest
import wsproto
import wsproto.events

from bamf.proxy.websocket import ws_handshake


class TestWsHandshake:
    """Test ws_handshake() HTTP upgrade request and 101 response parsing."""

    @pytest.mark.asyncio
    async def test_successful_handshake(self):
        """Successful 101 response returns (ws_conn, None) for no subprotocol."""
        reader = asyncio.StreamReader()
        capture_transport, writer = self._make_capture_writer()

        task = asyncio.create_task(
            ws_handshake(
                reader,
                writer,
                "/relay/agent-1/ws",
                {"Host": "target:8080", "X-Bamf-Target": "http://target:8080"},
            )
        )

        # Let handshake write its request then block on reading response
        await asyncio.sleep(0.01)

        raw = bytes(capture_transport._buffer)
        accept = self._compute_accept(raw)
        reader.feed_data(
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: " + accept + b"\r\n"
            b"\r\n"
        )

        ws_conn, negotiated = await task

        assert negotiated is None
        assert ws_conn is not None
        # Verify the outgoing request was written
        assert b"GET /relay/agent-1/ws HTTP/1.1" in raw
        assert b"Sec-WebSocket-Version: 13" in raw
        assert b"Sec-WebSocket-Key:" in raw

    @pytest.mark.asyncio
    async def test_handshake_with_subprotocol(self):
        """101 response with Sec-WebSocket-Protocol returns negotiated subprotocol."""
        reader = asyncio.StreamReader()
        capture_transport, writer = self._make_capture_writer()

        task = asyncio.create_task(
            ws_handshake(
                reader,
                writer,
                "/path",
                {"Host": "k8s-api:6443"},
                subprotocols=["v4.channel.k8s.io", "v3.channel.k8s.io"],
            )
        )

        await asyncio.sleep(0.01)

        raw = bytes(capture_transport._buffer)
        accept = self._compute_accept(raw)
        reader.feed_data(
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: " + accept + b"\r\n"
            b"Sec-WebSocket-Protocol: v4.channel.k8s.io\r\n"
            b"\r\n"
        )

        ws_conn, negotiated = await task
        assert negotiated == "v4.channel.k8s.io"

    @pytest.mark.asyncio
    async def test_handshake_sends_subprotocols(self):
        """Subprotocols are included in the Sec-WebSocket-Protocol header."""
        reader = asyncio.StreamReader()
        capture_transport, writer = self._make_capture_writer()

        task = asyncio.create_task(
            ws_handshake(
                reader,
                writer,
                "/path",
                {"Host": "target"},
                subprotocols=["proto-a", "proto-b"],
            )
        )

        await asyncio.sleep(0.01)

        raw = bytes(capture_transport._buffer)
        accept = self._compute_accept(raw)
        reader.feed_data(
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: " + accept + b"\r\n"
            b"\r\n"
        )

        await task
        assert b"Sec-WebSocket-Protocol: proto-a, proto-b" in raw

    @pytest.mark.asyncio
    async def test_handshake_non_101_raises(self):
        """Non-101 response raises RuntimeError."""
        reader = asyncio.StreamReader()

        response = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
        reader.feed_data(response)

        _, writer = self._make_capture_writer()
        with pytest.raises(RuntimeError, match="HTTP 403"):
            await ws_handshake(reader, writer, "/path", {"Host": "target"})

    @pytest.mark.asyncio
    async def test_handshake_500_raises(self):
        """500 response raises RuntimeError with status code."""
        reader = asyncio.StreamReader()

        response = b"HTTP/1.1 500 Internal Server Error\r\n\r\n"
        reader.feed_data(response)

        _, writer = self._make_capture_writer()
        with pytest.raises(RuntimeError, match="HTTP 500"):
            await ws_handshake(reader, writer, "/path", {"Host": "target"})

    @pytest.mark.asyncio
    async def test_handshake_closed_connection_raises(self):
        """Closed connection during handshake raises RuntimeError."""
        reader = asyncio.StreamReader()
        reader.feed_eof()

        _, writer = self._make_capture_writer()
        with pytest.raises(RuntimeError, match="closed connection"):
            await ws_handshake(reader, writer, "/path", {"Host": "target"})

    @pytest.mark.asyncio
    async def test_handshake_custom_headers_sent(self):
        """Custom headers (X-Bamf-Target, X-Forwarded-*) are included in request."""
        reader = asyncio.StreamReader()
        capture_transport, writer = self._make_capture_writer()

        task = asyncio.create_task(
            ws_handshake(
                reader,
                writer,
                "/relay/agent/path",
                {
                    "Host": "target:3000",
                    "X-Bamf-Target": "http://target:3000",
                    "X-Forwarded-Email": "alice@example.com",
                },
            )
        )

        await asyncio.sleep(0.01)

        raw = bytes(capture_transport._buffer)
        accept = self._compute_accept(raw)
        reader.feed_data(
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: " + accept + b"\r\n"
            b"\r\n"
        )

        await task

        assert b"Host: target:3000" in raw
        assert b"X-Bamf-Target: http://target:3000" in raw
        assert b"X-Forwarded-Email: alice@example.com" in raw

    def _compute_accept(self, raw_request: bytes) -> bytes:
        """Feed the raw client request into a server-side wsproto to produce a valid 101.

        Using wsproto on both sides ensures the accept token computation matches
        exactly, avoiding subtle differences between manual SHA1+GUID and
        wsproto's internal validation.
        """
        server = wsproto.WSConnection(wsproto.ConnectionType.SERVER)
        server.receive_data(raw_request)
        for event in server.events():
            if isinstance(event, wsproto.events.Request):
                # Let wsproto produce the 101 response with correct Accept
                accept_data = server.send(wsproto.events.AcceptConnection())
                # Extract Sec-WebSocket-Accept from the response
                match = re.search(b"Sec-WebSocket-Accept: (.+?)\r\n", accept_data)
                assert match, "Sec-WebSocket-Accept not found in server response"
                return match.group(1)
        raise AssertionError("No Request event from wsproto server")

    def _make_capture_writer(
        self,
    ) -> tuple["_BufferTransport", asyncio.StreamWriter]:
        """Create a StreamWriter whose output can be inspected via the transport."""
        reader = asyncio.StreamReader()
        transport = _BufferTransport()
        protocol = asyncio.StreamReaderProtocol(reader)
        writer = asyncio.StreamWriter(transport, protocol, reader, asyncio.get_event_loop())
        return transport, writer


class _BufferTransport(asyncio.Transport):
    """Minimal transport that captures writes into an internal buffer."""

    def __init__(self):
        super().__init__()
        self._buffer = bytearray()

    def write(self, data: bytes) -> None:
        self._buffer.extend(data)

    def get_write_buffer_size(self) -> int:
        return 0

    def is_closing(self) -> bool:
        return False

    def close(self) -> None:
        pass
