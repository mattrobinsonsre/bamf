"""Tests for the WebSocket proxy relay module."""

import asyncio

import pytest

from bamf.api.proxy.websocket import ws_handshake


class TestWsHandshake:
    """Test ws_handshake() HTTP upgrade request and 101 response parsing."""

    @pytest.mark.asyncio
    async def test_successful_handshake(self):
        """Successful 101 response returns None subprotocol."""
        reader, writer_to_test = self._make_streams()

        # Simulate a 101 response
        response = (
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"
            b"\r\n"
        )
        reader.feed_data(response)

        # Capture what ws_handshake writes
        capture_transport, capture_writer = self._make_capture_writer()
        negotiated = await ws_handshake(
            reader,
            capture_writer,
            "/relay/agent-1/ws",
            {"Host": "target:8080", "X-Bamf-Target": "http://target:8080"},
        )

        assert negotiated is None
        # Verify the outgoing request was written
        raw = bytes(capture_transport._buffer)
        assert b"GET /relay/agent-1/ws HTTP/1.1" in raw
        assert b"Upgrade: websocket" in raw
        assert b"Connection: Upgrade" in raw
        assert b"Sec-WebSocket-Version: 13" in raw
        assert b"Sec-WebSocket-Key:" in raw

    @pytest.mark.asyncio
    async def test_handshake_with_subprotocol(self):
        """101 response with Sec-WebSocket-Protocol returns negotiated subprotocol."""
        reader, _ = self._make_streams()

        response = (
            b"HTTP/1.1 101 Switching Protocols\r\n"
            b"Upgrade: websocket\r\n"
            b"Connection: Upgrade\r\n"
            b"Sec-WebSocket-Protocol: v4.channel.k8s.io\r\n"
            b"\r\n"
        )
        reader.feed_data(response)

        _, writer = self._make_capture_writer()
        negotiated = await ws_handshake(
            reader,
            writer,
            "/path",
            {"Host": "k8s-api:6443"},
            subprotocols=["v4.channel.k8s.io", "v3.channel.k8s.io"],
        )

        assert negotiated == "v4.channel.k8s.io"

    @pytest.mark.asyncio
    async def test_handshake_sends_subprotocols(self):
        """Subprotocols are included in the Sec-WebSocket-Protocol header."""
        reader, _ = self._make_streams()

        response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"
        reader.feed_data(response)

        capture_transport, writer = self._make_capture_writer()
        await ws_handshake(
            reader,
            writer,
            "/path",
            {"Host": "target"},
            subprotocols=["proto-a", "proto-b"],
        )

        raw = bytes(capture_transport._buffer)
        assert b"Sec-WebSocket-Protocol: proto-a, proto-b" in raw

    @pytest.mark.asyncio
    async def test_handshake_non_101_raises(self):
        """Non-101 response raises RuntimeError."""
        reader, _ = self._make_streams()

        response = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
        reader.feed_data(response)

        _, writer = self._make_capture_writer()
        with pytest.raises(RuntimeError, match="HTTP 403"):
            await ws_handshake(reader, writer, "/path", {"Host": "target"})

    @pytest.mark.asyncio
    async def test_handshake_500_raises(self):
        """500 response raises RuntimeError with status code."""
        reader, _ = self._make_streams()

        response = b"HTTP/1.1 500 Internal Server Error\r\n\r\n"
        reader.feed_data(response)

        _, writer = self._make_capture_writer()
        with pytest.raises(RuntimeError, match="HTTP 500"):
            await ws_handshake(reader, writer, "/path", {"Host": "target"})

    @pytest.mark.asyncio
    async def test_handshake_closed_connection_raises(self):
        """Closed connection during handshake raises RuntimeError."""
        reader, _ = self._make_streams()
        reader.feed_eof()

        _, writer = self._make_capture_writer()
        with pytest.raises(RuntimeError, match="closed connection"):
            await ws_handshake(reader, writer, "/path", {"Host": "target"})

    @pytest.mark.asyncio
    async def test_handshake_custom_headers_sent(self):
        """Custom headers (X-Bamf-Target, X-Forwarded-*) are included in request."""
        reader, _ = self._make_streams()

        response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n"
        reader.feed_data(response)

        capture_transport, writer = self._make_capture_writer()
        await ws_handshake(
            reader,
            writer,
            "/relay/agent/path",
            {
                "Host": "target:3000",
                "X-Bamf-Target": "http://target:3000",
                "X-Forwarded-Email": "alice@example.com",
            },
        )

        raw = bytes(capture_transport._buffer)
        assert b"Host: target:3000" in raw
        assert b"X-Bamf-Target: http://target:3000" in raw
        assert b"X-Forwarded-Email: alice@example.com" in raw

    def _make_streams(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """Create a StreamReader/StreamWriter pair.

        The writer writes to a buffer transport. Use _make_capture_writer()
        when you need to inspect what was written.
        """
        reader = asyncio.StreamReader()
        transport = _BufferTransport()
        protocol = asyncio.StreamReaderProtocol(reader)
        writer = asyncio.StreamWriter(transport, protocol, reader, asyncio.get_event_loop())
        return reader, writer

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

    def is_closing(self) -> bool:
        return False

    def close(self) -> None:
        pass
