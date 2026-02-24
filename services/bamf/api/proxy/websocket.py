"""WebSocket proxy relay using wsproto for frame encoding/decoding.

Provides helpers for proxying WebSocket connections between the ASGI server
(uvicorn handling browser WebSocket) and a raw TCP connection to the bridge
internal relay port.

The bridge/agent path is opaque TCP — the bridge does a byte-splice between
the API conn and the agent relay conn. wsproto encodes/decodes WebSocket
frames so the ASGI server can exchange typed messages while the bridge sees
raw bytes.
"""

from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING

import wsproto
import wsproto.events
from starlette.websockets import WebSocket, WebSocketDisconnect

from bamf.logging_config import get_logger

if TYPE_CHECKING:
    pass

logger = get_logger(__name__)


async def ws_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    path: str,
    headers: dict[str, str],
    subprotocols: list[str] | None = None,
) -> tuple[wsproto.WSConnection, str | None]:
    """Send a WebSocket upgrade request via wsproto and verify the 101 response.

    Returns (WSConnection in OPEN state, negotiated subprotocol or None).
    Raises ``RuntimeError`` on non-101 response or handshake failure.

    Uses wsproto's state machine for the entire handshake so the returned
    connection is ready for sending/receiving data frames immediately.
    """
    ws_conn = wsproto.WSConnection(wsproto.ConnectionType.CLIENT)

    # Extract Host for wsproto's host parameter
    host = headers.get("Host", "localhost")

    # Build extra headers, excluding Host (passed separately) and standard
    # WebSocket headers that wsproto generates itself.
    ws_managed = {
        "host",
        "upgrade",
        "connection",
        "sec-websocket-key",
        "sec-websocket-version",
        "sec-websocket-protocol",
    }
    extra_headers = [
        (k.encode(), v.encode()) for k, v in headers.items() if k.lower() not in ws_managed
    ]

    # Generate upgrade request via wsproto (handles Key, Version, etc.)
    request_bytes = ws_conn.send(
        wsproto.events.Request(
            host=host,
            target=path,
            extra_headers=extra_headers,
            subprotocols=subprotocols or [],
        )
    )
    writer.write(request_bytes)
    await writer.drain()

    # Read the full HTTP response (status line + headers + blank line)
    # and feed it to wsproto so it can transition to OPEN state.
    response_bytes = b""
    while True:
        line = await reader.readline()
        if not line:
            raise RuntimeError("bridge closed connection during WebSocket handshake")
        response_bytes += line
        if line == b"\r\n" or line == b"\n":
            break

    ws_conn.receive_data(response_bytes)

    negotiated = None
    for event in ws_conn.events():
        if isinstance(event, wsproto.events.AcceptConnection):
            negotiated = event.subprotocol
        elif isinstance(event, wsproto.events.RejectConnection):
            raise RuntimeError(f"WebSocket upgrade failed: HTTP {event.status_code}")
        elif isinstance(event, wsproto.events.RejectData):
            raise RuntimeError("WebSocket upgrade rejected")

    return ws_conn, negotiated


async def ws_relay(
    websocket: WebSocket,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    ws_conn: wsproto.WSConnection,
) -> None:
    """Bidirectional WebSocket relay between ASGI and raw TCP.

    - Browser → ASGI WebSocket → wsproto encode → TCP to bridge
    - TCP from bridge → wsproto decode → ASGI WebSocket → browser

    ``ws_conn`` must already be in OPEN state (from ``ws_handshake``).
    Runs until either side closes.
    """

    async def browser_to_bridge() -> None:
        """Read from ASGI WebSocket, encode as wsproto frames, write to TCP."""
        try:
            while True:
                msg = await websocket.receive()
                if msg.get("type") == "websocket.disconnect":
                    data = ws_conn.send(wsproto.events.CloseConnection(code=1000))
                    writer.write(data)
                    await writer.drain()
                    return

                if "text" in msg:
                    data = ws_conn.send(wsproto.events.TextMessage(data=msg["text"]))
                elif "bytes" in msg:
                    data = ws_conn.send(wsproto.events.BytesMessage(data=msg["bytes"]))
                else:
                    continue

                writer.write(data)
                await writer.drain()
        except WebSocketDisconnect:
            try:
                data = ws_conn.send(wsproto.events.CloseConnection(code=1000))
                writer.write(data)
                await writer.drain()
            except Exception:
                pass

    async def bridge_to_browser() -> None:
        """Read raw bytes from TCP, decode wsproto events, send to ASGI."""
        try:
            while True:
                raw = await reader.read(65536)
                if not raw:
                    return

                ws_conn.receive_data(raw)
                for event in ws_conn.events():
                    if isinstance(event, wsproto.events.TextMessage):
                        await websocket.send_text(event.data)
                    elif isinstance(event, wsproto.events.BytesMessage):
                        await websocket.send_bytes(event.data)
                    elif isinstance(event, wsproto.events.CloseConnection):
                        return
                    elif isinstance(event, wsproto.events.Ping):
                        pong = ws_conn.send(wsproto.events.Pong(payload=event.payload))
                        writer.write(pong)
                        await writer.drain()
        except Exception as exc:
            logger.debug("ws_relay: bridge→browser exception: %s", exc)

    b2b = asyncio.create_task(browser_to_bridge())
    br2b = asyncio.create_task(bridge_to_browser())

    try:
        done, pending = await asyncio.wait(
            [b2b, br2b],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for task in pending:
            task.cancel()
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
    finally:
        writer.close()
