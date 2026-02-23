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
import base64
import os
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
) -> str | None:
    """Send an HTTP/1.1 WebSocket upgrade request and verify the 101 response.

    Returns the negotiated subprotocol (or None).  Raises ``RuntimeError``
    on non-101 response.
    """
    # Generate Sec-WebSocket-Key
    ws_key = base64.b64encode(os.urandom(16)).decode()

    # Build raw HTTP upgrade request
    lines = [
        f"GET {path} HTTP/1.1",
    ]
    # Set required WebSocket headers
    headers["Upgrade"] = "websocket"
    headers["Connection"] = "Upgrade"
    headers["Sec-WebSocket-Key"] = ws_key
    headers["Sec-WebSocket-Version"] = "13"
    if subprotocols:
        headers["Sec-WebSocket-Protocol"] = ", ".join(subprotocols)

    for k, v in headers.items():
        lines.append(f"{k}: {v}")
    lines.append("")
    lines.append("")

    raw = "\r\n".join(lines).encode()
    writer.write(raw)
    await writer.drain()

    # Read HTTP response (status line + headers)
    status_line = await reader.readline()
    if not status_line:
        raise RuntimeError("bridge closed connection during WebSocket handshake")

    status_text = status_line.decode(errors="replace").strip()
    parts = status_text.split(" ", 2)
    if len(parts) < 2:
        raise RuntimeError(f"invalid HTTP response: {status_text}")

    status_code = int(parts[1])

    # Read headers
    resp_headers: dict[str, str] = {}
    while True:
        line = await reader.readline()
        stripped = line.decode(errors="replace").strip()
        if not stripped:
            break
        if ":" in stripped:
            k, v = stripped.split(":", 1)
            resp_headers[k.strip().lower()] = v.strip()

    if status_code != 101:
        raise RuntimeError(f"WebSocket upgrade failed: HTTP {status_code} {status_text}")

    negotiated = resp_headers.get("sec-websocket-protocol")
    return negotiated


async def ws_relay(
    websocket: WebSocket,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    """Bidirectional WebSocket relay between ASGI and raw TCP.

    - Browser → ASGI WebSocket → wsproto encode → TCP to bridge
    - TCP from bridge → wsproto decode → ASGI WebSocket → browser

    Runs until either side closes.
    """
    ws_conn = wsproto.WSConnection(wsproto.ConnectionType.CLIENT)

    async def browser_to_bridge() -> None:
        """Read from ASGI WebSocket, encode as wsproto frames, write to TCP."""
        try:
            while True:
                msg = await websocket.receive()
                if msg.get("type") == "websocket.disconnect":
                    # Send close frame to bridge
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
                    # Bridge closed
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
        except Exception:
            pass

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
