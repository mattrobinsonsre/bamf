"""Terminal router for browser-based SSH and database access.

Provides:
- POST /terminal/ticket — issue a one-time WebSocket auth ticket
- WS   /terminal/ssh/{session_id} — SSH web terminal relay
- WS   /terminal/db/{session_id}  — Database web terminal relay

The API is a pure stateless relay. All session state (SSH connection, PTY
subprocess) lives in the bridge. API pods can restart without breaking
terminal sessions — the browser auto-reconnects via any API pod.
"""

from __future__ import annotations

import asyncio
import json
import secrets
import struct

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, status
from pydantic import Field

from bamf.api.dependencies import get_current_user
from bamf.api.models.common import BAMFBaseModel
from bamf.api.tunnel_client import dial_bridge
from bamf.auth.sessions import Session
from bamf.logging_config import get_logger
from bamf.redis.client import get_redis, get_redis_client

logger = get_logger(__name__)

router = APIRouter(prefix="/terminal", tags=["terminal"])

# Frame protocol constants (must match pkg/bridge/webterm/frame.go)
FRAME_DATA = 0x01
FRAME_RESIZE = 0x02
FRAME_STATUS = 0x03

# Ticket TTL in seconds
TICKET_TTL = 60


class TicketRequest(BAMFBaseModel):
    """Request to issue a one-time WebSocket ticket."""

    session_id: str = Field(..., min_length=1, max_length=128)


class TicketResponse(BAMFBaseModel):
    """One-time WebSocket authentication ticket."""

    ticket: str


@router.post("/ticket", response_model=TicketResponse)
async def create_ticket(
    request: TicketRequest,
    r: aioredis.Redis = Depends(get_redis),
    current_user: Session = Depends(get_current_user),
) -> TicketResponse:
    """Issue a one-time ticket for WebSocket authentication.

    The ticket is stored in Redis with a 60s TTL and consumed atomically
    via GETDEL when the WebSocket connects. This prevents replay attacks.
    """
    # Verify the session exists and belongs to this user
    raw = await r.get(f"session:{request.session_id}")
    if not raw:
        from fastapi import HTTPException

        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Session not found or expired",
        )

    session_data = json.loads(raw)
    if session_data.get("user_email") != current_user.email:
        from fastapi import HTTPException

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Session does not belong to this user",
        )

    # Generate ticket
    ticket = secrets.token_urlsafe(32)
    ticket_data = json.dumps(
        {
            "session_id": request.session_id,
            "user_email": current_user.email,
        }
    )
    await r.setex(f"terminal:ticket:{ticket}", TICKET_TTL, ticket_data)

    return TicketResponse(ticket=ticket)


async def _validate_ticket(r: aioredis.Redis, ticket: str, session_id: str) -> dict | None:
    """Validate and consume a one-time ticket.

    Uses GETDEL for atomic consumption — the ticket can only be used once.
    Returns the ticket data dict if valid, None otherwise.
    """
    raw = await r.getdel(f"terminal:ticket:{ticket}")
    if not raw:
        return None

    data = json.loads(raw)

    # Verify ticket is for this session
    if data.get("session_id") != session_id:
        return None

    return data


def _write_frame(frame_type: int, payload: bytes) -> bytes:
    """Encode a frame: [1-byte type][2-byte length][payload]."""
    return struct.pack("!BH", frame_type, len(payload)) + payload


async def _read_frame(
    reader: asyncio.StreamReader,
) -> tuple[int, bytes] | None:
    """Read a frame from the bridge connection.

    Returns (frame_type, payload) or None on EOF.
    """
    header = await reader.readexactly(3)
    if not header or len(header) < 3:
        return None
    frame_type = header[0]
    length = struct.unpack("!H", header[1:3])[0]
    if length > 0:
        payload = await reader.readexactly(length)
    else:
        payload = b""
    return frame_type, payload


@router.websocket("/ssh/{session_id}")
async def terminal_ssh(websocket: WebSocket, session_id: str):
    """WebSocket relay for SSH web terminal sessions."""
    await _terminal_relay(websocket, session_id, "web-ssh")


@router.websocket("/db/{session_id}")
async def terminal_db(websocket: WebSocket, session_id: str):
    """WebSocket relay for database web terminal sessions."""
    await _terminal_relay(websocket, session_id, "web-db")


async def _terminal_relay(websocket: WebSocket, session_id: str, resource_type: str):
    """Common WebSocket relay logic for web terminal sessions.

    Flow:
    1. Accept WebSocket
    2. Validate ticket (from query param) via Redis GETDEL
    3. Load client creds from Redis
    4. Dial bridge via mTLS
    5. Read initial WebSocket message with credentials
    6. Forward credentials to bridge via frame protocol
    7. Wait for bridge "ready" status
    8. Enter stateless relay loop
    """
    r = get_redis_client()

    # Accept WebSocket first
    await websocket.accept()

    # Validate ticket from query params
    ticket = websocket.query_params.get("ticket")
    if not ticket:
        await websocket.close(code=4001, reason="Missing ticket")
        return

    ticket_data = await _validate_ticket(r, ticket, session_id)
    if not ticket_data:
        await websocket.close(code=4001, reason="Invalid or expired ticket")
        return

    # Load client creds from Redis (stored by connect.py _issue_session)
    creds_raw = await r.get(f"session:{session_id}:client_creds")
    if not creds_raw:
        await websocket.close(code=4002, reason="Session credentials not found")
        return

    creds = json.loads(creds_raw)

    # Dial bridge
    try:
        reader, writer = await dial_bridge(
            bridge_host=creds["bridge_host"],
            bridge_port=creds["bridge_port"],
            session_cert_pem=creds["cert"],
            session_key_pem=creds["key"],
            ca_cert_pem=creds["ca"],
            session_id=session_id,
            resource_type=resource_type,
        )
    except Exception as e:
        logger.warning(
            "Failed to dial bridge for terminal",
            session_id=session_id,
            error=str(e),
        )
        await websocket.close(code=4003, reason="Bridge connection failed")
        return

    try:
        # Read initial WebSocket message with credentials (SSH key or DB creds)
        initial_msg = await websocket.receive_text()
        msg = json.loads(initial_msg)

        # Read original resource type from session data to determine audit mode.
        # The session stores both "protocol" (web-ssh/web-db) and
        # "original_resource_type" (ssh, ssh-audit, postgres, etc.).
        session_raw = await r.get(f"session:{session_id}")
        original_resource_type = None
        if session_raw:
            session_info = json.loads(session_raw)
            original_resource_type = session_info.get("original_resource_type")
        is_audit = original_resource_type is not None and "-audit" in original_resource_type

        # Forward credentials to bridge via frame protocol
        await _send_credentials_to_bridge(writer, msg, resource_type, audit=is_audit)

        # Wait for bridge "ready" or "error" status
        frame = await _read_frame(reader)
        if frame is None:
            await websocket.close(code=4004, reason="Bridge disconnected")
            return

        frame_type, payload = frame
        if frame_type == FRAME_STATUS:
            status_msg = payload.decode("utf-8")
            if status_msg.startswith("error:"):
                await websocket.send_text(json.dumps({"type": "error", "message": status_msg[6:]}))
                await websocket.close(code=4005, reason=status_msg)
                return
            if status_msg != "ready":
                await websocket.close(code=4004, reason=f"Unexpected status: {status_msg}")
                return

        # Send ready to browser
        await websocket.send_text(json.dumps({"type": "status", "status": "ready"}))

        # Enter relay loop
        await _relay_loop(websocket, reader, writer)

    except WebSocketDisconnect:
        logger.debug("WebSocket disconnected", session_id=session_id)
    except asyncio.IncompleteReadError:
        logger.debug("Bridge connection closed", session_id=session_id)
    except Exception:
        logger.warning("Terminal relay error", session_id=session_id, exc_info=True)
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def _send_credentials_to_bridge(
    writer: asyncio.StreamWriter, msg: dict, resource_type: str, *, audit: bool = False
):
    """Forward credentials from the browser to the bridge via frame protocol.

    SSH key auth: status(cols/rows/user/audit/key-begin) → data(key) → status(key-end)
    SSH password: status(cols/rows/user/audit/auth=password) → data(password) → status(password-end)
    DB: sends cols/rows/username/database/password/db_type/audit via status frame.

    The ``audit`` flag tells the bridge whether to record the session (SSH) or
    tap queries (DB), matching the resource's -audit type classification.
    """
    audit_param = f"\naudit={'true' if audit else 'false'}"

    if resource_type == "web-ssh":
        auth_method = msg.get("auth_method", "key")

        if auth_method == "password":
            # Password auth: send params with auth=password marker
            params = (
                f"cols={msg['cols']}\nrows={msg['rows']}\nuser={msg['username']}"
                f"{audit_param}\nauth=password"
            )
            writer.write(_write_frame(FRAME_STATUS, params.encode()))

            # Password as a single data frame
            password = msg.get("password", "").encode()
            writer.write(_write_frame(FRAME_DATA, password))

            # End marker
            writer.write(_write_frame(FRAME_STATUS, b"password-end"))
            await writer.drain()
        else:
            # Key auth: send params with key-begin marker
            params = (
                f"cols={msg['cols']}\nrows={msg['rows']}\nuser={msg['username']}"
                f"{audit_param}\nkey-begin"
            )
            writer.write(_write_frame(FRAME_STATUS, params.encode()))

            # Key data as data frames (split into chunks if large)
            key_pem = msg["key"].encode()
            chunk_size = 16384  # 16KB chunks
            for i in range(0, len(key_pem), chunk_size):
                writer.write(_write_frame(FRAME_DATA, key_pem[i : i + chunk_size]))

            # End marker
            writer.write(_write_frame(FRAME_STATUS, b"key-end"))
            await writer.drain()

    elif resource_type == "web-db":
        # All DB params in a single status frame
        params = (
            f"cols={msg['cols']}\nrows={msg['rows']}\n"
            f"user={msg['username']}\ndatabase={msg['database']}\n"
            f"password={msg['password']}\ndb_type={msg['db_type']}"
            f"{audit_param}"
        )
        writer.write(_write_frame(FRAME_STATUS, params.encode()))
        await writer.drain()


async def _relay_loop(
    websocket: WebSocket,
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
):
    """Bidirectional relay between WebSocket and bridge frame protocol.

    - WebSocket binary → frame 0x01 → bridge
    - WebSocket text {"type":"resize",...} → frame 0x02 → bridge
    - Bridge frame 0x01 → WebSocket binary
    - Bridge frame 0x03 → WebSocket text
    """

    async def ws_to_bridge():
        """Read from WebSocket, write frames to bridge."""
        try:
            while True:
                message = await websocket.receive()
                if message.get("type") == "websocket.disconnect":
                    break

                if "bytes" in message and message["bytes"]:
                    # Terminal data
                    writer.write(_write_frame(FRAME_DATA, message["bytes"]))
                    await writer.drain()
                elif "text" in message and message["text"]:
                    # Control message (resize)
                    try:
                        ctrl = json.loads(message["text"])
                        if ctrl.get("type") == "resize":
                            cols = int(ctrl["cols"])
                            rows = int(ctrl["rows"])
                            payload = struct.pack("!HH", cols, rows)
                            writer.write(_write_frame(FRAME_RESIZE, payload))
                            await writer.drain()
                    except (json.JSONDecodeError, KeyError, ValueError):
                        pass
        except WebSocketDisconnect:
            pass
        except Exception:
            pass

    async def bridge_to_ws():
        """Read frames from bridge, write to WebSocket."""
        try:
            while True:
                frame = await _read_frame(reader)
                if frame is None:
                    break

                frame_type, payload = frame
                if frame_type == FRAME_DATA:
                    await websocket.send_bytes(payload)
                elif frame_type == FRAME_STATUS:
                    status_msg = payload.decode("utf-8")
                    await websocket.send_text(json.dumps({"type": "status", "status": status_msg}))
        except asyncio.IncompleteReadError:
            pass
        except WebSocketDisconnect:
            pass
        except Exception:
            pass

    # Run both directions concurrently; when either finishes, cancel the other
    ws_task = asyncio.create_task(ws_to_bridge())
    bridge_task = asyncio.create_task(bridge_to_ws())

    try:
        done, pending = await asyncio.wait(
            [ws_task, bridge_task], return_when=asyncio.FIRST_COMPLETED
        )
        for task in pending:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
    except Exception:
        ws_task.cancel()
        bridge_task.cancel()
