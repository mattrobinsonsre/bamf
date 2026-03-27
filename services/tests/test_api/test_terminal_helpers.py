"""Tests for terminal router helper functions.

Covers the testable functions in bamf/api/routers/terminal.py:
- _write_frame: binary frame encoding (type + 2-byte big-endian length + payload)
- _read_frame: binary frame decoding from an asyncio.StreamReader
- _validate_ticket: one-time ticket consumption via Redis GETDEL
- create_ticket: POST endpoint issuing one-time WebSocket auth tickets
- _send_credentials_to_bridge: credential marshalling into frame protocol
"""

from __future__ import annotations

import asyncio
import json
import struct
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from bamf.api.dependencies import get_current_user
from bamf.api.routers.terminal import (
    FRAME_DATA,
    FRAME_RESIZE,
    FRAME_STATUS,
    TICKET_TTL,
    _read_frame,
    _send_credentials_to_bridge,
    _validate_ticket,
    _write_frame,
    router,
)
from bamf.auth.sessions import Session
from bamf.db.session import get_db_read
from bamf.redis.client import get_redis

# ── Shared fixtures and helpers ──────────────────────────────────────

_NOW = datetime.now(UTC).isoformat()

USER_SESSION = Session(
    email="alice@example.com",
    display_name="Alice",
    roles=["developer"],
    provider_name="local",
    created_at=_NOW,
    expires_at=_NOW,
    last_active_at=_NOW,
)


def _make_mock_redis():
    r = AsyncMock()
    r.get = AsyncMock(return_value=None)
    r.getdel = AsyncMock(return_value=None)
    r.setex = AsyncMock()
    return r


def _make_stream_reader(data: bytes) -> asyncio.StreamReader:
    """Create an asyncio.StreamReader pre-loaded with data."""
    reader = asyncio.StreamReader()
    reader.feed_data(data)
    reader.feed_eof()
    return reader


def _make_mock_writer() -> AsyncMock:
    """Create a mock asyncio.StreamWriter with write and drain."""
    writer = AsyncMock(spec=asyncio.StreamWriter)
    writer._buffer = bytearray()

    def capture_write(data: bytes):
        writer._buffer.extend(data)

    writer.write = MagicMock(side_effect=capture_write)
    writer.drain = AsyncMock()
    return writer


@pytest.fixture
def mock_redis():
    return _make_mock_redis()


@pytest.fixture
def mock_db():
    return AsyncMock()


@pytest.fixture
def terminal_app(mock_redis, mock_db):
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")

    async def override_redis():
        yield mock_redis

    async def override_db():
        yield mock_db

    async def override_user() -> Session:
        return USER_SESSION

    app.dependency_overrides[get_redis] = override_redis
    app.dependency_overrides[get_db_read] = override_db
    app.dependency_overrides[get_current_user] = override_user
    return app


@pytest.fixture
async def terminal_client(terminal_app):
    async with AsyncClient(
        transport=ASGITransport(app=terminal_app),
        base_url="http://test",
    ) as client:
        yield client


# ── Tests: _write_frame ──────────────────────────────────────────────


class TestWriteFrame:
    """Test binary frame encoding: [1-byte type][2-byte length][payload]."""

    def test_data_frame_structure(self):
        """FRAME_DATA encodes type byte, big-endian length, then payload."""
        result = _write_frame(FRAME_DATA, b"hello")
        assert result[0] == 0x01
        length = struct.unpack("!H", result[1:3])[0]
        assert length == 5
        assert result[3:] == b"hello"

    def test_status_frame(self):
        """FRAME_STATUS encodes a UTF-8 status string."""
        result = _write_frame(FRAME_STATUS, b"ready")
        assert result[0] == 0x03
        length = struct.unpack("!H", result[1:3])[0]
        assert length == 5
        assert result[3:] == b"ready"

    def test_resize_frame(self):
        """FRAME_RESIZE with packed terminal dimensions."""
        payload = struct.pack("!HH", 80, 24)
        result = _write_frame(FRAME_RESIZE, payload)
        assert result[0] == 0x02
        length = struct.unpack("!H", result[1:3])[0]
        assert length == 4

    def test_empty_payload(self):
        """Empty payload produces a 3-byte header-only frame."""
        result = _write_frame(FRAME_DATA, b"")
        assert len(result) == 3
        assert result[0] == 0x01
        assert struct.unpack("!H", result[1:3])[0] == 0

    def test_total_length_is_header_plus_payload(self):
        """Total frame length is always 3 + len(payload)."""
        for size in [0, 1, 10, 100, 1000, 16384]:
            payload = b"x" * size
            result = _write_frame(FRAME_DATA, payload)
            assert len(result) == 3 + size

    def test_binary_payload_preserved(self):
        """Arbitrary binary data survives encoding unchanged."""
        payload = bytes(range(256))
        result = _write_frame(FRAME_DATA, payload)
        assert result[3:] == payload

    def test_max_two_byte_length(self):
        """Payload up to 65535 bytes fits in the 2-byte length field."""
        payload = b"A" * 65535
        result = _write_frame(FRAME_DATA, payload)
        length = struct.unpack("!H", result[1:3])[0]
        assert length == 65535
        assert len(result) == 3 + 65535


# ── Tests: _read_frame ───────────────────────────────────────────────


class TestReadFrame:
    """Test binary frame decoding from asyncio.StreamReader."""

    @pytest.mark.asyncio
    async def test_read_data_frame(self):
        """Read a well-formed data frame."""
        raw = _write_frame(FRAME_DATA, b"hello world")
        reader = _make_stream_reader(raw)
        result = await _read_frame(reader)
        assert result is not None
        frame_type, payload = result
        assert frame_type == FRAME_DATA
        assert payload == b"hello world"

    @pytest.mark.asyncio
    async def test_read_status_frame(self):
        """Read a well-formed status frame."""
        raw = _write_frame(FRAME_STATUS, b"ready")
        reader = _make_stream_reader(raw)
        result = await _read_frame(reader)
        assert result is not None
        frame_type, payload = result
        assert frame_type == FRAME_STATUS
        assert payload == b"ready"

    @pytest.mark.asyncio
    async def test_read_resize_frame(self):
        """Read a resize frame with packed dimensions."""
        dims = struct.pack("!HH", 120, 40)
        raw = _write_frame(FRAME_RESIZE, dims)
        reader = _make_stream_reader(raw)
        result = await _read_frame(reader)
        assert result is not None
        frame_type, payload = result
        assert frame_type == FRAME_RESIZE
        cols, rows = struct.unpack("!HH", payload)
        assert cols == 120
        assert rows == 40

    @pytest.mark.asyncio
    async def test_read_empty_payload(self):
        """Read a frame with zero-length payload."""
        raw = _write_frame(FRAME_DATA, b"")
        reader = _make_stream_reader(raw)
        result = await _read_frame(reader)
        assert result is not None
        frame_type, payload = result
        assert frame_type == FRAME_DATA
        assert payload == b""

    @pytest.mark.asyncio
    async def test_read_large_payload(self):
        """Read a frame with a 16KB payload."""
        data = b"Z" * 16384
        raw = _write_frame(FRAME_DATA, data)
        reader = _make_stream_reader(raw)
        result = await _read_frame(reader)
        assert result is not None
        frame_type, payload = result
        assert frame_type == FRAME_DATA
        assert payload == data

    @pytest.mark.asyncio
    async def test_eof_raises_incomplete_read(self):
        """EOF before full header raises IncompleteReadError."""
        reader = _make_stream_reader(b"")
        with pytest.raises(asyncio.IncompleteReadError):
            await _read_frame(reader)

    @pytest.mark.asyncio
    async def test_truncated_header_raises(self):
        """Incomplete header (only 2 bytes) raises IncompleteReadError."""
        reader = _make_stream_reader(b"\x01\x00")
        with pytest.raises(asyncio.IncompleteReadError):
            await _read_frame(reader)

    @pytest.mark.asyncio
    async def test_truncated_payload_raises(self):
        """Header claims 10 bytes but only 3 are available."""
        header = struct.pack("!BH", FRAME_DATA, 10)
        reader = _make_stream_reader(header + b"abc")
        with pytest.raises(asyncio.IncompleteReadError):
            await _read_frame(reader)

    @pytest.mark.asyncio
    async def test_roundtrip_write_then_read(self):
        """Write a frame, then read it back. Data must match exactly."""
        original = b"roundtrip test payload \x00\xff"
        raw = _write_frame(FRAME_STATUS, original)
        reader = _make_stream_reader(raw)
        result = await _read_frame(reader)
        assert result is not None
        frame_type, payload = result
        assert frame_type == FRAME_STATUS
        assert payload == original

    @pytest.mark.asyncio
    async def test_multiple_frames_sequential(self):
        """Read two consecutive frames from the same stream."""
        frame1 = _write_frame(FRAME_DATA, b"first")
        frame2 = _write_frame(FRAME_STATUS, b"second")
        reader = _make_stream_reader(frame1 + frame2)

        r1 = await _read_frame(reader)
        assert r1 is not None
        assert r1[0] == FRAME_DATA
        assert r1[1] == b"first"

        r2 = await _read_frame(reader)
        assert r2 is not None
        assert r2[0] == FRAME_STATUS
        assert r2[1] == b"second"

    @pytest.mark.asyncio
    async def test_binary_payload_roundtrip(self):
        """Binary data (all byte values) survives roundtrip."""
        original = bytes(range(256))
        raw = _write_frame(FRAME_DATA, original)
        reader = _make_stream_reader(raw)
        result = await _read_frame(reader)
        assert result is not None
        assert result[1] == original


# ── Tests: _validate_ticket ──────────────────────────────────────────


class TestValidateTicket:
    """Test one-time ticket validation via Redis GETDEL."""

    @pytest.mark.asyncio
    async def test_valid_ticket(self):
        """Valid ticket is consumed and returns ticket data dict."""
        r = AsyncMock()
        ticket_data = {"session_id": "sess-1", "user_email": "alice@example.com"}
        r.getdel = AsyncMock(return_value=json.dumps(ticket_data))

        result = await _validate_ticket(r, "ticket-abc", "sess-1")
        assert result is not None
        assert result["session_id"] == "sess-1"
        assert result["user_email"] == "alice@example.com"
        r.getdel.assert_called_once_with("terminal:ticket:ticket-abc")

    @pytest.mark.asyncio
    async def test_missing_ticket_returns_none(self):
        """Non-existent or expired ticket returns None."""
        r = AsyncMock()
        r.getdel = AsyncMock(return_value=None)

        result = await _validate_ticket(r, "gone", "sess-1")
        assert result is None

    @pytest.mark.asyncio
    async def test_session_id_mismatch_returns_none(self):
        """Ticket for a different session returns None."""
        r = AsyncMock()
        ticket_data = {"session_id": "sess-other", "user_email": "alice@example.com"}
        r.getdel = AsyncMock(return_value=json.dumps(ticket_data))

        result = await _validate_ticket(r, "ticket-abc", "sess-1")
        assert result is None

    @pytest.mark.asyncio
    async def test_missing_session_id_field_returns_none(self):
        """Ticket data without session_id field returns None."""
        r = AsyncMock()
        ticket_data = {"user_email": "alice@example.com"}
        r.getdel = AsyncMock(return_value=json.dumps(ticket_data))

        result = await _validate_ticket(r, "ticket-abc", "sess-1")
        assert result is None

    @pytest.mark.asyncio
    async def test_consumed_exactly_once(self):
        """GETDEL ensures the ticket cannot be reused."""
        r = AsyncMock()
        ticket_data = json.dumps({"session_id": "sess-1", "user_email": "a@b.com"})
        r.getdel = AsyncMock(side_effect=[ticket_data, None])

        first = await _validate_ticket(r, "ticket-abc", "sess-1")
        second = await _validate_ticket(r, "ticket-abc", "sess-1")

        assert first is not None
        assert second is None
        assert r.getdel.call_count == 2

    @pytest.mark.asyncio
    async def test_redis_key_format(self):
        """Verify the Redis key uses the terminal:ticket: prefix."""
        r = AsyncMock()
        r.getdel = AsyncMock(return_value=None)

        await _validate_ticket(r, "my-token", "any")
        r.getdel.assert_called_once_with("terminal:ticket:my-token")


# ── Tests: create_ticket endpoint ────────────────────────────────────


class TestCreateTicketEndpoint:
    """Test POST /terminal/ticket with dependency overrides."""

    @pytest.mark.asyncio
    async def test_session_not_found_returns_404(self, terminal_client, mock_redis):
        """Missing session in Redis returns 404."""
        mock_redis.get.return_value = None

        resp = await terminal_client.post(
            "/api/v1/terminal/ticket",
            json={"session_id": "nonexistent"},
            headers={"Authorization": "Bearer test-token"},
        )
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_wrong_user_returns_403(self, terminal_client, mock_redis):
        """Session belonging to a different user returns 403."""
        session_data = json.dumps(
            {
                "user_email": "bob@example.com",
                "resource_name": "grafana",
            }
        )
        mock_redis.get.return_value = session_data

        resp = await terminal_client.post(
            "/api/v1/terminal/ticket",
            json={"session_id": "sess-1"},
            headers={"Authorization": "Bearer test-token"},
        )
        assert resp.status_code == 403
        assert "does not belong" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_rbac_revoked_returns_403(self, terminal_client, mock_redis):
        """Ticket is denied when RBAC check fails (roles changed)."""
        session_data = json.dumps(
            {
                "user_email": "alice@example.com",
                "resource_name": "grafana",
            }
        )
        mock_redis.get.return_value = session_data

        mock_resource = MagicMock()
        mock_resource.name = "grafana"

        with (
            patch(
                "bamf.api.routers.terminal.get_resource",
                new_callable=AsyncMock,
                return_value=mock_resource,
            ),
            patch(
                "bamf.api.routers.terminal.check_access",
                new_callable=AsyncMock,
                return_value=False,
            ),
        ):
            resp = await terminal_client.post(
                "/api/v1/terminal/ticket",
                json={"session_id": "sess-1"},
                headers={"Authorization": "Bearer test-token"},
            )
        assert resp.status_code == 403
        assert "revoked" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_successful_ticket_issuance(self, terminal_client, mock_redis):
        """Valid session + RBAC pass returns a ticket."""
        session_data = json.dumps(
            {
                "user_email": "alice@example.com",
                "resource_name": "grafana",
            }
        )
        mock_redis.get.return_value = session_data

        mock_resource = MagicMock()
        mock_resource.name = "grafana"

        with (
            patch(
                "bamf.api.routers.terminal.get_resource",
                new_callable=AsyncMock,
                return_value=mock_resource,
            ),
            patch(
                "bamf.api.routers.terminal.check_access",
                new_callable=AsyncMock,
                return_value=True,
            ),
        ):
            resp = await terminal_client.post(
                "/api/v1/terminal/ticket",
                json={"session_id": "sess-1"},
                headers={"Authorization": "Bearer test-token"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert "ticket" in data
        assert len(data["ticket"]) > 20

        # Verify ticket stored in Redis with correct TTL
        mock_redis.setex.assert_called_once()
        args = mock_redis.setex.call_args[0]
        assert args[0].startswith("terminal:ticket:")
        assert args[1] == TICKET_TTL

        # Verify stored data contains session_id and user_email
        stored_data = json.loads(args[2])
        assert stored_data["session_id"] == "sess-1"
        assert stored_data["user_email"] == "alice@example.com"

    @pytest.mark.asyncio
    async def test_resource_gone_still_issues_ticket(self, terminal_client, mock_redis):
        """When resource is no longer in catalog, ticket is still issued."""
        session_data = json.dumps(
            {
                "user_email": "alice@example.com",
                "resource_name": "deleted-app",
            }
        )
        mock_redis.get.return_value = session_data

        with patch(
            "bamf.api.routers.terminal.get_resource",
            new_callable=AsyncMock,
            return_value=None,
        ):
            resp = await terminal_client.post(
                "/api/v1/terminal/ticket",
                json={"session_id": "sess-1"},
                headers={"Authorization": "Bearer test-token"},
            )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_no_resource_name_skips_rbac(self, terminal_client, mock_redis):
        """Session without resource_name skips RBAC and still issues ticket."""
        session_data = json.dumps(
            {
                "user_email": "alice@example.com",
            }
        )
        mock_redis.get.return_value = session_data

        resp = await terminal_client.post(
            "/api/v1/terminal/ticket",
            json={"session_id": "sess-1"},
            headers={"Authorization": "Bearer test-token"},
        )
        assert resp.status_code == 200
        assert "ticket" in resp.json()

    @pytest.mark.asyncio
    async def test_empty_session_id_rejected(self, terminal_client):
        """Empty session_id fails Pydantic validation (422)."""
        resp = await terminal_client.post(
            "/api/v1/terminal/ticket",
            json={"session_id": ""},
            headers={"Authorization": "Bearer test-token"},
        )
        assert resp.status_code == 422

    @pytest.mark.asyncio
    async def test_missing_session_id_rejected(self, terminal_client):
        """Missing session_id field fails Pydantic validation (422)."""
        resp = await terminal_client.post(
            "/api/v1/terminal/ticket",
            json={},
            headers={"Authorization": "Bearer test-token"},
        )
        assert resp.status_code == 422


# ── Tests: _send_credentials_to_bridge ───────────────────────────────


class TestSendCredentialsToBridge:
    """Test credential marshalling into frame protocol for SSH and DB."""

    @pytest.mark.asyncio
    async def test_ssh_key_auth(self):
        """SSH key auth sends status(params+key-begin), data(key), status(key-end)."""
        writer = _make_mock_writer()
        msg = {
            "cols": 80,
            "rows": 24,
            "username": "root",
            "auth_method": "key",
            "key": "-----BEGIN OPENSSH PRIVATE KEY-----\nfake-key-data\n-----END OPENSSH PRIVATE KEY-----",
        }

        await _send_credentials_to_bridge(writer, msg, "web-ssh", audit=False)

        # Parse all frames from the buffer
        buf = bytes(writer._buffer)
        frames = _parse_all_frames(buf)

        assert len(frames) == 3

        # First frame: status with params and key-begin
        assert frames[0][0] == FRAME_STATUS
        params = frames[0][1].decode()
        assert "cols=80" in params
        assert "rows=24" in params
        assert "user=root" in params
        assert "audit=false" in params
        assert "key-begin" in params

        # Second frame: data with key PEM
        assert frames[1][0] == FRAME_DATA
        assert b"BEGIN OPENSSH PRIVATE KEY" in frames[1][1]

        # Third frame: status with key-end
        assert frames[2][0] == FRAME_STATUS
        assert frames[2][1] == b"key-end"

        writer.drain.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_ssh_key_auth_with_audit(self):
        """SSH key auth with audit=True includes audit=true in params."""
        writer = _make_mock_writer()
        msg = {
            "cols": 120,
            "rows": 40,
            "username": "admin",
            "auth_method": "key",
            "key": "fake-key",
        }

        await _send_credentials_to_bridge(writer, msg, "web-ssh", audit=True)

        buf = bytes(writer._buffer)
        frames = _parse_all_frames(buf)

        params = frames[0][1].decode()
        assert "audit=true" in params

    @pytest.mark.asyncio
    async def test_ssh_password_auth(self):
        """SSH password auth sends status(params+auth=password), data(password), status(password-end)."""
        writer = _make_mock_writer()
        msg = {
            "cols": 132,
            "rows": 43,
            "username": "deploy",
            "auth_method": "password",
            "password": "s3cret!",
        }

        await _send_credentials_to_bridge(writer, msg, "web-ssh", audit=False)

        buf = bytes(writer._buffer)
        frames = _parse_all_frames(buf)

        assert len(frames) == 3

        # First frame: status with params and auth=password
        assert frames[0][0] == FRAME_STATUS
        params = frames[0][1].decode()
        assert "cols=132" in params
        assert "rows=43" in params
        assert "user=deploy" in params
        assert "audit=false" in params
        assert "auth=password" in params

        # Second frame: data with the password
        assert frames[1][0] == FRAME_DATA
        assert frames[1][1] == b"s3cret!"

        # Third frame: status with password-end
        assert frames[2][0] == FRAME_STATUS
        assert frames[2][1] == b"password-end"

        writer.drain.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_ssh_password_empty(self):
        """SSH password auth with empty password sends empty data frame."""
        writer = _make_mock_writer()
        msg = {
            "cols": 80,
            "rows": 24,
            "username": "user",
            "auth_method": "password",
        }

        await _send_credentials_to_bridge(writer, msg, "web-ssh", audit=False)

        buf = bytes(writer._buffer)
        frames = _parse_all_frames(buf)

        assert frames[1][0] == FRAME_DATA
        assert frames[1][1] == b""

    @pytest.mark.asyncio
    async def test_ssh_default_auth_method_is_key(self):
        """When auth_method is not specified, defaults to key auth."""
        writer = _make_mock_writer()
        msg = {
            "cols": 80,
            "rows": 24,
            "username": "user",
            "key": "my-key-pem",
        }

        await _send_credentials_to_bridge(writer, msg, "web-ssh", audit=False)

        buf = bytes(writer._buffer)
        frames = _parse_all_frames(buf)

        # Should use key auth (key-begin / key-end markers)
        params = frames[0][1].decode()
        assert "key-begin" in params
        assert frames[2][1] == b"key-end"

    @pytest.mark.asyncio
    async def test_ssh_large_key_chunked(self):
        """SSH key larger than 16KB is split into multiple data frames."""
        writer = _make_mock_writer()
        large_key = "K" * 40000  # 40KB key
        msg = {
            "cols": 80,
            "rows": 24,
            "username": "user",
            "auth_method": "key",
            "key": large_key,
        }

        await _send_credentials_to_bridge(writer, msg, "web-ssh", audit=False)

        buf = bytes(writer._buffer)
        frames = _parse_all_frames(buf)

        # First: status (params), then multiple data frames, then status (key-end)
        assert frames[0][0] == FRAME_STATUS
        assert frames[-1][0] == FRAME_STATUS
        assert frames[-1][1] == b"key-end"

        # Data frames are in the middle
        data_frames = [f for f in frames[1:-1] if f[0] == FRAME_DATA]
        assert len(data_frames) == 3  # 40000 / 16384 = 2.44 -> 3 chunks

        # Reassemble and verify
        reassembled = b"".join(f[1] for f in data_frames)
        assert reassembled == large_key.encode()

    @pytest.mark.asyncio
    async def test_db_credentials(self):
        """DB credentials are sent in a single status frame."""
        writer = _make_mock_writer()
        msg = {
            "cols": 80,
            "rows": 24,
            "username": "dbadmin",
            "database": "mydb",
            "password": "dbpass",
            "db_type": "postgres",
        }

        await _send_credentials_to_bridge(writer, msg, "web-db", audit=False)

        buf = bytes(writer._buffer)
        frames = _parse_all_frames(buf)

        assert len(frames) == 1
        assert frames[0][0] == FRAME_STATUS

        params = frames[0][1].decode()
        assert "cols=80" in params
        assert "rows=24" in params
        assert "user=dbadmin" in params
        assert "database=mydb" in params
        assert "password=dbpass" in params
        assert "db_type=postgres" in params
        assert "audit=false" in params

        writer.drain.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_db_credentials_with_audit(self):
        """DB credentials with audit=True include audit=true in params."""
        writer = _make_mock_writer()
        msg = {
            "cols": 120,
            "rows": 40,
            "username": "admin",
            "database": "orders",
            "password": "secret",
            "db_type": "mysql",
        }

        await _send_credentials_to_bridge(writer, msg, "web-db", audit=True)

        buf = bytes(writer._buffer)
        frames = _parse_all_frames(buf)

        params = frames[0][1].decode()
        assert "audit=true" in params
        assert "db_type=mysql" in params

    @pytest.mark.asyncio
    async def test_db_mysql_type(self):
        """MySQL db_type is included in the frame params."""
        writer = _make_mock_writer()
        msg = {
            "cols": 80,
            "rows": 24,
            "username": "root",
            "database": "app",
            "password": "pass",
            "db_type": "mysql",
        }

        await _send_credentials_to_bridge(writer, msg, "web-db", audit=False)

        buf = bytes(writer._buffer)
        frames = _parse_all_frames(buf)
        params = frames[0][1].decode()
        assert "db_type=mysql" in params


# ── Frame parsing helper ─────────────────────────────────────────────


def _parse_all_frames(data: bytes) -> list[tuple[int, bytes]]:
    """Parse all frames from a byte buffer. Returns list of (type, payload)."""
    frames = []
    offset = 0
    while offset < len(data):
        if offset + 3 > len(data):
            break
        frame_type = data[offset]
        length = struct.unpack("!H", data[offset + 1 : offset + 3])[0]
        offset += 3
        payload = data[offset : offset + length]
        offset += length
        frames.append((frame_type, payload))
    return frames
