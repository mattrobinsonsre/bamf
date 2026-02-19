"""Tests for terminal router helper functions.

Tests cover:
- _validate_ticket: one-time ticket consumption via Redis GETDEL
- _write_frame: binary frame encoding (type + length + payload)
- _is_excluded: middleware path exclusion logic
"""

import json
import struct
from unittest.mock import AsyncMock

import pytest

from bamf.api.middleware import _is_excluded
from bamf.api.routers.terminal import (
    FRAME_DATA,
    FRAME_RESIZE,
    FRAME_STATUS,
    _validate_ticket,
    _write_frame,
)


class TestWriteFrame:
    """Test binary frame encoding."""

    def test_data_frame(self):
        """Data frame (0x01) encodes type + 2-byte big-endian length + payload."""
        payload = b"hello"
        result = _write_frame(FRAME_DATA, payload)

        assert result[0:1] == bytes([0x01])  # type
        length = struct.unpack("!H", result[1:3])[0]
        assert length == 5
        assert result[3:] == b"hello"

    def test_resize_frame(self):
        """Resize frame (0x02) encodes terminal dimensions as payload."""
        cols, rows = 120, 40
        payload = struct.pack("!HH", cols, rows)
        result = _write_frame(FRAME_RESIZE, payload)

        assert result[0] == 0x02
        length = struct.unpack("!H", result[1:3])[0]
        assert length == 4  # 2 shorts = 4 bytes
        decoded_cols, decoded_rows = struct.unpack("!HH", result[3:])
        assert decoded_cols == 120
        assert decoded_rows == 40

    def test_status_frame(self):
        """Status frame (0x03) encodes a UTF-8 status string."""
        payload = b"ready"
        result = _write_frame(FRAME_STATUS, payload)

        assert result[0] == 0x03
        length = struct.unpack("!H", result[1:3])[0]
        assert length == 5
        assert result[3:] == b"ready"

    def test_empty_payload(self):
        """Empty payload produces a 3-byte frame (header only)."""
        result = _write_frame(FRAME_DATA, b"")

        assert len(result) == 3
        assert result[0] == 0x01
        length = struct.unpack("!H", result[1:3])[0]
        assert length == 0

    def test_large_payload(self):
        """Frame correctly encodes a payload up to 64KB (max for 2-byte length)."""
        payload = b"x" * 16384  # 16KB
        result = _write_frame(FRAME_DATA, payload)

        assert result[0] == 0x01
        length = struct.unpack("!H", result[1:3])[0]
        assert length == 16384
        assert result[3:] == payload
        assert len(result) == 3 + 16384

    def test_frame_total_length(self):
        """Total frame length is always 3 + len(payload)."""
        for size in [0, 1, 100, 1000]:
            payload = b"a" * size
            result = _write_frame(FRAME_DATA, payload)
            assert len(result) == 3 + size

    def test_binary_payload(self):
        """Frame correctly handles arbitrary binary data."""
        payload = bytes(range(256))
        result = _write_frame(FRAME_DATA, payload)

        assert result[0] == 0x01
        length = struct.unpack("!H", result[1:3])[0]
        assert length == 256
        assert result[3:] == payload


class TestValidateTicket:
    """Test one-time ticket validation via Redis GETDEL."""

    @pytest.fixture
    def mock_redis(self):
        """Create a mock Redis client."""
        return AsyncMock()

    @pytest.mark.asyncio
    async def test_valid_ticket_consumed(self, mock_redis):
        """Valid ticket is consumed via GETDEL and returns ticket data."""
        ticket_data = {
            "session_id": "session-abc",
            "user_email": "alice@example.com",
        }
        mock_redis.getdel = AsyncMock(return_value=json.dumps(ticket_data))

        result = await _validate_ticket(mock_redis, "ticket-123", "session-abc")

        assert result is not None
        assert result["session_id"] == "session-abc"
        assert result["user_email"] == "alice@example.com"
        mock_redis.getdel.assert_called_once_with("terminal:ticket:ticket-123")

    @pytest.mark.asyncio
    async def test_expired_ticket_returns_none(self, mock_redis):
        """Expired or missing ticket returns None (GETDEL returns nil)."""
        mock_redis.getdel = AsyncMock(return_value=None)

        result = await _validate_ticket(mock_redis, "expired-ticket", "session-abc")

        assert result is None
        mock_redis.getdel.assert_called_once_with("terminal:ticket:expired-ticket")

    @pytest.mark.asyncio
    async def test_wrong_session_id_returns_none(self, mock_redis):
        """Ticket for a different session_id returns None."""
        ticket_data = {
            "session_id": "session-xyz",
            "user_email": "alice@example.com",
        }
        mock_redis.getdel = AsyncMock(return_value=json.dumps(ticket_data))

        result = await _validate_ticket(mock_redis, "ticket-123", "session-abc")

        assert result is None

    @pytest.mark.asyncio
    async def test_ticket_consumed_exactly_once(self, mock_redis):
        """GETDEL ensures the ticket can only be used once."""
        ticket_data = {
            "session_id": "session-abc",
            "user_email": "alice@example.com",
        }
        # First call returns data, second call returns None (already consumed)
        mock_redis.getdel = AsyncMock(side_effect=[json.dumps(ticket_data), None])

        first = await _validate_ticket(mock_redis, "ticket-123", "session-abc")
        second = await _validate_ticket(mock_redis, "ticket-123", "session-abc")

        assert first is not None
        assert second is None
        assert mock_redis.getdel.call_count == 2

    @pytest.mark.asyncio
    async def test_ticket_missing_session_id_field(self, mock_redis):
        """Ticket data without session_id field returns None."""
        ticket_data = {
            "user_email": "alice@example.com",
        }
        mock_redis.getdel = AsyncMock(return_value=json.dumps(ticket_data))

        result = await _validate_ticket(mock_redis, "ticket-123", "session-abc")

        assert result is None

    @pytest.mark.asyncio
    async def test_redis_key_format(self, mock_redis):
        """Verify the correct Redis key format is used for lookup."""
        mock_redis.getdel = AsyncMock(return_value=None)

        await _validate_ticket(mock_redis, "my-ticket-token", "any-session")

        mock_redis.getdel.assert_called_once_with("terminal:ticket:my-ticket-token")


class TestIsExcluded:
    """Test middleware path exclusion logic."""

    def test_health_excluded(self):
        """Health endpoint is excluded from audit."""
        assert _is_excluded("/health") is True

    def test_health_subpath_excluded(self):
        """Health subpaths are excluded from audit."""
        assert _is_excluded("/health/details") is True

    def test_ready_excluded(self):
        """Ready endpoint is excluded from audit."""
        assert _is_excluded("/ready") is True

    def test_docs_excluded(self):
        """API docs are excluded from audit."""
        assert _is_excluded("/api/docs") is True

    def test_redoc_excluded(self):
        """ReDoc page is excluded from audit."""
        assert _is_excluded("/api/redoc") is True

    def test_openapi_json_excluded(self):
        """OpenAPI JSON spec is excluded from audit."""
        assert _is_excluded("/api/openapi.json") is True

    def test_metrics_excluded(self):
        """Metrics endpoint is excluded from audit."""
        assert _is_excluded("/metrics") is True

    def test_api_v1_not_excluded(self):
        """Normal API endpoints are NOT excluded."""
        assert _is_excluded("/api/v1/users") is False

    def test_api_auth_not_excluded(self):
        """Auth endpoints are NOT excluded."""
        assert _is_excluded("/api/v1/auth/token") is False

    def test_terminal_not_excluded(self):
        """Terminal endpoints are NOT excluded."""
        assert _is_excluded("/api/v1/terminal/ticket") is False

    def test_root_not_excluded(self):
        """Root path is NOT excluded."""
        assert _is_excluded("/") is False

    def test_empty_path_not_excluded(self):
        """Empty path is NOT excluded."""
        assert _is_excluded("") is False

    def test_connect_not_excluded(self):
        """Connect endpoint is NOT excluded."""
        assert _is_excluded("/api/v1/connect") is False
