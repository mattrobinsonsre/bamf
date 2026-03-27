"""Tests for terminal router.

Tests POST /terminal/ticket for session validation, RBAC re-check,
one-time ticket issuance, and frame protocol encoding/decoding helpers.
"""

from __future__ import annotations

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
    _validate_ticket,
    _write_frame,
    router,
)
from bamf.auth.sessions import Session
from bamf.db.session import get_db_read
from bamf.redis.client import get_redis

# ── Fixtures ──────────────────────────────────────────────────────────────

_NOW = datetime.now(UTC).isoformat()

USER_SESSION = Session(
    email="user@example.com",
    display_name="User",
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


# ── Tests: Frame Protocol Helpers ────────────────────────────────────────


class TestWriteFrame:
    def test_data_frame(self):
        result = _write_frame(FRAME_DATA, b"hello")
        assert result[0] == FRAME_DATA
        length = struct.unpack("!H", result[1:3])[0]
        assert length == 5
        assert result[3:] == b"hello"

    def test_empty_payload(self):
        result = _write_frame(FRAME_STATUS, b"")
        assert result[0] == FRAME_STATUS
        length = struct.unpack("!H", result[1:3])[0]
        assert length == 0
        assert result[3:] == b""

    def test_resize_frame(self):
        cols_rows = struct.pack("!HH", 120, 40)
        result = _write_frame(FRAME_RESIZE, cols_rows)
        assert result[0] == FRAME_RESIZE
        length = struct.unpack("!H", result[1:3])[0]
        assert length == 4

    def test_large_payload(self):
        payload = b"x" * 1000
        result = _write_frame(FRAME_DATA, payload)
        length = struct.unpack("!H", result[1:3])[0]
        assert length == 1000
        assert result[3:] == payload


class TestFrameConstants:
    def test_frame_data_value(self):
        assert FRAME_DATA == 0x01

    def test_frame_resize_value(self):
        assert FRAME_RESIZE == 0x02

    def test_frame_status_value(self):
        assert FRAME_STATUS == 0x03

    def test_ticket_ttl(self):
        assert TICKET_TTL == 60


# ── Tests: Validate Ticket ───────────────────────────────────────────────


class TestValidateTicket:
    @pytest.mark.asyncio
    async def test_ticket_not_found(self):
        r = AsyncMock()
        r.getdel = AsyncMock(return_value=None)

        result = await _validate_ticket(r, "nonexistent", "sess-1")
        assert result is None
        r.getdel.assert_called_once_with("terminal:ticket:nonexistent")

    @pytest.mark.asyncio
    async def test_session_id_mismatch(self):
        r = AsyncMock()
        ticket_data = json.dumps({"session_id": "sess-1", "user_email": "a@b.com"})
        r.getdel = AsyncMock(return_value=ticket_data)

        result = await _validate_ticket(r, "ticket-abc", "sess-wrong")
        assert result is None

    @pytest.mark.asyncio
    async def test_valid_ticket(self):
        r = AsyncMock()
        ticket_data = json.dumps({"session_id": "sess-1", "user_email": "a@b.com"})
        r.getdel = AsyncMock(return_value=ticket_data)

        result = await _validate_ticket(r, "ticket-abc", "sess-1")
        assert result is not None
        assert result["session_id"] == "sess-1"
        assert result["user_email"] == "a@b.com"

    @pytest.mark.asyncio
    async def test_ticket_consumed_atomically(self):
        """Ticket is consumed via GETDEL — second call returns None."""
        r = AsyncMock()
        ticket_data = json.dumps({"session_id": "sess-1", "user_email": "a@b.com"})
        r.getdel = AsyncMock(side_effect=[ticket_data, None])

        result1 = await _validate_ticket(r, "ticket-abc", "sess-1")
        result2 = await _validate_ticket(r, "ticket-abc", "sess-1")

        assert result1 is not None
        assert result2 is None


# ── Tests: Create Ticket Endpoint ────────────────────────────────────────


class TestCreateTicket:
    @pytest.mark.asyncio
    async def test_session_not_found(self, terminal_client, mock_redis):
        mock_redis.get.return_value = None

        resp = await terminal_client.post(
            "/api/v1/terminal/ticket",
            json={"session_id": "nonexistent"},
            headers={"Authorization": "Bearer test"},
        )

        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_wrong_user(self, terminal_client, mock_redis):
        session_data = json.dumps(
            {
                "user_email": "other@example.com",
                "resource_name": "web-01",
            }
        )
        mock_redis.get.return_value = session_data

        resp = await terminal_client.post(
            "/api/v1/terminal/ticket",
            json={"session_id": "sess-1"},
            headers={"Authorization": "Bearer test"},
        )

        assert resp.status_code == 403
        assert "does not belong" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_rbac_revoked(self, terminal_client, mock_redis, mock_db):
        """Access denied when roles changed after session creation."""
        session_data = json.dumps(
            {
                "user_email": "user@example.com",
                "resource_name": "web-01",
            }
        )
        mock_redis.get.return_value = session_data

        mock_resource = MagicMock()
        mock_resource.name = "web-01"

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
                headers={"Authorization": "Bearer test"},
            )

        assert resp.status_code == 403
        assert "revoked" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_successful_ticket(self, terminal_client, mock_redis, mock_db):
        session_data = json.dumps(
            {
                "user_email": "user@example.com",
                "resource_name": "web-01",
            }
        )
        mock_redis.get.return_value = session_data

        mock_resource = MagicMock()
        mock_resource.name = "web-01"

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
                headers={"Authorization": "Bearer test"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert "ticket" in data
        assert len(data["ticket"]) > 20  # URL-safe token

        # Verify ticket was stored in Redis with correct TTL
        mock_redis.setex.assert_called_once()
        call_args = mock_redis.setex.call_args
        assert call_args[0][0].startswith("terminal:ticket:")
        assert call_args[0][1] == TICKET_TTL

    @pytest.mark.asyncio
    async def test_resource_not_found_still_issues_ticket(
        self, terminal_client, mock_redis, mock_db
    ):
        """When resource is gone from catalog, ticket is still issued (session exists)."""
        session_data = json.dumps(
            {
                "user_email": "user@example.com",
                "resource_name": "web-01",
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
                headers={"Authorization": "Bearer test"},
            )

        # Resource gone from catalog but session exists — ticket issued
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_empty_session_id_rejected(self, terminal_client):
        resp = await terminal_client.post(
            "/api/v1/terminal/ticket",
            json={"session_id": ""},
            headers={"Authorization": "Bearer test"},
        )

        assert resp.status_code == 422  # Pydantic validation
