"""Tests for active tunnels dashboard endpoints.

Tests /api/v1/tunnels endpoints for listing active tunnels
and terminating tunnel sessions.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from bamf.api.dependencies import get_current_user, require_admin_or_audit
from bamf.api.routers.tunnels import router
from bamf.auth.sessions import Session
from bamf.redis.client import get_redis

# ── Fixtures ──────────────────────────────────────────────────────────────

_NOW = datetime.now(UTC).isoformat()

ADMIN_SESSION = Session(
    email="admin@example.com",
    display_name="Admin",
    roles=["admin"],
    provider_name="local",
    created_at=_NOW,
    expires_at=_NOW,
    last_active_at=_NOW,
)

USER_SESSION = Session(
    email="user@example.com",
    display_name="User",
    roles=[],
    provider_name="local",
    created_at=_NOW,
    expires_at=_NOW,
    last_active_at=_NOW,
)


def _make_mock_redis():
    """Create a mock Redis client."""
    r = AsyncMock()
    r.smembers = AsyncMock(return_value=set())
    r.mget = AsyncMock(return_value=[])
    r.srem = AsyncMock()
    r.get = AsyncMock(return_value=None)
    r.delete = AsyncMock()
    r.zincrby = AsyncMock()
    r.hincrby = AsyncMock()
    r.sadd = AsyncMock()
    return r


@pytest.fixture
def mock_redis():
    return _make_mock_redis()


@pytest.fixture
def tunnels_app(mock_redis):
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")

    async def override_redis():
        yield mock_redis

    async def override_admin() -> Session:
        return ADMIN_SESSION

    async def override_user() -> Session:
        return USER_SESSION

    app.dependency_overrides[get_redis] = override_redis
    app.dependency_overrides[require_admin_or_audit] = override_admin
    app.dependency_overrides[get_current_user] = override_user
    return app


@pytest.fixture
async def tunnels_client(tunnels_app):
    async with AsyncClient(
        transport=ASGITransport(app=tunnels_app),
        base_url="http://test",
    ) as client:
        yield client


# ── Tests: List Active Tunnels ─────────────────────────────────────────


class TestListActiveTunnels:
    @pytest.mark.asyncio
    async def test_empty_active_set(self, tunnels_client, mock_redis):
        mock_redis.smembers.return_value = set()

        resp = await tunnels_client.get(
            "/api/v1/tunnels/active",
            headers={"Authorization": "Bearer test"},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 0
        assert data["tunnels"] == []
        assert data["by_user"] == {}

    @pytest.mark.asyncio
    async def test_returns_active_tunnels(self, tunnels_client, mock_redis):
        session_data = json.dumps(
            {
                "user_email": "alice@example.com",
                "resource_name": "web-01",
                "protocol": "ssh",
                "bridge_id": "bridge-0",
                "status": "established",
                "created_at": _NOW,
                "established_at": str(datetime.now(UTC).timestamp()),
            }
        )
        mock_redis.smembers.return_value = {"sess-1"}
        mock_redis.mget.return_value = [session_data]

        resp = await tunnels_client.get(
            "/api/v1/tunnels/active",
            headers={"Authorization": "Bearer test"},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        assert data["tunnels"][0]["session_id"] == "sess-1"
        assert data["tunnels"][0]["user_email"] == "alice@example.com"
        assert data["by_user"] == {"alice@example.com": 1}
        assert data["by_resource"] == {"web-01": 1}
        assert data["by_bridge"] == {"bridge-0": 1}
        assert data["by_protocol"] == {"ssh": 1}

    @pytest.mark.asyncio
    async def test_stale_entries_cleaned(self, tunnels_client, mock_redis):
        """Sessions with expired Redis keys are removed from active set."""
        mock_redis.smembers.return_value = {"sess-live", "sess-stale"}
        live_data = json.dumps(
            {
                "user_email": "bob@example.com",
                "resource_name": "db-01",
                "protocol": "postgres",
                "bridge_id": "bridge-1",
                "status": "established",
                "created_at": _NOW,
            }
        )

        # mget must return values matching the key order, which depends on
        # set iteration order.  Use a side_effect that maps keys to values
        # so the pairing is always correct regardless of set ordering.
        session_data_map = {
            "session:sess-live": live_data,
            "session:sess-stale": None,
        }

        async def mget_side_effect(*keys):
            return [session_data_map.get(k) for k in keys]

        mock_redis.mget = AsyncMock(side_effect=mget_side_effect)

        resp = await tunnels_client.get(
            "/api/v1/tunnels/active",
            headers={"Authorization": "Bearer test"},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["total"] == 1
        mock_redis.srem.assert_called_once_with("sessions:active", "sess-stale")

    @pytest.mark.asyncio
    async def test_multiple_tunnels_counters(self, tunnels_client, mock_redis):
        sessions = {
            "s1": {
                "user_email": "alice@example.com",
                "resource_name": "web-01",
                "protocol": "ssh",
                "bridge_id": "bridge-0",
                "status": "established",
                "created_at": _NOW,
            },
            "s2": {
                "user_email": "alice@example.com",
                "resource_name": "db-01",
                "protocol": "postgres",
                "bridge_id": "bridge-0",
                "status": "established",
                "created_at": _NOW,
            },
            "s3": {
                "user_email": "bob@example.com",
                "resource_name": "web-01",
                "protocol": "ssh",
                "bridge_id": "bridge-1",
                "status": "pending",
                "created_at": _NOW,
            },
        }
        mock_redis.smembers.return_value = set(sessions.keys())
        mock_redis.mget.return_value = [json.dumps(v) for v in sessions.values()]

        resp = await tunnels_client.get(
            "/api/v1/tunnels/active",
            headers={"Authorization": "Bearer test"},
        )

        data = resp.json()
        assert data["total"] == 3
        assert data["by_user"]["alice@example.com"] == 2
        assert data["by_user"]["bob@example.com"] == 1
        assert data["by_resource"]["web-01"] == 2
        assert data["by_protocol"]["ssh"] == 2


# ── Tests: Terminate Tunnel ─────────────────────────────────────────────


class TestTerminateTunnel:
    @pytest.mark.asyncio
    async def test_not_found(self, tunnels_client, mock_redis):
        mock_redis.get.return_value = None

        resp = await tunnels_client.delete(
            "/api/v1/tunnels/nonexistent",
            headers={"Authorization": "Bearer test"},
        )

        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_own_tunnel(self, tunnels_client, mock_redis):
        session_data = json.dumps(
            {
                "user_email": "user@example.com",
                "resource_name": "web-01",
                "protocol": "ssh",
                "bridge_id": "bridge-0",
                "agent_id": "agent-1",
                "instance_id": "inst-1",
            }
        )
        mock_redis.get.return_value = session_data

        with patch("bamf.api.routers.tunnels.log_audit_event", new_callable=AsyncMock):
            resp = await tunnels_client.delete(
                "/api/v1/tunnels/sess-123",
                headers={"Authorization": "Bearer test"},
            )

        assert resp.status_code == 200
        mock_redis.delete.assert_any_call("session:sess-123")
        mock_redis.srem.assert_called_with("sessions:active", "sess-123")

    @pytest.mark.asyncio
    async def test_other_users_tunnel_denied(self, tunnels_client, mock_redis):
        """Non-admin users cannot terminate other users' tunnels."""
        session_data = json.dumps(
            {
                "user_email": "other@example.com",
                "resource_name": "web-01",
                "protocol": "ssh",
                "bridge_id": "bridge-0",
            }
        )
        mock_redis.get.return_value = session_data

        resp = await tunnels_client.delete(
            "/api/v1/tunnels/sess-456",
            headers={"Authorization": "Bearer test"},
        )

        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_admin_terminates_any_tunnel(self, tunnels_app, mock_redis):
        """Admins can terminate any user's tunnel."""

        # Override to make current user an admin
        async def override_admin_user() -> Session:
            return ADMIN_SESSION

        tunnels_app.dependency_overrides[get_current_user] = override_admin_user

        session_data = json.dumps(
            {
                "user_email": "other@example.com",
                "resource_name": "web-01",
                "protocol": "ssh",
                "bridge_id": "bridge-0",
                "agent_id": "agent-1",
                "instance_id": "inst-1",
            }
        )
        mock_redis.get.return_value = session_data

        async with AsyncClient(
            transport=ASGITransport(app=tunnels_app),
            base_url="http://test",
        ) as client:
            with patch("bamf.api.routers.tunnels.log_audit_event", new_callable=AsyncMock):
                resp = await client.delete(
                    "/api/v1/tunnels/sess-789",
                    headers={"Authorization": "Bearer admin-token"},
                )

        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_bridge_counter_decremented(self, tunnels_client, mock_redis):
        session_data = json.dumps(
            {
                "user_email": "user@example.com",
                "resource_name": "web-01",
                "protocol": "ssh",
                "bridge_id": "bridge-0",
                "agent_id": "agent-1",
                "instance_id": "inst-1",
            }
        )
        mock_redis.get.return_value = session_data

        with patch("bamf.api.routers.tunnels.log_audit_event", new_callable=AsyncMock):
            await tunnels_client.delete(
                "/api/v1/tunnels/sess-abc",
                headers={"Authorization": "Bearer test"},
            )

        mock_redis.zincrby.assert_called_with("bridges:available", -1, "bridge-0")
        mock_redis.hincrby.assert_called_with("bridge:bridge-0", "active_tunnels", -1)
