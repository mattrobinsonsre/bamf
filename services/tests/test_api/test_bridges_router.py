"""Tests for internal bridge management endpoints.

Tests /api/v1/internal endpoints for bridge bootstrap, registration,
heartbeat, session validation, tunnel lifecycle, drain, and recording upload.
"""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.api.dependencies import BridgeIdentity, get_bridge_identity
from bamf.api.routers.internal_bridges import router
from bamf.db.session import get_db
from bamf.redis.client import get_redis

# ── Fixtures ──────────────────────────────────────────────────────────────

_NOW = datetime.now(UTC)


def _make_mock_redis():
    r = AsyncMock()
    r.get = AsyncMock(return_value=None)
    r.setex = AsyncMock()
    r.set = AsyncMock()
    r.delete = AsyncMock()
    r.srem = AsyncMock()
    r.exists = AsyncMock(return_value=True)
    r.hset = AsyncMock()
    r.hget = AsyncMock(return_value=None)
    r.hgetall = AsyncMock(return_value={})
    r.hincrby = AsyncMock()
    r.expire = AsyncMock()
    r.zadd = AsyncMock()
    r.zrem = AsyncMock()
    r.zincrby = AsyncMock()
    return r


def _make_bridge_identity(bridge_id="bamf-bridge-0"):
    return BridgeIdentity(
        bridge_id=bridge_id,
        certificate=MagicMock(),
        expires_at=_NOW + timedelta(hours=24),
    )


@pytest.fixture
def mock_redis():
    return _make_mock_redis()


@pytest.fixture
def mock_db():
    return AsyncMock(spec=AsyncSession)


@pytest.fixture
def bridges_app(mock_redis, mock_db):
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")

    async def override_redis():
        yield mock_redis

    async def override_db():
        yield mock_db

    async def override_bridge() -> BridgeIdentity:
        return _make_bridge_identity()

    app.dependency_overrides[get_redis] = override_redis
    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_bridge_identity] = override_bridge
    return app


@pytest.fixture
async def bridges_client(bridges_app):
    async with AsyncClient(
        transport=ASGITransport(app=bridges_app),
        base_url="http://test",
    ) as client:
        yield client


# ── Tests: Bootstrap ──────────────────────────────────────────────────


class TestBootstrapBridge:
    @pytest.mark.asyncio
    async def test_invalid_token(self, bridges_client):
        with patch("bamf.api.routers.internal_bridges.settings") as mock_settings:
            mock_settings.bridge_bootstrap_token = "correct-token"
            mock_settings.default_outpost_name = None
            # Outpost lookup returns nothing
            with patch(
                "bamf.api.routers.internal_bridges.async_session_factory_read"
            ) as mock_factory:
                mock_session = AsyncMock()
                mock_result = MagicMock()
                mock_result.scalar_one_or_none.return_value = None
                mock_session.execute = AsyncMock(return_value=mock_result)
                mock_session.__aenter__ = AsyncMock(return_value=mock_session)
                mock_session.__aexit__ = AsyncMock()
                mock_factory.return_value = mock_session

                resp = await bridges_client.post(
                    "/api/v1/internal/bridges/bootstrap",
                    json={
                        "bridge_id": "bamf-bridge-0",
                        "hostname": "0.bridge.tunnel.example.com",
                        "bootstrap_token": "wrong-token",
                    },
                )

        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_successful_bootstrap(self, bridges_client):
        mock_cert = MagicMock()
        mock_cert.not_valid_after_utc = _NOW + timedelta(hours=24)
        mock_key = MagicMock()
        ca = MagicMock()
        ca.issue_service_certificate.return_value = (mock_cert, mock_key)
        ca.ca_cert_pem = "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n"

        with (
            patch("bamf.api.routers.internal_bridges.settings") as mock_settings,
            patch("bamf.api.routers.internal_bridges.get_ca", return_value=ca),
            patch("bamf.api.routers.internal_bridges.serialize_certificate", return_value=b"CERT"),
            patch("bamf.api.routers.internal_bridges.serialize_private_key", return_value=b"KEY"),
            patch("bamf.api.routers.internal_bridges.get_ssh_host_key_pem", return_value="SSH-KEY"),
        ):
            mock_settings.bridge_bootstrap_token = "correct-token"
            mock_settings.default_outpost_name = "us-east"
            mock_settings.namespace = "bamf"
            mock_settings.bridge_headless_service = None

            resp = await bridges_client.post(
                "/api/v1/internal/bridges/bootstrap",
                json={
                    "bridge_id": "bamf-bridge-0",
                    "hostname": "0.bridge.tunnel.example.com",
                    "bootstrap_token": "correct-token",
                },
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["certificate"] == "CERT"
        assert data["private_key"] == "KEY"
        assert data["ssh_host_key"] == "SSH-KEY"
        assert data["outpost_name"] == "us-east"


# ── Tests: Register ──────────────────────────────────────────────────


class TestRegisterBridge:
    @pytest.mark.asyncio
    async def test_register_success(self, bridges_client, mock_redis):
        resp = await bridges_client.post(
            "/api/v1/internal/bridges/register",
            json={
                "bridge_id": "bamf-bridge-0",
                "hostname": "0.bridge.tunnel.example.com",
            },
        )

        assert resp.status_code == 200
        mock_redis.hset.assert_called_once()
        mock_redis.zadd.assert_called_once_with("bridges:available", {"bamf-bridge-0": 0})

    @pytest.mark.asyncio
    async def test_register_with_outpost(self, bridges_client, mock_redis):
        resp = await bridges_client.post(
            "/api/v1/internal/bridges/register",
            json={
                "bridge_id": "bamf-bridge-0",
                "hostname": "0.bridge.eu.tunnel.example.com",
                "outpost_name": "eu",
            },
        )

        assert resp.status_code == 200
        # Should add to both global and per-outpost sorted sets
        assert mock_redis.zadd.call_count == 2


# ── Tests: Heartbeat ──────────────────────────────────────────────────


class TestBridgeHeartbeat:
    @pytest.mark.asyncio
    async def test_heartbeat_existing(self, bridges_client, mock_redis):
        mock_redis.exists.return_value = True
        mock_redis.hget.return_value = "ready"

        resp = await bridges_client.post(
            "/api/v1/internal/bridges/bamf-bridge-0/heartbeat",
            json={"active_tunnels": 5},
        )

        assert resp.status_code == 200
        mock_redis.hset.assert_any_call("bridge:bamf-bridge-0", "active_tunnels", "5")
        mock_redis.expire.assert_called_once()

    @pytest.mark.asyncio
    async def test_heartbeat_reregisters_expired(self, bridges_client, mock_redis):
        """If bridge hash expired, heartbeat re-registers it."""
        mock_redis.exists.return_value = False
        mock_redis.hget.return_value = "ready"

        resp = await bridges_client.post(
            "/api/v1/internal/bridges/bamf-bridge-0/heartbeat",
            json={"active_tunnels": 0, "hostname": "0.bridge.tunnel.example.com"},
        )

        assert resp.status_code == 200
        # Should call hset with full mapping for re-registration
        calls = mock_redis.hset.call_args_list
        assert any("hostname" in str(c) for c in calls)


# ── Tests: Status Update ──────────────────────────────────────────────


class TestBridgeStatus:
    @pytest.mark.asyncio
    async def test_not_found(self, bridges_client, mock_redis):
        mock_redis.exists.return_value = False

        resp = await bridges_client.post(
            "/api/v1/internal/bridges/nonexistent/status",
            json={"status": "draining"},
        )

        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_set_draining(self, bridges_client, mock_redis):
        mock_redis.exists.return_value = True
        mock_redis.hget.return_value = ""  # outpost

        resp = await bridges_client.post(
            "/api/v1/internal/bridges/bamf-bridge-0/status",
            json={"status": "draining"},
        )

        assert resp.status_code == 200
        mock_redis.hset.assert_called_with("bridge:bamf-bridge-0", "status", "draining")
        mock_redis.zrem.assert_called_once_with("bridges:available", "bamf-bridge-0")

    @pytest.mark.asyncio
    async def test_set_ready(self, bridges_client, mock_redis):
        mock_redis.exists.return_value = True
        mock_redis.hget.side_effect = ["", "5"]  # outpost, then active_tunnels

        resp = await bridges_client.post(
            "/api/v1/internal/bridges/bamf-bridge-0/status",
            json={"status": "ready"},
        )

        assert resp.status_code == 200
        mock_redis.zadd.assert_called()


# ── Tests: Session Validation ──────────────────────────────────────────


class TestValidateSession:
    @pytest.mark.asyncio
    async def test_session_not_found(self, bridges_client, mock_redis):
        mock_redis.get.return_value = None

        resp = await bridges_client.post(
            "/api/v1/internal/sessions/validate",
            json={"session_token": "nonexistent"},
        )

        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_valid_session(self, bridges_client, mock_redis):
        session_data = json.dumps(
            {
                "user_email": "alice@example.com",
                "resource_name": "web-01",
                "agent_id": "agent-1",
                "protocol": "ssh",
                "created_at": _NOW.isoformat(),
                "expires_at": (_NOW + timedelta(minutes=5)).isoformat(),
            }
        )
        mock_redis.get.return_value = session_data

        resp = await bridges_client.post(
            "/api/v1/internal/sessions/validate",
            json={"session_token": "sess-123"},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["user_email"] == "alice@example.com"
        assert data["resource_name"] == "web-01"
        assert data["protocol"] == "ssh"


# ── Tests: Tunnel Establish ──────────────────────────────────────────


class TestTunnelEstablish:
    @pytest.mark.asyncio
    async def test_session_not_found(self, bridges_client, mock_redis):
        mock_redis.get.return_value = None

        resp = await bridges_client.post(
            "/api/v1/internal/tunnels/establish",
            json={"session_token": "gone", "agent_id": "agent-1"},
        )

        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_agent_not_connected(self, bridges_client, mock_redis):
        session_data = json.dumps(
            {
                "resource_name": "web-01",
                "protocol": "ssh",
            }
        )
        mock_redis.get.return_value = session_data
        mock_redis.hgetall.return_value = {}

        resp = await bridges_client.post(
            "/api/v1/internal/tunnels/establish",
            json={"session_token": "sess-123", "agent_id": "agent-1"},
        )

        assert resp.status_code == 503

    @pytest.mark.asyncio
    async def test_successful_establish(self, bridges_client, mock_redis):
        session_data = json.dumps(
            {
                "resource_name": "web-01",
                "protocol": "ssh",
            }
        )
        mock_redis.get.return_value = session_data
        mock_redis.hgetall.return_value = {
            "name": "test-agent",
            "target_host": "web-01.internal",
            "target_port": "22",
        }

        resp = await bridges_client.post(
            "/api/v1/internal/tunnels/establish",
            json={"session_token": "sess-123", "agent_id": "agent-1"},
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["resource_name"] == "web-01"
        assert data["agent_name"] == "test-agent"
        assert data["target_host"] == "web-01.internal"


# ── Tests: Tunnel Established ──────────────────────────────────────────


class TestTunnelEstablished:
    @pytest.mark.asyncio
    async def test_updates_session(self, bridges_client, mock_redis, mock_db):
        session_data = json.dumps(
            {
                "user_email": "alice@example.com",
                "resource_name": "web-01",
                "protocol": "ssh",
                "status": "pending",
            }
        )
        mock_redis.get.return_value = session_data
        mock_db.commit = AsyncMock()

        with patch("bamf.api.routers.internal_bridges.log_audit_event", new_callable=AsyncMock):
            resp = await bridges_client.post(
                "/api/v1/internal/tunnels/established",
                json={"session_token": "sess-123", "tunnel_id": "tun-1"},
            )

        assert resp.status_code == 200
        # Should update session with extended TTL
        mock_redis.setex.assert_called_once()
        args = mock_redis.setex.call_args
        assert args[0][1] == 86400  # 24h TTL


# ── Tests: Tunnel Closed ──────────────────────────────────────────────


class TestTunnelClosed:
    @pytest.mark.asyncio
    async def test_cleans_up_session(self, bridges_client, mock_redis, mock_db):
        session_data = json.dumps(
            {
                "user_email": "alice@example.com",
                "resource_name": "web-01",
                "protocol": "ssh",
                "agent_id": "agent-1",
                "instance_id": "inst-1",
                "bridge_id": "bamf-bridge-0",
                "established_at": str(time.time() - 300),
            }
        )
        mock_redis.get.return_value = session_data
        mock_redis.hget.return_value = ""  # outpost
        mock_db.commit = AsyncMock()

        with (
            patch("bamf.api.routers.internal_bridges.log_audit_event", new_callable=AsyncMock),
            patch(
                "bamf.services.agent_instances.decrement_instance_tunnels",
                new_callable=AsyncMock,
            ),
        ):
            resp = await bridges_client.post(
                "/api/v1/internal/tunnels/closed",
                json={
                    "session_token": "sess-123",
                    "tunnel_id": "tun-1",
                    "bytes_sent": 1024,
                    "bytes_received": 2048,
                },
            )

        assert resp.status_code == 200
        mock_redis.delete.assert_any_call("session:sess-123")
        mock_redis.srem.assert_called_with("sessions:active", "sess-123")
        mock_redis.zincrby.assert_called_with("bridges:available", -1, "bamf-bridge-0")

    @pytest.mark.asyncio
    async def test_missing_session_still_succeeds(self, bridges_client, mock_redis, mock_db):
        """Tunnel close should succeed even if session already expired."""
        mock_redis.get.return_value = None
        mock_db.commit = AsyncMock()

        with patch("bamf.api.routers.internal_bridges.log_audit_event", new_callable=AsyncMock):
            resp = await bridges_client.post(
                "/api/v1/internal/tunnels/closed",
                json={"session_token": "gone", "tunnel_id": "tun-1"},
            )

        assert resp.status_code == 200


# ── Tests: Drain ──────────────────────────────────────────────────────


class TestDrainBridge:
    @pytest.mark.asyncio
    async def test_non_migratable_returned(self, bridges_client, mock_redis, mock_db):
        mock_db.commit = AsyncMock()

        resp = await bridges_client.post(
            "/api/v1/internal/bridges/bamf-bridge-0/drain",
            json={
                "tunnels": [
                    {"session_token": "sess-1", "protocol": "ssh-audit"},
                    {"session_token": "sess-2", "protocol": "ssh-audit"},
                ],
            },
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["migrated_count"] == 0
        assert len(data["non_migratable_sessions"]) == 2
        assert "sess-1" in data["non_migratable_sessions"]

    @pytest.mark.asyncio
    async def test_session_not_found_during_drain(self, bridges_client, mock_redis, mock_db):
        mock_redis.get.return_value = None
        mock_db.commit = AsyncMock()

        resp = await bridges_client.post(
            "/api/v1/internal/bridges/bamf-bridge-0/drain",
            json={
                "tunnels": [
                    {"session_token": "missing", "protocol": "ssh"},
                ],
            },
        )

        assert resp.status_code == 200
        data = resp.json()
        assert data["migrated_count"] == 0
        assert len(data["errors"]) == 1


# ── Tests: Recording Upload ──────────────────────────────────────────


class TestRecordingUpload:
    @pytest.mark.asyncio
    async def test_upload_recording(self, bridges_client, mock_redis, mock_db):
        session_data = json.dumps(
            {
                "user_email": "alice@example.com",
                "resource_name": "web-01",
            }
        )
        mock_redis.get.return_value = session_data
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()

        with patch("bamf.api.routers.internal_bridges.log_audit_event", new_callable=AsyncMock):
            resp = await bridges_client.post(
                "/api/v1/internal/sessions/00000000-0000-0000-0000-000000000001/recording",
                json={
                    "format": "asciicast-v2",
                    "data": '{"version":2}\n[0.0,"o","hello"]\n',
                },
            )

        assert resp.status_code == 200
        mock_db.add.assert_called_once()

    @pytest.mark.asyncio
    async def test_upload_with_expired_session(self, bridges_client, mock_redis, mock_db):
        """Recording upload should work even if session already cleaned up."""
        mock_redis.get.return_value = None
        mock_db.add = MagicMock()
        mock_db.commit = AsyncMock()

        with patch("bamf.api.routers.internal_bridges.log_audit_event", new_callable=AsyncMock):
            resp = await bridges_client.post(
                "/api/v1/internal/sessions/00000000-0000-0000-0000-000000000002/recording",
                json={
                    "format": "queries-v1",
                    "data": '{"query":"SELECT 1"}\n',
                },
            )

        assert resp.status_code == 200
