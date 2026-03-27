"""Tests for connect endpoint.

Tests /api/v1/connect for new connections, reconnects,
RBAC validation, bridge selection, and protocol overrides.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.api.dependencies import get_current_user
from bamf.api.routers.connect import (
    NON_MIGRATABLE_PROTOCOLS,
    _extract_ordinal,
    _validate_protocol_override,
    router,
)
from bamf.auth.sessions import Session
from bamf.db.session import get_db
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
    r.setex = AsyncMock()
    r.sadd = AsyncMock()
    r.zincrby = AsyncMock()
    r.hincrby = AsyncMock()
    r.hgetall = AsyncMock(return_value={})
    r.zrangebyscore = AsyncMock(return_value=[])
    r.publish = AsyncMock()
    r.expire = AsyncMock()
    r.scan = AsyncMock(return_value=("0", []))
    r.delete = AsyncMock()
    return r


@pytest.fixture
def mock_redis():
    return _make_mock_redis()


@pytest.fixture
def mock_db():
    return AsyncMock(spec=AsyncSession)


@pytest.fixture
def connect_app(mock_redis, mock_db):
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")

    async def override_redis():
        yield mock_redis

    async def override_db():
        yield mock_db

    async def override_user() -> Session:
        return USER_SESSION

    app.dependency_overrides[get_redis] = override_redis
    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_current_user] = override_user
    return app


@pytest.fixture
async def connect_client(connect_app):
    async with AsyncClient(
        transport=ASGITransport(app=connect_app),
        base_url="http://test",
    ) as client:
        yield client


def _mock_resource(name="web-01", resource_type="ssh", agent_id="agent-1", outpost=None):
    """Create a mock ResourceInfo."""
    r = MagicMock()
    r.name = name
    r.resource_type = resource_type
    r.agent_id = agent_id
    r.labels = {"env": "dev"}
    r.outpost = outpost
    return r


def _mock_ca():
    """Create a mock CA that issues fake certs."""
    ca = MagicMock()
    ca.ca_cert_pem = "-----BEGIN CERTIFICATE-----\nFAKECA\n-----END CERTIFICATE-----\n"

    mock_cert = MagicMock()
    mock_cert.not_valid_after_utc = datetime.now(UTC)

    mock_key = MagicMock()
    ca.issue_session_certificate.return_value = (mock_cert, mock_key)
    return ca


# ── Tests: Pure Functions ─────────────────────────────────────────────────


class TestExtractOrdinal:
    def test_standard_bridge(self):
        assert _extract_ordinal("bamf-bridge-0") == 0

    def test_higher_ordinal(self):
        assert _extract_ordinal("bamf-bridge-12") == 12

    def test_no_ordinal(self):
        assert _extract_ordinal("custom-bridge") == 0

    def test_nested_name(self):
        assert _extract_ordinal("my-app-bridge-5") == 5


class TestValidateProtocolOverride:
    def test_valid_web_ssh(self):
        _validate_protocol_override("web-ssh", "ssh")

    def test_valid_web_ssh_audit(self):
        _validate_protocol_override("web-ssh", "ssh-audit")

    def test_valid_web_db_postgres(self):
        _validate_protocol_override("web-db", "postgres")

    def test_valid_web_db_mysql_audit(self):
        _validate_protocol_override("web-db", "mysql-audit")

    def test_invalid_protocol(self):
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            _validate_protocol_override("invalid", "ssh")
        assert exc_info.value.status_code == 400

    def test_incompatible_type(self):
        from fastapi import HTTPException

        with pytest.raises(HTTPException) as exc_info:
            _validate_protocol_override("web-ssh", "postgres")
        assert exc_info.value.status_code == 400


class TestNonMigratableProtocols:
    def test_ssh_audit_non_migratable(self):
        assert "ssh-audit" in NON_MIGRATABLE_PROTOCOLS

    def test_web_ssh_non_migratable(self):
        assert "web-ssh" in NON_MIGRATABLE_PROTOCOLS

    def test_ssh_is_migratable(self):
        assert "ssh" not in NON_MIGRATABLE_PROTOCOLS


# ── Tests: New Connection ─────────────────────────────────────────────────


class TestNewConnection:
    @pytest.mark.asyncio
    async def test_resource_not_found(self, connect_client, mock_redis):
        with patch(
            "bamf.api.routers.connect.get_resource", new_callable=AsyncMock, return_value=None
        ):
            resp = await connect_client.post(
                "/api/v1/connect",
                json={"resource_name": "nonexistent"},
                headers={"Authorization": "Bearer test"},
            )

        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_access_denied(self, connect_client, mock_redis, mock_db):
        resource = _mock_resource()
        mock_check = AsyncMock(return_value=False)
        with (
            patch("bamf.api.routers.connect.get_resource", new=AsyncMock(return_value=resource)),
            patch("bamf.api.routers.connect.check_access", new=mock_check),
            patch("bamf.api.routers.connect.log_audit_event", new=AsyncMock()),
        ):
            resp = await connect_client.post(
                "/api/v1/connect",
                json={"resource_name": "web-01"},
                headers={"Authorization": "Bearer test"},
            )

        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_agent_offline(self, connect_client, mock_redis, mock_db):
        resource = _mock_resource()
        mock_redis.get.return_value = None  # agent status not in Redis

        with (
            patch("bamf.api.routers.connect.get_resource", new=AsyncMock(return_value=resource)),
            patch("bamf.api.routers.connect.check_access", new=AsyncMock(return_value=True)),
        ):
            resp = await connect_client.post(
                "/api/v1/connect",
                json={"resource_name": "web-01"},
                headers={"Authorization": "Bearer test"},
            )

        assert resp.status_code == 503
        assert "offline" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_no_agent_assigned(self, connect_client, mock_redis):
        resource = _mock_resource(agent_id=None)

        with (
            patch("bamf.api.routers.connect.get_resource", new=AsyncMock(return_value=resource)),
            patch("bamf.api.routers.connect.check_access", new=AsyncMock(return_value=True)),
        ):
            resp = await connect_client.post(
                "/api/v1/connect",
                json={"resource_name": "web-01"},
                headers={"Authorization": "Bearer test"},
            )

        assert resp.status_code == 503

    @pytest.mark.asyncio
    async def test_no_bridges_available(self, connect_client, mock_redis, mock_db):
        resource = _mock_resource()
        mock_redis.get.return_value = "online"
        mock_redis.zrangebyscore.return_value = []

        with (
            patch("bamf.api.routers.connect.get_resource", new=AsyncMock(return_value=resource)),
            patch("bamf.api.routers.connect.check_access", new=AsyncMock(return_value=True)),
            patch(
                "bamf.api.routers.connect._geoip_select_outpost", new=AsyncMock(return_value=None)
            ),
            patch("bamf.api.routers.connect.settings") as mock_settings,
        ):
            mock_settings.target_tunnels_per_pod = 10
            mock_settings.default_outpost_name = None

            resp = await connect_client.post(
                "/api/v1/connect",
                json={"resource_name": "web-01"},
                headers={"Authorization": "Bearer test"},
            )

        assert resp.status_code == 503

    @pytest.mark.asyncio
    async def test_successful_connection(self, connect_client, mock_redis, mock_db):
        resource = _mock_resource()

        def get_side_effect(key):
            if "status" in key:
                return "online"
            if "cluster_internal" in key:
                return None
            return None

        mock_redis.get.side_effect = get_side_effect
        mock_redis.zrangebyscore.return_value = [("bridge-0", 0)]
        mock_redis.hgetall.return_value = {"hostname": "0.bridge.tunnel.example.com", "outpost": ""}

        ca = _mock_ca()

        with (
            patch("bamf.api.routers.connect.get_resource", new=AsyncMock(return_value=resource)),
            patch("bamf.api.routers.connect.check_access", new=AsyncMock(return_value=True)),
            patch(
                "bamf.api.routers.connect._geoip_select_outpost", new=AsyncMock(return_value=None)
            ),
            patch("bamf.api.routers.connect.get_ca", return_value=ca),
            patch("bamf.api.routers.connect.serialize_certificate", return_value=b"CERT-PEM"),
            patch("bamf.api.routers.connect.serialize_private_key", return_value=b"KEY-PEM"),
            patch("bamf.api.routers.connect.log_audit_event", new=AsyncMock()),
            patch("bamf.api.routers.connect.settings") as mock_settings,
            patch(
                "bamf.services.agent_instances.select_agent_instance",
                new=AsyncMock(return_value="inst-1"),
            ),
            patch("bamf.services.agent_instances.increment_instance_tunnels", new=AsyncMock()),
        ):
            mock_settings.target_tunnels_per_pod = 10
            mock_settings.bridge_tunnel_port = 443
            mock_settings.bridge_internal_tunnel_port = 8443
            mock_settings.namespace = "bamf"
            mock_settings.default_outpost_name = None

            resp = await connect_client.post(
                "/api/v1/connect",
                json={"resource_name": "web-01"},
                headers={"Authorization": "Bearer test"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["bridge_hostname"] == "0.bridge.tunnel.example.com"
        assert data["resource_type"] == "ssh"
        assert "session_id" in data

    @pytest.mark.asyncio
    async def test_protocol_override(self, connect_client, mock_redis, mock_db):
        """Web terminal can override resource type to web-ssh."""
        resource = _mock_resource(resource_type="ssh")

        def get_side_effect(key):
            if "status" in key:
                return "online"
            return None

        mock_redis.get.side_effect = get_side_effect
        mock_redis.zrangebyscore.return_value = [("bridge-0", 0)]
        mock_redis.hgetall.return_value = {"hostname": "bridge.example.com"}

        ca = _mock_ca()

        with (
            patch("bamf.api.routers.connect.get_resource", new=AsyncMock(return_value=resource)),
            patch("bamf.api.routers.connect.check_access", new=AsyncMock(return_value=True)),
            patch(
                "bamf.api.routers.connect._geoip_select_outpost", new=AsyncMock(return_value=None)
            ),
            patch("bamf.api.routers.connect.get_ca", return_value=ca),
            patch("bamf.api.routers.connect.serialize_certificate", return_value=b"CERT"),
            patch("bamf.api.routers.connect.serialize_private_key", return_value=b"KEY"),
            patch("bamf.api.routers.connect.log_audit_event", new=AsyncMock()),
            patch("bamf.api.routers.connect.settings") as mock_settings,
            patch(
                "bamf.services.agent_instances.select_agent_instance",
                new=AsyncMock(return_value="inst-1"),
            ),
            patch("bamf.services.agent_instances.increment_instance_tunnels", new=AsyncMock()),
        ):
            mock_settings.target_tunnels_per_pod = 10
            mock_settings.bridge_tunnel_port = 443
            mock_settings.bridge_internal_tunnel_port = 8443
            mock_settings.namespace = "bamf"
            mock_settings.default_outpost_name = None

            resp = await connect_client.post(
                "/api/v1/connect",
                json={"resource_name": "web-01", "protocol": "web-ssh"},
                headers={"Authorization": "Bearer test"},
            )

        assert resp.status_code == 200
        assert resp.json()["resource_type"] == "web-ssh"


# ── Tests: Reconnect ─────────────────────────────────────────────────────


class TestReconnect:
    @pytest.mark.asyncio
    async def test_session_not_found(self, connect_client, mock_redis):
        mock_redis.get.return_value = None

        resp = await connect_client.post(
            "/api/v1/connect",
            json={"resource_name": "web-01", "reconnect_session_id": "dead-session"},
            headers={"Authorization": "Bearer test"},
        )

        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_wrong_user(self, connect_client, mock_redis):
        session_data = json.dumps(
            {
                "user_email": "other@example.com",
                "resource_name": "web-01",
                "agent_id": "agent-1",
            }
        )
        mock_redis.get.return_value = session_data

        resp = await connect_client.post(
            "/api/v1/connect",
            json={"resource_name": "web-01", "reconnect_session_id": "sess-123"},
            headers={"Authorization": "Bearer test"},
        )

        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_agent_offline_on_reconnect(self, connect_client, mock_redis):
        session_data = json.dumps(
            {
                "user_email": "user@example.com",
                "resource_name": "web-01",
                "agent_id": "agent-1",
                "bridge_id": "bridge-0",
            }
        )

        call_count = 0

        async def get_side_effect(key):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return session_data  # session lookup
            return None  # agent status

        mock_redis.get.side_effect = get_side_effect

        resp = await connect_client.post(
            "/api/v1/connect",
            json={"resource_name": "web-01", "reconnect_session_id": "sess-123"},
            headers={"Authorization": "Bearer test"},
        )

        assert resp.status_code == 503
