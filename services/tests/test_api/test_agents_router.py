"""Tests for agent management endpoints.

Tests /api/v1/agents endpoints for agent registration (join),
heartbeat, status, certificate renewal, listing, deletion,
drain, and instance management.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.api.dependencies import (
    AgentIdentity,
    get_agent_identity,
    require_admin,
    require_admin_or_audit,
)
from bamf.api.routers.agents import router
from bamf.auth.sessions import Session
from bamf.db.session import get_db, get_db_read
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

AGENT_UUID = uuid4()
AGENT_NAME = "test-agent-01"


def _make_mock_redis():
    r = AsyncMock()
    r.get = AsyncMock(return_value=None)
    r.setex = AsyncMock()
    r.set = AsyncMock()
    r.delete = AsyncMock()
    r.expire = AsyncMock()
    r.exists = AsyncMock(return_value=True)
    r.hset = AsyncMock()
    r.hget = AsyncMock(return_value=None)
    r.hdel = AsyncMock()
    r.hgetall = AsyncMock(return_value={})
    r.publish = AsyncMock()
    r.scan = AsyncMock(return_value=("0", []))
    return r


def _make_mock_agent(agent_id=None, name=AGENT_NAME):
    """Create a mock Agent ORM object."""
    agent = MagicMock()
    agent.id = agent_id or AGENT_UUID
    agent.name = name
    agent.certificate_fingerprint = "sha256:abc123"
    agent.certificate_expires_at = datetime.now(UTC) + timedelta(days=365)
    agent.created_at = datetime.now(UTC)
    agent.updated_at = datetime.now(UTC)
    return agent


def _make_mock_token(
    name="test-token",
    is_revoked=False,
    expired=False,
    max_uses=None,
    use_count=0,
):
    """Create a mock JoinToken ORM object."""
    token = MagicMock()
    token.name = name
    token.is_revoked = is_revoked
    token.expires_at = datetime.now(UTC) + (timedelta(hours=-1) if expired else timedelta(hours=24))
    token.max_uses = max_uses
    token.use_count = use_count
    token.agent_labels = {"env": "dev"}
    return token


@pytest.fixture
def mock_redis():
    return _make_mock_redis()


@pytest.fixture
def mock_db():
    return AsyncMock(spec=AsyncSession)


@pytest.fixture
def agents_app(mock_redis, mock_db):
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")

    async def override_redis():
        yield mock_redis

    async def override_db():
        yield mock_db

    async def override_admin() -> Session:
        return ADMIN_SESSION

    async def override_agent_identity() -> AgentIdentity:
        return AgentIdentity(
            name=AGENT_NAME,
            expires_at=datetime.now(UTC) + timedelta(days=365),
            certificate=MagicMock(),
        )

    app.dependency_overrides[get_redis] = override_redis
    app.dependency_overrides[get_db] = override_db
    app.dependency_overrides[get_db_read] = override_db
    app.dependency_overrides[require_admin] = override_admin
    app.dependency_overrides[require_admin_or_audit] = override_admin
    app.dependency_overrides[get_agent_identity] = override_agent_identity
    return app


@pytest.fixture
async def agents_client(agents_app):
    async with AsyncClient(
        transport=ASGITransport(app=agents_app),
        base_url="http://test",
    ) as client:
        yield client


def _mock_db_execute_returning(result_value):
    """Create an AsyncMock db.execute that returns a scalar result."""
    mock_result = MagicMock()
    mock_result.scalar_one_or_none.return_value = result_value
    mock_result.scalars.return_value.all.return_value = [result_value] if result_value else []
    return AsyncMock(return_value=mock_result)


# ── Tests: Join (Registration) ──────────────────────────────────────────


class TestJoinAgent:
    @pytest.mark.asyncio
    async def test_invalid_token(self, agents_client, mock_db):
        mock_db.execute = _mock_db_execute_returning(None)

        resp = await agents_client.post(
            "/api/v1/agents/join",
            json={"join_token": "invalid-token", "name": "new-agent"},
        )

        assert resp.status_code == 401
        assert "Invalid join token" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_revoked_token(self, agents_client, mock_db):
        token = _make_mock_token(is_revoked=True)
        mock_db.execute = _mock_db_execute_returning(token)

        resp = await agents_client.post(
            "/api/v1/agents/join",
            json={"join_token": "revoked-token", "name": "new-agent"},
        )

        assert resp.status_code == 401
        assert "revoked" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_expired_token(self, agents_client, mock_db):
        token = _make_mock_token(expired=True)
        mock_db.execute = _mock_db_execute_returning(token)

        resp = await agents_client.post(
            "/api/v1/agents/join",
            json={"join_token": "expired-token", "name": "new-agent"},
        )

        assert resp.status_code == 401
        assert "expired" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_max_uses_reached(self, agents_client, mock_db):
        token = _make_mock_token(max_uses=1, use_count=1)
        mock_db.execute = _mock_db_execute_returning(token)

        resp = await agents_client.post(
            "/api/v1/agents/join",
            json={"join_token": "maxed-token", "name": "new-agent"},
        )

        assert resp.status_code == 401
        assert "maximum uses" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_duplicate_name(self, agents_client, mock_db):
        token = _make_mock_token()
        existing_agent = _make_mock_agent()
        call_count = 0

        async def execute_side_effect(query):
            nonlocal call_count
            call_count += 1
            result = MagicMock()
            if call_count == 1:
                result.scalar_one_or_none.return_value = token
            else:
                result.scalar_one_or_none.return_value = existing_agent
            return result

        mock_db.execute = AsyncMock(side_effect=execute_side_effect)

        resp = await agents_client.post(
            "/api/v1/agents/join",
            json={"join_token": "valid-token", "name": AGENT_NAME},
        )

        assert resp.status_code == 409
        assert "already exists" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_successful_join(self, agents_client, mock_db, mock_redis):
        token = _make_mock_token()
        call_count = 0

        async def execute_side_effect(query):
            nonlocal call_count
            call_count += 1
            result = MagicMock()
            if call_count == 1:
                result.scalar_one_or_none.return_value = token
            else:
                result.scalar_one_or_none.return_value = None
            return result

        mock_db.execute = AsyncMock(side_effect=execute_side_effect)

        # Ensure the Agent object gets a real UUID id when added to the session.
        # In production, SQLAlchemy's default=generate_uuid7 sets this at init,
        # but with a mocked session it may not be populated before flush.
        _join_agent_id = uuid4()

        def add_side_effect(obj):
            if hasattr(obj, "id") and obj.id is None:
                obj.id = _join_agent_id

        mock_db.add = MagicMock(side_effect=add_side_effect)
        mock_db.flush = AsyncMock()

        mock_cert = MagicMock()
        mock_cert.not_valid_after_utc = datetime.now(UTC) + timedelta(days=365)
        mock_key = MagicMock()
        ca = MagicMock()
        ca.issue_service_certificate.return_value = (mock_cert, mock_key)
        ca.ca_cert_pem = "-----BEGIN CERTIFICATE-----\nFAKECA\n-----END CERTIFICATE-----\n"

        with (
            patch("bamf.api.routers.agents.get_ca", return_value=ca),
            patch("bamf.api.routers.agents.serialize_certificate", return_value=b"CERT-PEM"),
            patch("bamf.api.routers.agents.serialize_private_key", return_value=b"KEY-PEM"),
            patch("bamf.api.routers.agents.get_certificate_fingerprint", return_value="sha256:new"),
            patch("bamf.api.routers.agents.log_audit_event", new_callable=AsyncMock),
            patch("bamf.api.routers.agents.set_agent_labels", new_callable=AsyncMock),
        ):
            resp = await agents_client.post(
                "/api/v1/agents/join",
                json={"join_token": "valid-token", "name": "new-agent", "labels": {"team": "sre"}},
            )

        assert resp.status_code == 201
        data = resp.json()
        assert "agent_id" in data
        # Verify agent_id is a valid UUID string
        UUID(data["agent_id"])
        assert data["certificate"] == "CERT-PEM"
        assert data["private_key"] == "KEY-PEM"
        assert data["ca_certificate"].strip() == ca.ca_cert_pem.strip()
        assert token.use_count == 1


# ── Tests: Heartbeat ──────────────────────────────────────────────────


class TestAgentHeartbeat:
    @pytest.mark.asyncio
    async def test_agent_not_found(self, agents_client, mock_db):
        mock_db.execute = _mock_db_execute_returning(None)

        resp = await agents_client.post(
            f"/api/v1/agents/{uuid4()}/heartbeat",
            json={},
        )

        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_simple_heartbeat(self, agents_client, mock_db, mock_redis):
        agent = _make_mock_agent()
        mock_db.execute = _mock_db_execute_returning(agent)

        with (
            patch("bamf.api.routers.agents.set_agent_labels", new_callable=AsyncMock),
            patch("bamf.api.routers.agents.set_agent_resources", new_callable=AsyncMock),
            patch("bamf.api.routers.agents.set_tunnel_hostnames", new_callable=AsyncMock),
            patch("bamf.services.agent_instances.register_instance", new_callable=AsyncMock),
            patch(
                "bamf.services.agent_instances.update_instance_tunnel_count", new_callable=AsyncMock
            ),
            patch("bamf.services.agent_instances.cleanup_stale_instances", new_callable=AsyncMock),
        ):
            resp = await agents_client.post(
                f"/api/v1/agents/{AGENT_UUID}/heartbeat",
                json={"labels": {"env": "prod"}, "resources": [], "instance_id": "inst-1"},
            )

        assert resp.status_code == 200
        mock_redis.setex.assert_any_call(f"agent:{AGENT_UUID}:status", 180, "online")

    @pytest.mark.asyncio
    async def test_heartbeat_by_name(self, agents_client, mock_db, mock_redis):
        """Agent can heartbeat using its name instead of UUID."""
        agent = _make_mock_agent()
        call_count = 0

        async def execute_side_effect(query):
            nonlocal call_count
            call_count += 1
            result = MagicMock()
            if call_count == 1:
                # First call: UUID parse fails, so it tries name lookup
                result.scalar_one_or_none.return_value = agent
            else:
                result.scalar_one_or_none.return_value = agent
            return result

        mock_db.execute = AsyncMock(side_effect=execute_side_effect)

        with (
            patch("bamf.api.routers.agents.set_agent_labels", new_callable=AsyncMock),
            patch("bamf.api.routers.agents.set_agent_resources", new_callable=AsyncMock),
            patch("bamf.api.routers.agents.set_tunnel_hostnames", new_callable=AsyncMock),
        ):
            resp = await agents_client.post(
                f"/api/v1/agents/{AGENT_NAME}/heartbeat",
                json={},
            )

        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_heartbeat_with_resources(self, agents_client, mock_db, mock_redis):
        agent = _make_mock_agent()
        mock_db.execute = _mock_db_execute_returning(agent)

        with (
            patch("bamf.api.routers.agents.set_agent_labels", new_callable=AsyncMock),
            patch(
                "bamf.api.routers.agents.set_agent_resources", new_callable=AsyncMock
            ) as mock_set_res,
            patch("bamf.api.routers.agents.set_tunnel_hostnames", new_callable=AsyncMock),
        ):
            resp = await agents_client.post(
                f"/api/v1/agents/{AGENT_UUID}/heartbeat",
                json={
                    "resources": [
                        {"name": "web-01", "resource_type": "ssh", "labels": {"env": "dev"}},
                        {"name": "db-01", "resource_type": "postgres", "labels": {"env": "dev"}},
                    ],
                    "labels": {"env": "dev"},
                },
            )

        assert resp.status_code == 200
        mock_set_res.assert_called_once()
        args = mock_set_res.call_args
        assert len(args[0][2]) == 2  # 2 resources


# ── Tests: Certificate Renewal ──────────────────────────────────────────


class TestRenewCertificate:
    @pytest.mark.asyncio
    async def test_agent_not_found(self, agents_client, mock_db):
        mock_db.execute = _mock_db_execute_returning(None)

        resp = await agents_client.post(f"/api/v1/agents/{uuid4()}/renew")

        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_cn_mismatch(self, agents_client, mock_db):
        agent = _make_mock_agent(name="different-agent")
        mock_db.execute = _mock_db_execute_returning(agent)

        resp = await agents_client.post(f"/api/v1/agents/{AGENT_UUID}/renew")

        assert resp.status_code == 403
        assert "does not match" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_successful_renewal(self, agents_client, mock_db):
        agent = _make_mock_agent()
        mock_db.execute = _mock_db_execute_returning(agent)
        mock_db.flush = AsyncMock()

        mock_cert = MagicMock()
        mock_cert.not_valid_after_utc = datetime.now(UTC) + timedelta(days=365)
        mock_key = MagicMock()
        ca = MagicMock()
        ca.issue_service_certificate.return_value = (mock_cert, mock_key)
        ca.ca_cert_pem = "-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n"

        with (
            patch("bamf.api.routers.agents.get_ca", return_value=ca),
            patch("bamf.api.routers.agents.serialize_certificate", return_value=b"NEW-CERT"),
            patch("bamf.api.routers.agents.serialize_private_key", return_value=b"NEW-KEY"),
            patch("bamf.api.routers.agents.get_certificate_fingerprint", return_value="sha256:new"),
            patch("bamf.api.routers.agents.log_audit_event", new_callable=AsyncMock),
        ):
            resp = await agents_client.post(f"/api/v1/agents/{AGENT_UUID}/renew")

        assert resp.status_code == 200
        data = resp.json()
        assert data["certificate"] == "NEW-CERT"
        assert data["private_key"] == "NEW-KEY"


# ── Tests: List Agents ──────────────────────────────────────────────────


class TestListAgents:
    @pytest.mark.asyncio
    async def test_empty_list(self, agents_client, mock_db, mock_redis):
        result = MagicMock()
        result.scalars.return_value.all.return_value = []
        mock_db.execute = AsyncMock(return_value=result)

        resp = await agents_client.get("/api/v1/agents")

        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["has_more"] is False

    @pytest.mark.asyncio
    async def test_returns_agents(self, agents_client, mock_db, mock_redis):
        agent = _make_mock_agent()
        result = MagicMock()
        result.scalars.return_value.all.return_value = [agent]
        mock_db.execute = AsyncMock(return_value=result)

        # Mock Redis get to return appropriate values per key.
        # The list_agents endpoint calls r.get() for status, last_heartbeat, and bridge.
        async def redis_get_side_effect(key):
            if ":status" in key:
                return "online"
            if ":last_heartbeat" in key:
                return None
            if ":bridge" in key:
                return None
            return None

        mock_redis.get = AsyncMock(side_effect=redis_get_side_effect)

        with (
            patch(
                "bamf.api.routers.agents.get_agent_labels",
                new_callable=AsyncMock,
                return_value={"env": "dev"},
            ),
            patch(
                "bamf.api.routers.agents.get_agent_resource_count",
                new_callable=AsyncMock,
                return_value=2,
            ),
        ):
            resp = await agents_client.get("/api/v1/agents")

        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) == 1
        assert data["items"][0]["name"] == AGENT_NAME


# ── Tests: Get Agent ────────────────────────────────────────────────────


class TestGetAgent:
    @pytest.mark.asyncio
    async def test_not_found(self, agents_client, mock_db):
        mock_db.execute = _mock_db_execute_returning(None)

        resp = await agents_client.get(f"/api/v1/agents/{uuid4()}")

        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_get_by_uuid(self, agents_client, mock_db, mock_redis):
        agent = _make_mock_agent()
        mock_db.execute = _mock_db_execute_returning(agent)

        # Mock Redis get to return appropriate values per key.
        # The get_agent endpoint calls r.get() for status, last_heartbeat, and bridge.
        async def redis_get_side_effect(key):
            if ":status" in key:
                return "online"
            if ":last_heartbeat" in key:
                return None
            if ":bridge" in key:
                return None
            return None

        mock_redis.get = AsyncMock(side_effect=redis_get_side_effect)

        with (
            patch(
                "bamf.api.routers.agents.get_agent_labels", new_callable=AsyncMock, return_value={}
            ),
            patch(
                "bamf.api.routers.agents.get_agent_resource_count",
                new_callable=AsyncMock,
                return_value=0,
            ),
        ):
            resp = await agents_client.get(f"/api/v1/agents/{AGENT_UUID}")

        assert resp.status_code == 200
        assert resp.json()["name"] == AGENT_NAME


# ── Tests: Delete Agent ─────────────────────────────────────────────────


class TestDeleteAgent:
    @pytest.mark.asyncio
    async def test_not_found(self, agents_client, mock_db):
        mock_db.execute = _mock_db_execute_returning(None)

        resp = await agents_client.delete(f"/api/v1/agents/{uuid4()}")

        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_successful_delete(self, agents_client, mock_db, mock_redis):
        agent = _make_mock_agent()
        mock_db.execute = _mock_db_execute_returning(agent)
        mock_db.delete = AsyncMock()

        with patch("bamf.api.routers.agents.log_audit_event", new_callable=AsyncMock):
            resp = await agents_client.delete(f"/api/v1/agents/{AGENT_UUID}")

        assert resp.status_code == 200
        assert AGENT_NAME in resp.json()["message"]
        mock_db.delete.assert_called_once_with(agent)
        # Verify Redis cleanup
        assert mock_redis.delete.call_count >= 9  # 9 keys to delete


# ── Tests: Drain & Offline ──────────────────────────────────────────────


class TestDrainInstance:
    @pytest.mark.asyncio
    async def test_drain_success(self, agents_client, mock_db, mock_redis):
        agent = _make_mock_agent()
        mock_db.execute = _mock_db_execute_returning(agent)

        with patch(
            "bamf.services.agent_instances.drain_instance",
            new_callable=AsyncMock,
        ) as mock_drain:
            resp = await agents_client.post(
                f"/api/v1/agents/{AGENT_UUID}/drain",
                json={"instance_id": "inst-1"},
            )

        assert resp.status_code == 200
        mock_drain.assert_called_once()


class TestRemoveInstance:
    @pytest.mark.asyncio
    async def test_offline_success(self, agents_client, mock_db, mock_redis):
        agent = _make_mock_agent()
        mock_db.execute = _mock_db_execute_returning(agent)

        with patch(
            "bamf.services.agent_instances.remove_instance",
            new_callable=AsyncMock,
        ) as mock_remove:
            resp = await agents_client.post(
                f"/api/v1/agents/{AGENT_UUID}/instance/inst-1/offline",
            )

        assert resp.status_code == 200
        mock_remove.assert_called_once()
