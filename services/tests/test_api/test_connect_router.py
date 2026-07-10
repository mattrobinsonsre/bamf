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
    _build_candidate_edges,
    _extract_ordinal,
    _select_edge_for_agent,
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
    r.zcard = AsyncMock(return_value=0)
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


def _mock_resource(name="web-01", resource_type="ssh", agent_id="agent-1", edge=None):
    """Create a mock ResourceInfo."""
    r = MagicMock()
    r.name = name
    r.resource_type = resource_type
    r.agent_id = agent_id
    r.labels = {"env": "dev"}
    r.edge = edge
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
            patch("bamf.api.routers.connect.settings") as mock_settings,
        ):
            mock_settings.target_tunnels_per_pod = 10
            mock_settings.default_edge_name = None

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
        mock_redis.hgetall.return_value = {"hostname": "0.bridge.tunnel.example.com", "edge": ""}

        ca = _mock_ca()

        with (
            patch("bamf.api.routers.connect.get_resource", new=AsyncMock(return_value=resource)),
            patch("bamf.api.routers.connect.check_access", new=AsyncMock(return_value=True)),
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
            mock_settings.default_edge_name = None

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
            mock_settings.default_edge_name = None

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

    @pytest.mark.asyncio
    async def test_reconnect_rehomes_to_best_edge_with_client_legs(self, mock_db):
        from bamf.api.models.connect import ConnectRequest
        from bamf.api.routers.connect import _handle_reconnect

        session_data = json.dumps(
            {
                "user_email": "user@example.com",
                "resource_name": "web-01",
                "agent_id": "agent-1",
                "bridge_id": "bridge-0",
                "edge_name": "eu",  # session opened on eu
            }
        )
        r = _make_mock_redis()

        async def get_side(key):
            return "online" if "status" in key else session_data

        r.get = AsyncMock(side_effect=get_side)

        captured = {}

        async def fake_issue(**kwargs):
            captured.update(kwargs)
            return MagicMock()

        req = ConnectRequest(
            resource_name="web-01",
            reconnect_session_id="s",
            client_edge_rtts={"us": 5},
        )
        with (
            patch(
                "bamf.api.routers.connect._select_edge_for_agent",
                new=AsyncMock(return_value="us"),
            ),
            patch("bamf.api.routers.connect._issue_session", new=fake_issue),
        ):
            await _handle_reconnect(req, mock_db, r, USER_SESSION)

        # Reconnect re-homed from eu to the rendezvous edge us.
        assert captured["edge_name"] == "us"

    @pytest.mark.asyncio
    async def test_reconnect_keeps_edge_without_client_legs(self, mock_db):
        from bamf.api.models.connect import ConnectRequest
        from bamf.api.routers.connect import _handle_reconnect

        session_data = json.dumps(
            {
                "user_email": "user@example.com",
                "resource_name": "web-01",
                "agent_id": "agent-1",
                "bridge_id": "bridge-0",
                "edge_name": "eu",
            }
        )
        r = _make_mock_redis()

        async def get_side(key):
            return "online" if "status" in key else session_data

        r.get = AsyncMock(side_effect=get_side)

        captured = {}

        async def fake_issue(**kwargs):
            captured.update(kwargs)
            return MagicMock()

        req = ConnectRequest(resource_name="web-01", reconnect_session_id="s")
        sel = AsyncMock(return_value="us")
        with (
            patch("bamf.api.routers.connect._select_edge_for_agent", new=sel),
            patch("bamf.api.routers.connect._issue_session", new=fake_issue),
        ):
            await _handle_reconnect(req, mock_db, r, USER_SESSION)

        # No fresh client legs → selector not consulted, prior edge kept.
        sel.assert_not_awaited()
        assert captured["edge_name"] == "eu"


class _EdgeRedis:
    """Fake Redis for the edge-selection guess: an agent-leg RTT table plus
    per-edge bridge capacity."""

    def __init__(self, rtts: dict[str, int], capacity: dict[str, int]):
        self._keys = {f"agent:a1:edge_rtt:{e}": str(ms) for e, ms in rtts.items()}
        self._capacity = capacity

    async def scan(self, cursor="0", match=None, count=None):
        import fnmatch

        return "0", [k for k in self._keys if fnmatch.fnmatch(k, match)]

    async def get(self, key):
        return self._keys.get(key)

    async def zcard(self, key):
        # key is "bridges:available:{edge}"
        return self._capacity.get(key.rsplit(":", 1)[-1], 0)


@pytest.mark.asyncio
class TestSelectEdgeForAgent:
    async def test_selects_agent_nearest_with_capacity(self):
        r = _EdgeRedis({"eu": 40, "us": 12}, {"eu": 2, "us": 2})
        assert await _select_edge_for_agent(r, "a1") == "us"

    async def test_skips_nearest_without_capacity(self):
        # us is nearer but has no bridge → eu is chosen.
        r = _EdgeRedis({"eu": 40, "us": 12}, {"eu": 2, "us": 0})
        assert await _select_edge_for_agent(r, "a1") == "eu"

    async def test_none_when_no_measurements(self):
        # No agent-leg data → caller falls back to the default edge.
        assert await _select_edge_for_agent(_EdgeRedis({}, {}), "a1") is None

    async def test_none_when_no_capacity_anywhere(self):
        r = _EdgeRedis({"eu": 40, "us": 12}, {"eu": 0, "us": 0})
        assert await _select_edge_for_agent(r, "a1") is None

    async def test_client_legs_flip_the_choice_to_the_rendezvous(self):
        # Agent-nearest is us (10). But the client is far from us and near eu,
        # so the rendezvous (client+agent) is eu: 10+40=50 < 90+10=100.
        r = _EdgeRedis({"eu": 40, "us": 10}, {"eu": 2, "us": 2})
        assert await _select_edge_for_agent(r, "a1") == "us"  # no client legs → guess
        assert (
            await _select_edge_for_agent(r, "a1", {"eu": 10, "us": 90}) == "eu"
        )  # with client legs → rendezvous

    async def test_client_leg_only_edge_considered_when_no_agent_leg(self):
        # An edge the agent never measured but the client did is still a
        # candidate (tier 3), provided it has capacity.
        r = _EdgeRedis({}, {"eu": 2})
        assert await _select_edge_for_agent(r, "a1", {"eu": 15}) == "eu"


class _CandidateRedis:
    """Fake Redis for _build_candidate_edges: an agent-leg table, a bridge per
    edge (bridges:available:{edge}), and each bridge's registered hostname."""

    def __init__(self, agent_rtts: dict[str, int], bridge_hosts: dict[str, str]):
        # bridge_hosts: edge -> bridge hostname (edge has a live bridge iff present)
        self._keys = {f"agent:a1:edge_rtt:{e}": str(ms) for e, ms in agent_rtts.items()}
        self._bridge_hosts = bridge_hosts

    async def scan(self, cursor="0", match=None, count=None):
        import fnmatch

        return "0", [k for k in self._keys if fnmatch.fnmatch(k, match)]

    async def get(self, key):
        return self._keys.get(key)

    async def zrangebyscore(self, key, *_args, **_kwargs):
        edge = key.rsplit(":", 1)[-1]  # bridges:available:{edge}
        return [f"bridge-{edge}"] if edge in self._bridge_hosts else []

    async def hgetall(self, key):
        edge = key.removeprefix("bridge:bridge-")  # bridge:bridge-{edge}
        host = self._bridge_hosts.get(edge)
        return {"hostname": host} if host else {}


@pytest.mark.asyncio
class TestBuildCandidateEdges:
    async def test_lists_probe_targets_for_multi_edge(self):
        r = _CandidateRedis(
            {"eu": 12, "us": 40},
            {"eu": "0.bridge.eu.tunnel.example.com", "us": "0.bridge.us.tunnel.example.com"},
        )
        targets = await _build_candidate_edges(r, "a1")
        assert {t.name for t in targets} == {"eu", "us"}
        eu = next(t for t in targets if t.name == "eu")
        assert eu.probe_host == "0.bridge.eu.tunnel.example.com"
        assert eu.probe_port > 0

    async def test_empty_for_single_edge(self):
        # Nothing to choose between → no probing.
        r = _CandidateRedis({"eu": 12}, {"eu": "0.bridge.eu.tunnel.example.com"})
        assert await _build_candidate_edges(r, "a1") == []

    async def test_skips_edges_without_a_live_bridge(self):
        # us has an agent-leg but no bridge → only eu remains → <2 → [].
        r = _CandidateRedis({"eu": 12, "us": 40}, {"eu": "0.bridge.eu.tunnel.example.com"})
        assert await _build_candidate_edges(r, "a1") == []


class _ReevalRedis:
    """Fake Redis for the reevaluate endpoint: a session JSON blob, an agent-leg
    table, and per-edge bridge capacity."""

    def __init__(self, session_json, agent_rtts: dict[str, int], capacity: dict[str, int]):
        self._session = session_json
        self._rtt_keys = {f"agent:a1:edge_rtt:{e}": str(ms) for e, ms in agent_rtts.items()}
        self._capacity = capacity

    async def get(self, key):
        if key.startswith("session:"):
            return self._session
        return self._rtt_keys.get(key)

    async def scan(self, cursor="0", match=None, count=None):
        import fnmatch

        return "0", [k for k in self._rtt_keys if fnmatch.fnmatch(k, match)]

    async def zcard(self, key):
        return self._capacity.get(key.rsplit(":", 1)[-1], 0)


@pytest.mark.asyncio
class TestReevaluate:
    def _session(self, user="user@example.com", edge="eu"):
        return json.dumps({"user_email": user, "agent_id": "a1", "edge_name": edge})

    async def _call(self, r):
        from bamf.api.models.connect import ReevaluateRequest
        from bamf.api.routers.connect import reevaluate_session_edge

        req = ReevaluateRequest(session_id="s", client_edge_rtts={"eu": 50, "us": 20})
        return await reevaluate_session_edge(req, r, USER_SESSION)

    async def test_hops_when_a_meaningfully_better_edge_exists(self):
        # eu 50+50=100 vs us 20+20=40 → hop to us.
        r = _ReevalRedis(self._session(edge="eu"), {"eu": 50, "us": 20}, {"eu": 1, "us": 1})
        assert (await self._call(r)).hop_edge == "us"

    async def test_stays_when_current_edge_is_best(self):
        from bamf.api.models.connect import ReevaluateRequest
        from bamf.api.routers.connect import reevaluate_session_edge

        r = _ReevalRedis(self._session(edge="eu"), {"eu": 10, "us": 50}, {"eu": 1, "us": 1})
        req = ReevaluateRequest(session_id="s", client_edge_rtts={"eu": 10, "us": 50})
        assert (await reevaluate_session_edge(req, r, USER_SESSION)).hop_edge is None

    async def test_wrong_user_forbidden(self):
        from fastapi import HTTPException

        r = _ReevalRedis(self._session(user="other@example.com"), {}, {})
        with pytest.raises(HTTPException) as exc:
            await self._call(r)
        assert exc.value.status_code == 403

    async def test_session_not_found(self):
        from fastapi import HTTPException

        r = _ReevalRedis(None, {}, {})
        with pytest.raises(HTTPException) as exc:
            await self._call(r)
        assert exc.value.status_code == 404


@pytest.mark.asyncio
class TestMeasureThenCommit:
    """Gate: recorded (non-migratable) sessions probe-then-commit rather than
    open on the un-hoppable guess (#267)."""

    async def _run(self, req, *, resource_type="ssh-audit", edge=None, candidates):
        from bamf.api.routers.connect import _handle_new_connection

        resource = _mock_resource(resource_type=resource_type, edge=edge)
        r = _make_mock_redis()
        r.get = AsyncMock(return_value="online")  # agent status

        async def fake_issue(**kwargs):
            return MagicMock(probe_required=False, session_id="issued")

        with (
            patch("bamf.api.routers.connect.get_resource", new=AsyncMock(return_value=resource)),
            patch("bamf.api.routers.connect.check_access", new=AsyncMock(return_value=True)),
            patch(
                "bamf.api.routers.connect._build_candidate_edges",
                new=AsyncMock(return_value=candidates),
            ),
            patch("bamf.api.routers.connect._issue_session", new=fake_issue),
        ):
            return await _handle_new_connection(req, AsyncMock(), r, USER_SESSION)

    def _req(self, **kw):
        from bamf.api.models.connect import ConnectRequest

        return ConnectRequest(resource_name="host", **kw)

    def _two_edges(self):
        from bamf.api.models.connect import EdgeProbeTarget

        return [
            EdgeProbeTarget(name="eu", probe_host="0.bridge.eu.example.com", probe_port=443),
            EdgeProbeTarget(name="us", probe_host="0.bridge.us.example.com", probe_port=443),
        ]

    async def test_probe_required_for_cold_ssh_audit_multi_edge(self):
        resp = await self._run(self._req(probe_retry_supported=True), candidates=self._two_edges())
        assert resp.probe_required is True
        assert resp.session_id == ""  # no session issued
        assert {c.name for c in resp.candidate_edges} == {"eu", "us"}

    async def test_no_probe_when_client_legs_already_present(self):
        # Warm client → already has the client-leg → place directly, no round-trip.
        resp = await self._run(
            self._req(probe_retry_supported=True, client_edge_rtts={"eu": 5}),
            candidates=self._two_edges(),
        )
        assert resp.session_id == "issued"

    async def test_no_probe_for_migratable_resource(self):
        resp = await self._run(
            self._req(probe_retry_supported=True), resource_type="ssh", candidates=self._two_edges()
        )
        assert resp.session_id == "issued"

    async def test_no_probe_for_pinned_resource(self):
        resp = await self._run(
            self._req(probe_retry_supported=True), edge="eu", candidates=self._two_edges()
        )
        assert resp.session_id == "issued"

    async def test_no_probe_for_single_edge(self):
        # _build_candidate_edges returns [] when there is nothing to choose between.
        resp = await self._run(self._req(probe_retry_supported=True), candidates=[])
        assert resp.session_id == "issued"

    async def test_no_probe_without_capability_flag(self):
        # Older CLI that can't handle probe_required → old behaviour (the guess).
        resp = await self._run(self._req(), candidates=self._two_edges())
        assert resp.session_id == "issued"


@pytest.mark.asyncio
class TestSessionEdgeConsistency:
    """The session must record the SELECTED bridge's actual edge so the
    reconnect decrement matches the connect increment (#266)."""

    async def test_stores_bridge_edge_and_increments_matching_set(
        self, connect_client, mock_redis, mock_db
    ):
        resource = _mock_resource()

        def get_side_effect(key):
            return "online" if "status" in key else None

        mock_redis.get.side_effect = get_side_effect
        mock_redis.zrangebyscore.return_value = [("bridge-0", 0)]
        # The selected bridge actually lives in edge "us" (e.g. bridge selection
        # fell back to the global pool from a different requested edge).
        mock_redis.hgetall.return_value = {"hostname": "0.bridge.us.example.com", "edge": "us"}
        ca = _mock_ca()

        with (
            patch("bamf.api.routers.connect.get_resource", new=AsyncMock(return_value=resource)),
            patch("bamf.api.routers.connect.check_access", new=AsyncMock(return_value=True)),
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
            mock_settings.default_edge_name = None

            resp = await connect_client.post(
                "/api/v1/connect",
                json={"resource_name": "web-01"},
                headers={"Authorization": "Bearer test"},
            )

        assert resp.status_code == 200

        # The session JSON stored via setex carries the BRIDGE's edge (us).
        session_writes = [
            c
            for c in mock_redis.setex.call_args_list
            if c.args
            and str(c.args[0]).startswith("session:")
            and not str(c.args[0]).endswith(":client_creds")
        ]
        assert session_writes, "session was stored"
        stored = json.loads(session_writes[0].args[2])
        assert stored["edge_name"] == "us"

        # …and the per-edge increment used that same set — so a later reconnect,
        # which decrements bridges:available:{stored edge}, lands on it.
        assert any(
            c.args and c.args[0] == "bridges:available:us"
            for c in mock_redis.zincrby.call_args_list
        ), "per-edge counter incremented on the bridge's actual edge"
