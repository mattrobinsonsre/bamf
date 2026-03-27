"""Tests for Redis-backed resource catalog.

Tests get/set operations for resources, agent labels,
tunnel hostname reverse index, and stale resource cleanup.
"""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock

import pytest

from bamf.services.resource_catalog import (
    ResourceInfo,
    get_agent_labels,
    get_agent_resource_count,
    get_resource,
    get_resource_by_tunnel_hostname,
    set_agent_labels,
    set_agent_resources,
    set_tunnel_hostnames,
)

# ── Fixtures ──────────────────────────────────────────────────────────────


def _make_resource(**overrides) -> ResourceInfo:
    defaults = {
        "name": "web-01",
        "resource_type": "ssh",
        "labels": {"env": "dev"},
        "agent_id": "agent-1",
    }
    defaults.update(overrides)
    return ResourceInfo(**defaults)


def _make_mock_redis():
    r = AsyncMock()
    r.get = AsyncMock(return_value=None)
    r.setex = AsyncMock()
    r.delete = AsyncMock()
    r.pipeline = MagicMock()
    pipe = AsyncMock()
    pipe.setex = MagicMock()
    pipe.execute = AsyncMock()
    r.pipeline.return_value = pipe
    return r, pipe


# ── Tests: get_resource ──────────────────────────────────────────────────


class TestGetResource:
    @pytest.mark.asyncio
    async def test_not_found(self):
        r = AsyncMock()
        r.get = AsyncMock(return_value=None)

        result = await get_resource(r, "nonexistent")
        assert result is None
        r.get.assert_called_once_with("resource:nonexistent")

    @pytest.mark.asyncio
    async def test_found(self):
        data = json.dumps(
            {
                "name": "web-01",
                "resource_type": "ssh",
                "labels": {"env": "prod"},
                "agent_id": "agent-1",
            }
        )
        r = AsyncMock()
        r.get = AsyncMock(return_value=data)

        result = await get_resource(r, "web-01")
        assert result is not None
        assert result.name == "web-01"
        assert result.resource_type == "ssh"
        assert result.labels == {"env": "prod"}
        assert result.agent_id == "agent-1"

    @pytest.mark.asyncio
    async def test_with_optional_fields(self):
        data = json.dumps(
            {
                "name": "grafana",
                "resource_type": "http",
                "labels": {},
                "agent_id": "agent-2",
                "hostname": "grafana.internal",
                "port": 3000,
                "tunnel_hostname": "grafana",
            }
        )
        r = AsyncMock()
        r.get = AsyncMock(return_value=data)

        result = await get_resource(r, "grafana")
        assert result.hostname == "grafana.internal"
        assert result.port == 3000
        assert result.tunnel_hostname == "grafana"


# ── Tests: set_agent_resources ───────────────────────────────────────────


class TestSetAgentResources:
    @pytest.mark.asyncio
    async def test_sets_resources(self):
        r, pipe = _make_mock_redis()
        r.get.return_value = None  # no existing resources

        resources = [_make_resource(name="web-01"), _make_resource(name="db-01")]
        await set_agent_resources(r, "agent-1", resources, ttl=180)

        assert pipe.setex.call_count == 3  # 2 resources + 1 agent:resources list
        pipe.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_cleans_stale_resources(self):
        r, pipe = _make_mock_redis()
        # Agent previously had web-01 and old-resource
        r.get.return_value = json.dumps(["web-01", "old-resource"])

        resources = [_make_resource(name="web-01")]
        await set_agent_resources(r, "agent-1", resources, ttl=180)

        # Should delete the stale resource
        r.delete.assert_called_once_with("resource:old-resource")

    @pytest.mark.asyncio
    async def test_no_stale_cleanup_when_empty(self):
        r, pipe = _make_mock_redis()
        r.get.return_value = None

        resources = [_make_resource()]
        await set_agent_resources(r, "agent-1", resources, ttl=180)

        r.delete.assert_not_called()


# ── Tests: get_agent_resource_count ──────────────────────────────────────


class TestGetAgentResourceCount:
    @pytest.mark.asyncio
    async def test_no_resources(self):
        r = AsyncMock()
        r.get = AsyncMock(return_value=None)

        count = await get_agent_resource_count(r, "agent-1")
        assert count == 0

    @pytest.mark.asyncio
    async def test_with_resources(self):
        r = AsyncMock()
        r.get = AsyncMock(return_value=json.dumps(["web-01", "db-01", "k8s-prod"]))

        count = await get_agent_resource_count(r, "agent-1")
        assert count == 3


# ── Tests: get_agent_labels ──────────────────────────────────────────────


class TestGetAgentLabels:
    @pytest.mark.asyncio
    async def test_no_labels(self):
        r = AsyncMock()
        r.get = AsyncMock(return_value=None)

        labels = await get_agent_labels(r, "agent-1")
        assert labels == {}

    @pytest.mark.asyncio
    async def test_with_labels(self):
        r = AsyncMock()
        r.get = AsyncMock(return_value=json.dumps({"env": "prod", "region": "us-east"}))

        labels = await get_agent_labels(r, "agent-1")
        assert labels == {"env": "prod", "region": "us-east"}


# ── Tests: set_agent_labels ──────────────────────────────────────────────


class TestSetAgentLabels:
    @pytest.mark.asyncio
    async def test_sets_labels(self):
        r = AsyncMock()
        r.setex = AsyncMock()

        await set_agent_labels(r, "agent-1", {"env": "prod"}, ttl=180)

        r.setex.assert_called_once_with("agent:agent-1:labels", 180, json.dumps({"env": "prod"}))


# ── Tests: get_resource_by_tunnel_hostname ───────────────────────────────


class TestGetResourceByTunnelHostname:
    @pytest.mark.asyncio
    async def test_not_found(self):
        r = AsyncMock()
        r.get = AsyncMock(return_value=None)

        result = await get_resource_by_tunnel_hostname(r, "nonexistent")
        assert result is None

    @pytest.mark.asyncio
    async def test_found(self):
        resource_data = json.dumps(
            {
                "name": "grafana",
                "resource_type": "http",
                "labels": {},
                "agent_id": "agent-1",
                "tunnel_hostname": "grafana",
            }
        )

        r = AsyncMock()
        r.get = AsyncMock(
            side_effect=lambda key: {
                "tunnel:grafana": "grafana",
                "resource:grafana": resource_data,
            }.get(key)
        )

        result = await get_resource_by_tunnel_hostname(r, "grafana")
        assert result is not None
        assert result.name == "grafana"

    @pytest.mark.asyncio
    async def test_tunnel_exists_but_resource_gone(self):
        """Tunnel hostname key exists but resource key expired."""
        r = AsyncMock()
        r.get = AsyncMock(
            side_effect=lambda key: {
                "tunnel:grafana": "grafana",
                "resource:grafana": None,
            }.get(key)
        )

        result = await get_resource_by_tunnel_hostname(r, "grafana")
        assert result is None


# ── Tests: set_tunnel_hostnames ──────────────────────────────────────────


class TestSetTunnelHostnames:
    @pytest.mark.asyncio
    async def test_sets_http_resources_only(self):
        r, pipe = _make_mock_redis()

        resources = [
            _make_resource(name="grafana", resource_type="http", tunnel_hostname="grafana"),
            _make_resource(name="ssh-box", resource_type="ssh"),  # no tunnel_hostname
        ]

        await set_tunnel_hostnames(r, resources, ttl=180)

        # Only the HTTP resource with tunnel_hostname should be set
        assert pipe.setex.call_count == 1
        pipe.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_no_tunnel_hostnames(self):
        r, pipe = _make_mock_redis()

        resources = [_make_resource(name="ssh-box")]
        await set_tunnel_hostnames(r, resources, ttl=180)

        pipe.setex.assert_not_called()
        pipe.execute.assert_called_once()


# ── Tests: ResourceInfo ──────────────────────────────────────────────────


class TestResourceInfo:
    def test_defaults(self):
        r = ResourceInfo(name="x", resource_type="ssh", labels={}, agent_id="a")
        assert r.hostname is None
        assert r.port is None
        assert r.tunnel_hostname is None
        assert r.outpost is None
        assert r.webhooks == []

    def test_with_webhooks(self):
        r = ResourceInfo(
            name="x",
            resource_type="http",
            labels={},
            agent_id="a",
            webhooks=[{"path": "/hook", "methods": ["POST"]}],
        )
        assert len(r.webhooks) == 1
