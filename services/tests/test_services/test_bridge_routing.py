"""Tests for split-horizon bridge-host resolution (#167)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from bamf.services import bridge_routing

PUBLIC = "0.bridge.default.tunnel.bamf.example.com"


class FakeRedis:
    def __init__(self, data: dict | None = None):
        self._d = data or {}

    async def get(self, key: str):
        return self._d.get(key)


def _settings(monkeypatch, *, m2m="tunnel.bamf.internal"):
    monkeypatch.setattr(
        bridge_routing,
        "settings",
        SimpleNamespace(
            tunnel_domain="tunnel.bamf.example.com",
            m2m_tunnel_domain=m2m,
            namespace="bamf",
            bridge_tunnel_port=443,
            bridge_internal_tunnel_port=8443,
        ),
    )


@pytest.fixture
def domains(monkeypatch):
    _settings(monkeypatch)


@pytest.mark.asyncio
async def test_zone_in_cluster_uses_service_dns(domains):
    r = FakeRedis({"agent:a:zone": "in-cluster"})
    host, port = await bridge_routing.resolve_agent_bridge_endpoint(r, "a", "bamf-bridge-0", PUBLIC)
    assert host == "bamf-bridge-0.bamf.svc.cluster.local"
    assert port == 8443


@pytest.mark.asyncio
async def test_zone_internal_swaps_tunnel_domain(domains):
    r = FakeRedis({"agent:a:zone": "internal"})
    host, port = await bridge_routing.resolve_agent_bridge_endpoint(r, "a", "bamf-bridge-0", PUBLIC)
    assert host == "0.bridge.default.tunnel.bamf.internal"
    assert port == 443


@pytest.mark.asyncio
async def test_zone_public_uses_registered_hostname(domains):
    r = FakeRedis({"agent:a:zone": "public"})
    host, port = await bridge_routing.resolve_agent_bridge_endpoint(r, "a", "bamf-bridge-0", PUBLIC)
    assert host == PUBLIC
    assert port == 443


@pytest.mark.asyncio
async def test_backcompat_cluster_internal_maps_to_in_cluster(domains):
    r = FakeRedis({"agent:a:cluster_internal": "1"})
    host, _ = await bridge_routing.resolve_agent_bridge_endpoint(r, "a", "bamf-bridge-0", PUBLIC)
    assert host == "bamf-bridge-0.bamf.svc.cluster.local"


@pytest.mark.asyncio
async def test_default_zone_is_public(domains):
    r = FakeRedis({})
    host, _ = await bridge_routing.resolve_agent_bridge_endpoint(r, "a", "bamf-bridge-0", PUBLIC)
    assert host == PUBLIC


@pytest.mark.asyncio
async def test_internal_falls_back_to_public_when_no_m2m(monkeypatch):
    _settings(monkeypatch, m2m="")  # not configured
    r = FakeRedis({"agent:a:zone": "internal"})
    host, _ = await bridge_routing.resolve_agent_bridge_endpoint(r, "a", "bamf-bridge-0", PUBLIC)
    assert host == PUBLIC


def test_internal_bridge_host_swaps_suffix(monkeypatch):
    _settings(monkeypatch)
    assert bridge_routing.internal_bridge_host(PUBLIC) == "0.bridge.default.tunnel.bamf.internal"


def test_internal_bridge_host_fallback_on_mismatch(monkeypatch):
    _settings(monkeypatch)
    # Hostname doesn't carry the public tunnel domain → return unchanged.
    assert bridge_routing.internal_bridge_host("weird.host") == "weird.host"
