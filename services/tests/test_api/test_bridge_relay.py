"""Tests for bridge relay helpers (services/bamf/api/bridge_relay.py)."""

from __future__ import annotations

from unittest.mock import AsyncMock, patch

import pytest

from bamf.api.bridge_relay import build_agent_edge_probe_targets


def _redis_with(edges: dict[str, list[str]], bridges: dict[str, dict]):
    """A mock async Redis whose ``bamf:edges`` SET holds the edge names.

    ``edges`` maps edge name → the bridge ids in its available set (order =
    score order). ``bridges`` maps bridge id → its ``bridge:{id}`` hash.
    """
    r = AsyncMock()

    async def smembers(key):
        return set(edges.keys())

    async def zrangebyscore(key, *a, **k):
        edge = key.removeprefix("bridges:available:")
        return list(edges.get(edge, []))

    async def hgetall(key):
        return bridges.get(key.removeprefix("bridge:"), {})

    r.smembers = smembers
    r.zrangebyscore = zrangebyscore
    r.hgetall = hgetall
    return r


@pytest.mark.asyncio
async def test_build_probe_targets_one_per_edge():
    """One (edge, host, port) per edge with a live bridge; the least-loaded
    (first in the available set) bridge is used, resolved to the agent-reachable
    endpoint."""
    r = _redis_with(
        edges={"eu": ["bamf-bridge-eu-0", "bamf-bridge-eu-1"], "us": ["bamf-bridge-us-0"]},
        bridges={
            "bamf-bridge-eu-0": {"hostname": "0.bridge.eu.tunnel.example.com"},
            "bamf-bridge-us-0": {"hostname": "0.bridge.us.tunnel.example.com"},
        },
    )
    with patch(
        "bamf.api.bridge_relay.resolve_agent_bridge_endpoint",
        new=AsyncMock(side_effect=lambda r, aid, bid, host: (host, 443)),
    ):
        targets = await build_agent_edge_probe_targets(r, "agent-1")

    assert sorted(targets) == [
        ("eu", "0.bridge.eu.tunnel.example.com", 443),
        ("us", "0.bridge.us.tunnel.example.com", 443),
    ]


@pytest.mark.asyncio
async def test_build_probe_targets_skips_empty_and_bridgeless():
    """Edges with no live bridge, and a bridge with no hostname, are skipped;
    the global ``bridges:available`` set (empty edge name) is ignored."""
    r = _redis_with(
        edges={"": ["global-ignored"], "eu": ["bamf-bridge-eu-0"], "drained": []},
        bridges={"bamf-bridge-eu-0": {"hostname": "0.bridge.eu.tunnel.example.com"}},
    )
    with patch(
        "bamf.api.bridge_relay.resolve_agent_bridge_endpoint",
        new=AsyncMock(side_effect=lambda r, aid, bid, host: (host, 443)),
    ):
        targets = await build_agent_edge_probe_targets(r, "agent-1")

    assert targets == [("eu", "0.bridge.eu.tunnel.example.com", 443)]
