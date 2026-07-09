"""Real-Redis integration test for measured-latency edge selection (#119).

Unlike the mocked unit tests in ``test_api/test_connect_router.py``, this seeds a
2-edge topology into a **real** Redis and exercises the actual wiring end to end:
the ``SCAN`` of the agent-leg keys, ``ZCARD`` / ``ZRANGEBYSCORE`` of bridge
availability, and ``HGETALL`` of bridge hostnames. It is the automated stand-in
for a live 2-edge deployment — deterministic (seeded), not flaky.

Skips cleanly when no Redis is reachable (e.g. a bare ``pytest`` run without the
docker test stack); runs under ``make test-python`` and CI, which provide Redis.

Keys are namespaced per test (``request.node.name``) so the suite stays safe
under pytest-xdist parallelism.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest
import redis.asyncio as aioredis

from bamf.api.routers.connect import _build_candidate_edges, _select_edge_for_agent
from bamf.config import settings
from bamf.services.edge_selection import get_agent_edge_rtts


async def _cleanup(ns: SimpleNamespace) -> None:
    keys = [k async for k in ns.r.scan_iter(match=f"agent:{ns.agent}:*")]
    for edge in (ns.eu, ns.us):
        keys.append(f"bridges:available:{edge}")
        keys.append(f"bridge:bridge-{edge}")
    if keys:
        await ns.r.delete(*keys)


@pytest.fixture
async def edge_env(request):
    """A real Redis seeded with a 2-edge topology (eu far, us near the agent)."""
    try:
        r = aioredis.from_url(str(settings.redis_url), decode_responses=True)
        await r.ping()
    except Exception:
        pytest.skip("real Redis not available")

    suffix = request.node.name
    ns = SimpleNamespace(r=r, agent=f"itest-{suffix}", eu=f"ite-eu-{suffix}", us=f"ite-us-{suffix}")
    await _cleanup(ns)  # in case a prior run left keys behind

    # Agent-leg: the agent is near us (10 ms), far from eu (40 ms).
    await r.set(f"agent:{ns.agent}:edge_rtt:{ns.eu}", 40)
    await r.set(f"agent:{ns.agent}:edge_rtt:{ns.us}", 10)
    # One live bridge per edge, each with a registered public hostname.
    for edge in (ns.eu, ns.us):
        await r.zadd(f"bridges:available:{edge}", {f"bridge-{edge}": 0})
        await r.hset(
            f"bridge:bridge-{edge}", mapping={"hostname": f"0.bridge.{edge}.tunnel.example.com"}
        )

    yield ns

    await _cleanup(ns)
    await r.aclose()


@pytest.mark.asyncio
async def test_agent_leg_table_round_trips_through_real_redis(edge_env):
    rtts = await get_agent_edge_rtts(edge_env.r, edge_env.agent)
    assert rtts == {edge_env.eu: 40, edge_env.us: 10}


@pytest.mark.asyncio
async def test_cold_client_gets_agent_nearest_guess(edge_env):
    # No client legs → the agent-nearest edge with capacity is us (10 ms).
    assert await _select_edge_for_agent(edge_env.r, edge_env.agent) == edge_env.us


@pytest.mark.asyncio
async def test_warm_client_gets_the_rendezvous_edge(edge_env):
    # Client near eu (5), far from us (90): the rendezvous flips to eu because
    # eu 5+40=45 beats us 90+10=100 — the whole point of measuring both legs.
    client_rtts = {edge_env.eu: 5, edge_env.us: 90}
    assert await _select_edge_for_agent(edge_env.r, edge_env.agent, client_rtts) == edge_env.eu


@pytest.mark.asyncio
async def test_candidate_edges_lists_both_with_real_hostnames(edge_env):
    targets = await _build_candidate_edges(edge_env.r, edge_env.agent)
    assert {t.name for t in targets} == {edge_env.eu, edge_env.us}
    hosts = {t.name: t.probe_host for t in targets}
    assert hosts[edge_env.us] == f"0.bridge.{edge_env.us}.tunnel.example.com"
    assert all(t.probe_port > 0 for t in targets)
