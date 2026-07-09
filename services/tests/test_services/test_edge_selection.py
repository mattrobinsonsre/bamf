"""Tests for measured-latency edge selection (#119, step 2)."""

from __future__ import annotations

import pytest

from bamf.services.edge_selection import (
    EdgeCandidate,
    get_agent_edge_rtts,
    select_edge,
)


def _c(name, *, capacity=True, agent=None, client=None):
    return EdgeCandidate(name=name, has_capacity=capacity, agent_rtt_ms=agent, client_rtt_ms=client)


class TestSelectEdge:
    def test_no_candidates_returns_none(self):
        assert select_edge([]) is None

    def test_no_healthy_candidates_returns_none(self):
        # An edge with a great latency but no bridge is never chosen.
        assert select_edge([_c("eu", capacity=False, agent=1, client=1)]) is None

    def test_both_legs_minimizes_the_sum(self):
        # eu: 40+40=80, us: 10+90=100, apac: 30+30=60  → apac wins the rendezvous,
        # even though us has the smallest single (client) leg.
        candidates = [
            _c("eu", agent=40, client=40),
            _c("us", agent=10, client=90),
            _c("apac", agent=30, client=30),
        ]
        assert select_edge(candidates) == "apac"

    def test_agent_only_is_nearest_to_agent_guess(self):
        # No client legs yet → tier 2: argmin(agent).
        candidates = [
            _c("eu", agent=40),
            _c("us", agent=12),
            _c("apac", agent=25),
        ]
        assert select_edge(candidates) == "us"

    def test_client_only_is_nearest_to_client(self):
        candidates = [_c("eu", client=40), _c("us", client=12)]
        assert select_edge(candidates) == "us"

    def test_both_tier_wins_over_partial(self):
        # A candidate with both legs is chosen from tier 1; the agent-only edge
        # is never compared against it (sum vs lone leg is not comparable).
        candidates = [
            _c("eu", agent=5),  # agent-only, tiny — but ignored while tier 1 is non-empty
            _c("us", agent=50, client=50),  # both legs
        ]
        assert select_edge(candidates) == "us"

    def test_ties_break_deterministically_by_name(self):
        # Equal sums → lexicographically smallest edge name, stable across calls.
        candidates = [
            _c("zeta", agent=20, client=20),
            _c("alpha", agent=20, client=20),
        ]
        assert select_edge(candidates) == "alpha"

    def test_unhealthy_edges_filtered_before_selection(self):
        # us has the best latency but no capacity → eu is chosen.
        candidates = [
            _c("us", capacity=False, agent=1, client=1),
            _c("eu", agent=40, client=40),
        ]
        assert select_edge(candidates) == "eu"

    def test_default_used_when_no_measurements(self):
        candidates = [_c("eu"), _c("us")]
        assert select_edge(candidates, default_edge="us") == "us"

    def test_default_ignored_when_unhealthy(self):
        # Default names an edge with no capacity → no healthy fallback → None.
        candidates = [_c("us", capacity=False)]
        assert select_edge(candidates, default_edge="us") is None

    def test_no_measurements_no_default_returns_none(self):
        assert select_edge([_c("eu"), _c("us")]) is None


class _FakeRedis:
    """Minimal async Redis stub supporting a single-shot scan + get."""

    def __init__(self, data: dict[str, str]):
        self._data = data

    async def scan(self, cursor="0", match=None, count=None):
        import fnmatch

        keys = [k for k in self._data if match is None or fnmatch.fnmatch(k, match)]
        return "0", keys

    async def get(self, key):
        return self._data.get(key)


@pytest.mark.asyncio
class TestGetAgentEdgeRTTs:
    async def test_reads_and_parses_table(self):
        r = _FakeRedis(
            {
                "agent:a1:edge_rtt:eu": "12",
                "agent:a1:edge_rtt:us-east": "40",
                "agent:other:edge_rtt:eu": "5",  # different agent — excluded
                "agent:a1:relay:eu": "bridge-0",  # sibling key — excluded by scan pattern
            }
        )
        assert await get_agent_edge_rtts(r, "a1") == {"eu": 12, "us-east": 40}

    async def test_empty_when_no_samples(self):
        assert await get_agent_edge_rtts(_FakeRedis({}), "a1") == {}

    async def test_skips_malformed_values(self):
        r = _FakeRedis({"agent:a1:edge_rtt:eu": "not-a-number", "agent:a1:edge_rtt:us": "7"})
        assert await get_agent_edge_rtts(r, "a1") == {"us": 7}
