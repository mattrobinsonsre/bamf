"""Measured-latency edge selection (#119).

Routing a tunnel ``client → edge → agent`` costs

    cost(E) = RTT(client, E) + RTT(E, agent)

— the agent→target leg is constant and drops out, so the edge is a *rendezvous*
and the goal is the shortest detour through it, not the nearest edge to either
end. Selection minimizes that sum from **measured** scalar legs. It never
triangulates or uses geography: internet latency is non-Euclidean and routinely
violates the triangle inequality, so neither coordinates nor a single leg
predict the sum (see #119).

The leg tables are gathered separately — the agent-leg from Redis
(``get_agent_edge_rtts``, harvested from heartbeats in #246), the client-leg
from the client probe (a later step) — and fed to :func:`select_edge`, which is
a pure, table-testable function.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class EdgeCandidate:
    """One edge under consideration, with whatever legs have been measured.

    ``agent_rtt_ms`` / ``client_rtt_ms`` are ``None`` when that leg has not been
    measured yet. ``has_capacity`` is False when the edge has no live bridge to
    serve a tunnel — such edges are never selected regardless of latency.
    """

    name: str
    has_capacity: bool
    agent_rtt_ms: int | None = None
    client_rtt_ms: int | None = None


def select_edge(
    candidates: list[EdgeCandidate],
    default_edge: str | None = None,
) -> str | None:
    """Pick the rendezvous edge minimizing ``client_leg + agent_leg``.

    Only edges with capacity are candidates. Selection degrades by information
    tier so a partial leg table still yields the best available decision:

    1. edges with **both** legs   → ``argmin(client + agent)``  (true rendezvous)
    2. else edges with agent-leg  → ``argmin(agent)``           (nearest-to-agent guess)
    3. else edges with client-leg → ``argmin(client)``          (nearest-to-client)
    4. else                       → the default edge, if it is healthy

    Costs are only ever compared within a single tier, never across (a sum and a
    lone leg are not comparable). Ties break deterministically by edge name, so
    the choice is stable across calls and does not flap. Returns ``None`` when no
    edge has capacity, or when tier 4 has no healthy default to fall back to.
    """
    healthy = [c for c in candidates if c.has_capacity]
    if not healthy:
        return None

    both = [c for c in healthy if c.agent_rtt_ms is not None and c.client_rtt_ms is not None]
    if both:
        return min(both, key=lambda c: (c.client_rtt_ms + c.agent_rtt_ms, c.name)).name

    agent_only = [c for c in healthy if c.agent_rtt_ms is not None]
    if agent_only:
        return min(agent_only, key=lambda c: (c.agent_rtt_ms, c.name)).name

    client_only = [c for c in healthy if c.client_rtt_ms is not None]
    if client_only:
        return min(client_only, key=lambda c: (c.client_rtt_ms, c.name)).name

    # No measurements at all — fall back to the default edge only if it can
    # actually serve a tunnel; otherwise let the caller decide.
    if default_edge and any(c.name == default_edge for c in healthy):
        return default_edge
    return None


async def get_agent_edge_rtts(r, agent_id: str) -> dict[str, int]:
    """Read the agent-leg RTT table ``{edge → ms}`` for an agent from Redis.

    Reads the ``agent:{id}:edge_rtt:{edge}`` keys harvested from heartbeats
    (#246). Missing or malformed values are skipped. Returns an empty dict when
    the agent has reported no measurements.
    """
    from bamf.redis_keys import agent_edge_rtt_key

    prefix = agent_edge_rtt_key(agent_id, "")
    rtts: dict[str, int] = {}
    cursor = "0"
    while True:
        cursor, keys = await r.scan(cursor=cursor, match=f"{prefix}*", count=50)
        for key in keys:
            value = await r.get(key)
            if value is None:
                continue
            try:
                rtts[key[len(prefix) :]] = int(value)
            except TypeError, ValueError:
                continue
        if cursor == 0 or cursor == "0":
            break
    return rtts
