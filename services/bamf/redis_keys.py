"""Canonical Redis key builders — the single source of truth for key formats.

CONTRACT — there are two SEPARATE session namespaces that must NEVER be merged:

  - ``tunnel_session_key(id)`` -> ``"session:{id}"`` — per-tunnel setup/live state,
    keyed by session id or session token (connect.py, terminal.py, tunnels.py,
    internal_bridges.py). No ``bamf:`` prefix.
  - USER sessions use the ``"bamf:session:{token}"`` prefix
    (``bamf.auth.sessions.SESSION_PREFIX``).

Prefixing the tunnel keys with ``bamf:`` (or dropping the prefix from user
session keys) would let a tunnel session id collide with a user session token
key — a catastrophic auth/state confusion. The formats and their distinctness
are locked by ``services/tests/test_redis_keys.py``, and a guard test forbids
raw ``f"session:{...}"`` literals outside this module.
"""


def tunnel_session_key(session_id: str) -> str:
    """Redis key for a tunnel session's setup/live state (short TTL)."""
    return f"session:{session_id}"


def tunnel_session_creds_key(session_id: str) -> str:
    """Redis key for a tunnel session's cached client credentials."""
    return f"session:{session_id}:client_creds"


def agent_edge_rtt_key(agent_id: str, edge: str) -> str:
    """Redis key for an agent's measured latency to a given edge (#246).

    Value is the smoothed agent→edge relay RTT in milliseconds, reported on
    each heartbeat and refreshed with the agent TTL. This is the agent-leg
    of the rendezvous cost in measured-latency edge selection (#119). Keyed
    under ``agent:{id}:*`` alongside the sibling ``agent:{id}:relay:{edge}``
    assignment key, so per-agent cleanup scans reach it.
    """
    return f"agent:{agent_id}:edge_rtt:{edge}"


def edges_registry_key() -> str:
    """Redis SET of known edge names (#280).

    A bridge SADDs its edge here on registration. It lets the agent probe-target
    builder enumerate edges with a single SMEMBERS instead of a per-heartbeat
    ``SCAN bridges:available:*`` over the whole keyspace. Membership is not
    reaped (edge names are a small, stable set), which is safe: the builder gates
    every edge on a live bridge (``bridges:available:{edge}``), so a stale entry
    for a fully-drained edge is simply skipped.
    """
    return "bamf:edges"
