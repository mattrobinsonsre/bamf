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
