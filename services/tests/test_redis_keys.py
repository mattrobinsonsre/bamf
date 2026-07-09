"""Guard the Redis session-key namespaces (see bamf/redis_keys.py).

The catastrophic failure this prevents: merging the tunnel-session namespace
(``session:{id}``) with the user-session namespace (``bamf:session:{token}``),
which would let a tunnel id collide with a user session token key.
"""

import re
from pathlib import Path

import bamf
from bamf.auth.sessions import SESSION_PREFIX
from bamf.redis_keys import (
    agent_edge_rtt_key,
    tunnel_session_creds_key,
    tunnel_session_key,
)

_BAMF_SRC = Path(bamf.__file__).resolve().parent


def test_tunnel_session_key_formats():
    assert tunnel_session_key("abc") == "session:abc"
    assert tunnel_session_creds_key("abc") == "session:abc:client_creds"


def test_agent_edge_rtt_key_format():
    # Keyed under agent:{id}:* (like the sibling relay-assignment key), and
    # never in the tunnel-session namespace.
    assert agent_edge_rtt_key("agent-1", "eu") == "agent:agent-1:edge_rtt:eu"
    assert not agent_edge_rtt_key("a", "eu").startswith("session:")


def test_session_namespaces_stay_distinct():
    # Tunnel-session keys must NOT carry the user-session `bamf:` prefix.
    assert not tunnel_session_key("x").startswith("bamf:")
    assert not tunnel_session_creds_key("x").startswith("bamf:")
    # User sessions live under a separate, prefixed namespace.
    assert SESSION_PREFIX == "bamf:session:"
    # The two never collide for the same id/token.
    assert tunnel_session_key("t") != SESSION_PREFIX + "t"


def test_no_raw_tunnel_session_literals_outside_module():
    """New code must build tunnel-session keys via redis_keys, not raw f-strings —
    a stray f"session:{...}" risks drifting from or colliding with the namespace."""
    offenders = []
    for py in _BAMF_SRC.rglob("*.py"):
        if py.name == "redis_keys.py":
            continue
        for n, line in enumerate(py.read_text().splitlines(), 1):
            if re.search(r'f"session:\{', line):
                offenders.append(f"{py.relative_to(_BAMF_SRC)}:{n}")
    assert not offenders, f"raw tunnel-session key literals (use bamf.redis_keys): {offenders}"
