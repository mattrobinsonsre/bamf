"""Anti-recurrence guard: every state-changing (and credential-streaming) API
route must enforce authentication.

This exists because agent heartbeat/status/events/drain/offline once shipped
**unauthenticated** (issue #193 — the /events stream leaks session certs, enabling
agent impersonation and tunnel hijack). A mutating route without a recognized
auth dependency now fails CI. Adding a new public route is a conscious act: put
it on PUBLIC_ROUTES with a reason (which a reviewer sees), or add auth.

Recognized auth = a FastAPI dependency of one of AUTH_DEPS in the route's
dependant tree. Endpoints that authenticate manually in-body (e.g. the login
flow validating a code, or an admin check via `_require_session`) are listed in
PUBLIC_ROUTES with the mechanism noted.
"""

from bamf.api.app import create_application

# Dependency-injected auth guards. verify_internal_token authenticates the
# co-located/edge proxy + bridge internal calls.
AUTH_DEPS = {
    "get_current_session",
    "get_current_user",
    "require_admin",
    "require_admin_or_audit",
    "get_agent_identity",
    "get_bridge_identity",
    "verify_internal_token",
}

# (METHOD, path) that are intentionally reachable without a DI auth dependency,
# each with the reason. Anything NOT here must carry an AUTH_DEPS dependency.
PUBLIC_ROUTES = {
    # Pre-auth login flow (the caller has no session yet).
    ("POST", "/auth/local/authorize"),  # validates email+password+PKCE
    ("POST", "/auth/local/login"),  # validates email+password
    ("POST", "/auth/token"),  # OAuth code+PKCE exchange
    ("POST", "/auth/saml/acs"),  # SAML assertion consumer
    ("POST", "/auth/logout"),  # revokes the presented bearer token
    ("POST", "/auth/logout/all"),  # manual bearer → revoke caller's sessions
    ("DELETE", "/auth/sessions/user/{email}"),  # manual _require_session + admin check
    # Token-in-body join/bootstrap (the caller has no cert yet).
    ("POST", "/agents/join"),  # agent join token
    ("POST", "/edges/join"),  # edge join token
    ("POST", "/internal/bridges/bootstrap"),  # bridge bootstrap token
}


def _dep_names(dependant) -> set[str]:
    names = set()
    call = getattr(dependant, "call", None)
    if call is not None and hasattr(call, "__name__"):
        names.add(call.__name__)
    for sub in getattr(dependant, "dependencies", []):
        names |= _dep_names(sub)
    return names


def _mutating_routes():
    app = create_application()
    routes = []

    def collect(rs):
        for r in rs:
            orig = getattr(r, "original_router", None)
            if orig is not None:
                collect(orig.routes)
            elif hasattr(r, "dependant") and getattr(r, "methods", None):
                routes.append(r)

    collect(app.routes)
    mutating = {"POST", "PUT", "PATCH", "DELETE"}
    return [r for r in routes if mutating & r.methods]


def test_all_mutating_routes_enforce_auth():
    offenders = []
    for r in _mutating_routes():
        method = sorted(m for m in r.methods if m in {"POST", "PUT", "PATCH", "DELETE"})[0]
        if AUTH_DEPS & _dep_names(r.dependant):
            continue
        if (method, r.path) in PUBLIC_ROUTES:
            continue
        offenders.append(f"{method} {r.path}")
    assert not offenders, (
        "State-changing routes without a recognized auth dependency (add auth or, "
        f"if truly public, add to PUBLIC_ROUTES with a reason): {sorted(offenders)}"
    )


def test_public_routes_allowlist_has_no_stale_entries():
    """Keep the allowlist honest — every PUBLIC_ROUTES entry must still be a real
    mutating route (so a removed/renamed endpoint can't hide a future gap)."""
    live = {
        (sorted(m for m in r.methods if m in {"POST", "PUT", "PATCH", "DELETE"})[0], r.path)
        for r in _mutating_routes()
    }
    stale = PUBLIC_ROUTES - live
    assert not stale, f"PUBLIC_ROUTES entries no longer exist as routes: {sorted(stale)}"


def test_require_cert_matches_agent_rejects_other_agents():
    """#193 regression: an agent cert may only act on its own agent record —
    a CN that doesn't match the resolved agent is 403 (no cross-agent control)."""
    from datetime import UTC, datetime
    from unittest.mock import MagicMock

    import pytest
    from fastapi import HTTPException

    from bamf.api.dependencies import AgentIdentity
    from bamf.api.routers.agents import _require_cert_matches_agent

    ident = AgentIdentity(name="agent-a", certificate=MagicMock(), expires_at=datetime.now(UTC))

    same = MagicMock()
    same.name = "agent-a"
    _require_cert_matches_agent(ident, same)  # matching CN → no raise

    other = MagicMock()
    other.name = "agent-b"
    with pytest.raises(HTTPException) as exc:
        _require_cert_matches_agent(ident, other)
    assert exc.value.status_code == 403
