"""Resolve which bridge endpoint an agent should dial, per its network zone.

Split-horizon / multi-vantage routing (#167). The hub (API) and the bridge are
reachable from up to three vantages, and an agent/edge is handed the bridge dial
host that matches the one it lives in:

- ``in-cluster`` — K8s Service DNS (co-located edges).
- ``internal``   — the internal-ingress SNI hostname (the ``gateway.m2m``
  binding's tunnel domain), for edges on a private/TGW network.
- ``public``     — the bridge's registered public SNI hostname (external edges;
  also the CLI/human path).

The zone comes from ``agent:{id}:zone`` in Redis (reported by the agent). For
back-compat, the older ``agent:{id}:cluster_internal`` boolean maps to
``in-cluster``; absence of both means ``public`` (today's default).
"""

from __future__ import annotations

from bamf.config import settings

ZONE_IN_CLUSTER = "in-cluster"
ZONE_INTERNAL = "internal"
ZONE_PUBLIC = "public"
VALID_ZONES = frozenset({ZONE_IN_CLUSTER, ZONE_INTERNAL, ZONE_PUBLIC})


async def resolve_agent_zone(r, agent_id: str) -> str:
    """Return the agent's network zone (in-cluster | internal | public)."""
    zone = await r.get(f"agent:{agent_id}:zone")
    if zone in VALID_ZONES:
        return zone
    # Back-compat: the boolean cluster_internal flag predates zones.
    if await r.get(f"agent:{agent_id}:cluster_internal"):
        return ZONE_IN_CLUSTER
    return ZONE_PUBLIC


def internal_bridge_host(public_hostname: str) -> str:
    """Map a bridge's public SNI hostname to its internal-ingress equivalent.

    The two hostnames share the same ``{ordinal}.bridge[.{edge}]`` prefix and
    differ only in the trailing tunnel domain, so we swap the public
    ``tunnel_domain`` suffix for the ``m2m_tunnel_domain``. If no m2m domain is
    configured (or the hostname doesn't carry the public domain), fall back to
    the public hostname — never invent an unreachable name.
    """
    public_td = settings.tunnel_domain
    m2m_td = settings.m2m_tunnel_domain
    if m2m_td and public_td and public_hostname.endswith(public_td):
        return public_hostname[: -len(public_td)] + m2m_td
    return public_hostname


async def resolve_agent_bridge_endpoint(
    r, agent_id: str, bridge_id: str, public_hostname: str
) -> tuple[str, int]:
    """Resolve the (host, port) the agent should dial for this bridge.

    ``public_hostname`` is the bridge's registered public SNI hostname
    (``bridge:{id}`` → ``hostname``).
    """
    zone = await resolve_agent_zone(r, agent_id)
    if zone == ZONE_IN_CLUSTER:
        return (
            f"{bridge_id}.{settings.namespace}.svc.cluster.local",
            settings.bridge_internal_tunnel_port,
        )
    if zone == ZONE_INTERNAL:
        return internal_bridge_host(public_hostname), settings.bridge_tunnel_port
    return public_hostname, settings.bridge_tunnel_port
