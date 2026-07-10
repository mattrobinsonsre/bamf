"""Shared bridge relay helpers for HTTP proxy and Kubernetes proxy.

Provides common functions for forwarding requests through bridge relay
connections to agents: bridge selection, relay_connect SSE signaling,
and HTTP forwarding.

Relay connection lifecycle:
- The first proxy request for an agent triggers relay_connect via SSE.
- ``ensure_relay_connected()`` uses a Redis lock to prevent duplicate
  relay_connect commands when many browser requests arrive at once.
- Subsequent requests reuse the existing relay until it goes idle.
"""

from __future__ import annotations

import asyncio

from bamf.api.agent_commands import enqueue_agent_command
from bamf.auth.ca import get_ca
from bamf.config import settings
from bamf.logging_config import get_logger
from bamf.redis_keys import edges_registry_key
from bamf.services.bridge_routing import resolve_agent_bridge_endpoint

logger = get_logger(__name__)

# Bridge internal health/relay port
BRIDGE_INTERNAL_PORT = 8080

# How long to wait for a relay connection to establish after sending relay_connect.
# The agent typically connects in <100ms; 1 second is generous.
RELAY_CONNECT_WAIT_SECONDS = 1

# How long to poll for relay readiness (total wall-clock budget)
RELAY_READY_TIMEOUT_SECONDS = 10

# Polling interval when waiting for relay readiness
RELAY_POLL_INTERVAL_SECONDS = 0.5


async def assign_relay_bridge(r, agent_id: str, edge_name: str | None = None) -> str | None:
    """Assign a bridge for the agent's relay connection.

    Picks the least-loaded bridge from the sorted set and stores
    the assignment in Redis.

    When edge_name is provided, uses the per-edge sorted set
    (bridges:available:{edge_name}) and stores the assignment in
    agent:{id}:relay:{edge_name}. Falls back to the global
    bridges:available set for backward compatibility.
    """
    # Try edge-specific pool first, then global
    bridge_id = None
    if edge_name:
        bridges = await r.zrangebyscore(
            f"bridges:available:{edge_name}", "-inf", "+inf", start=0, num=1
        )
        if bridges:
            bridge_id = bridges[0]

    if bridge_id is None:
        bridges = await r.zrangebyscore("bridges:available", "-inf", "+inf", start=0, num=1)
        if not bridges:
            return None
        bridge_id = bridges[0]

    # Store assignment with agent TTL (refreshed on heartbeat)
    if edge_name:
        await r.setex(f"agent:{agent_id}:relay:{edge_name}", 180, bridge_id)
    await r.setex(f"agent:{agent_id}:relay_bridge", 180, bridge_id)

    logger.info(
        "Assigned relay bridge",
        agent_id=agent_id,
        bridge_id=bridge_id,
        edge_name=edge_name,
    )
    return bridge_id


async def send_relay_connect(
    r, agent_id: str, bridge_id: str, edge_name: str | None = None
) -> None:
    """Send a relay_connect SSE event to a specific agent instance via Redis pub/sub.

    Selects the best instance (preferring one without an active relay) and
    routes the command to its instance-specific channel.
    """
    from bamf.services.agent_instances import select_agent_instance, set_instance_has_relay

    instance_id = await select_agent_instance(r, agent_id, prefer_no_relay=True)
    if not instance_id:
        logger.warning("No live agent instances for relay_connect", agent_id=agent_id)
        return

    bridge_info = await r.hgetall(f"bridge:{bridge_id}")
    bridge_hostname = bridge_info.get("hostname", bridge_id)
    bridge_host, bridge_port = await resolve_agent_bridge_endpoint(
        r, agent_id, bridge_id, bridge_hostname
    )

    # Include CA cert so the agent can verify the bridge's certificate.
    # The agent may have joined with a previous CA — always send the current one.
    ca = get_ca()

    # Enqueue on the selected instance's reliable delivery queue.
    await enqueue_agent_command(
        r,
        agent_id,
        instance_id,
        {
            "command": "relay_connect",
            "bridge_host": bridge_host,
            "bridge_port": bridge_port,
            "ca_certificate": ca.ca_cert_pem,
            # Which edge this relay is for — the agent keys its per-edge relay
            # map on this so it holds one relay per edge (#194). Omitted (agent
            # defaults to a single "" key) when no edge is in play.
            **({"edge": edge_name} if edge_name else {}),
        },
    )

    # Mark this instance as having a relay connection
    await set_instance_has_relay(r, agent_id, instance_id, True)

    logger.info(
        "Sent relay_connect to agent instance",
        agent_id=agent_id,
        instance_id=instance_id,
        bridge_host=bridge_host,
        bridge_port=bridge_port,
    )


async def ensure_relay_connected(
    r,
    agent_id: str,
    relay_bridge: str,
    edge_name: str | None = None,
) -> bool:
    """Ensure the agent has an active relay connection to the bridge.

    Uses a Redis lock to prevent duplicate relay_connect commands when
    many concurrent requests arrive for an unconnected agent (e.g. a
    browser loading HTML + CSS + JS + favicon simultaneously). The lock is
    per-edge so concurrent requests to *different* edges each get their own
    relay_connect (#194).

    Returns True if the relay is believed ready, False on timeout.
    """
    lock_key = f"agent:{agent_id}:relay_connecting:{edge_name or 'default'}"

    # Try to acquire the lock (NX = set-if-not-exists, EX = auto-expire)
    acquired = await r.set(lock_key, "1", nx=True, ex=RELAY_READY_TIMEOUT_SECONDS + 5)

    if acquired:
        # We won the race — send relay_connect and wait for it to establish.
        await send_relay_connect(r, agent_id, relay_bridge, edge_name)
        await asyncio.sleep(RELAY_CONNECT_WAIT_SECONDS)
        # Clean up the lock so the next cold-start can send relay_connect.
        await r.delete(lock_key)
        return True

    # Another request already triggered relay_connect — wait for it.
    loop = asyncio.get_running_loop()
    deadline = loop.time() + RELAY_READY_TIMEOUT_SECONDS
    while loop.time() < deadline:
        # If the lock is gone, the winner finished and relay should be up.
        if not await r.exists(lock_key):
            return True
        await asyncio.sleep(RELAY_POLL_INTERVAL_SECONDS)

    logger.warning(
        "Timed out waiting for relay connection",
        agent_id=agent_id,
        relay_bridge=relay_bridge,
    )
    return False


def build_bridge_relay_host(relay_bridge: str) -> str:
    """Return the FQDN of a bridge pod's internal relay endpoint."""
    headless_svc = settings.bridge_headless_service
    return f"{relay_bridge}.{headless_svc}.{settings.namespace}.svc.cluster.local"


async def build_agent_edge_probe_targets(r, agent_id: str) -> list[tuple[str, str, int]]:
    """Edges the agent should latency-probe to measure its agent-leg (#277).

    Returns ``(edge, host, port)`` for every edge that has a live bridge, where
    ``(host, port)`` is the agent-reachable endpoint of that edge's least-loaded
    bridge (resolved per the agent's network zone, exactly as a real relay/tunnel
    dial would be). The agent TCP-times each and reports it as ``edge_rtts`` on
    its next heartbeat.

    This decouples the agent-leg measurement from web-app relays: before, an
    RTT only existed for edges the agent happened to hold a relay to, so
    SSH/DB/TCP-only and idle agents measured nothing and measured-latency
    selection silently fell back to the default edge. Now every online agent
    measures every reachable edge.
    """
    # Enumerate edges from the registry SET (#280) rather than a per-heartbeat
    # SCAN of the whole keyspace. Each edge is still gated on a live bridge, so a
    # stale registry entry for a drained edge is skipped.
    targets: list[tuple[str, str, int]] = []
    for edge in await r.smembers(edges_registry_key()):
        if not edge:
            continue
        bridges = await r.zrangebyscore(f"bridges:available:{edge}", "-inf", "+inf", start=0, num=1)
        if not bridges:
            continue
        bridge_id = bridges[0]
        info = await r.hgetall(f"bridge:{bridge_id}")
        hostname = info.get("hostname")
        if not hostname:
            continue
        host, port = await resolve_agent_bridge_endpoint(r, agent_id, bridge_id, hostname)
        targets.append((edge, host, port))
    return targets
