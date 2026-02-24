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
import json

import httpx

from bamf.auth.ca import get_ca
from bamf.config import settings
from bamf.logging_config import get_logger

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


async def forward_to_bridge(
    method: str,
    url: str,
    headers: dict[str, str],
    body: bytes,
) -> httpx.Response | None:
    """Forward an HTTP request to the bridge relay endpoint."""
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            return await client.request(
                method=method,
                url=url,
                headers=headers,
                content=body,
            )
    except httpx.ConnectError:
        logger.warning("Bridge connection failed", url=url)
        return None
    except httpx.TimeoutException:
        logger.warning("Bridge request timed out", url=url)
        return None


async def assign_relay_bridge(r, agent_id: str) -> str | None:
    """Assign a bridge for the agent's relay connection.

    Picks the least-loaded bridge from the sorted set and stores
    the assignment in Redis.
    """
    bridges = await r.zrangebyscore("bridges:available", "-inf", "+inf", start=0, num=1)
    if not bridges:
        return None

    bridge_id = bridges[0]

    # Store assignment with agent TTL (refreshed on heartbeat)
    await r.setex(f"agent:{agent_id}:relay_bridge", 180, bridge_id)

    logger.info("Assigned relay bridge", agent_id=agent_id, bridge_id=bridge_id)
    return bridge_id


async def send_relay_connect(r, agent_id: str, bridge_id: str) -> None:
    """Send a relay_connect SSE event to a specific agent instance via Redis pub/sub.

    Selects the best instance (preferring one without an active relay) and
    routes the command to its instance-specific channel.
    """
    from bamf.services.agent_instances import select_agent_instance, set_instance_has_relay

    instance_id = await select_agent_instance(r, agent_id, prefer_no_relay=True)
    if not instance_id:
        logger.warning("No live agent instances for relay_connect", agent_id=agent_id)
        return

    agent_cluster_internal = await r.get(f"agent:{agent_id}:cluster_internal")
    bridge_info = await r.hgetall(f"bridge:{bridge_id}")
    bridge_hostname = bridge_info.get("hostname", bridge_id)

    if agent_cluster_internal:
        bridge_host = f"{bridge_id}.{settings.namespace}.svc.cluster.local"
        bridge_port = settings.bridge_internal_tunnel_port
    else:
        bridge_host = bridge_hostname
        bridge_port = settings.bridge_tunnel_port

    # Include CA cert so the agent can verify the bridge's certificate.
    # The agent may have joined with a previous CA — always send the current one.
    ca = get_ca()

    # Route to the selected instance's channel
    channel = f"agent:{agent_id}:instance:{instance_id}:commands"
    await r.publish(
        channel,
        json.dumps(
            {
                "command": "relay_connect",
                "bridge_host": bridge_host,
                "bridge_port": bridge_port,
                "ca_certificate": ca.ca_cert_pem,
            }
        ),
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
) -> bool:
    """Ensure the agent has an active relay connection to the bridge.

    Uses a Redis lock to prevent duplicate relay_connect commands when
    many concurrent requests arrive for an unconnected agent (e.g. a
    browser loading HTML + CSS + JS + favicon simultaneously).

    Returns True if the relay is believed ready, False on timeout.
    """
    lock_key = f"agent:{agent_id}:relay_connecting"

    # Try to acquire the lock (NX = set-if-not-exists, EX = auto-expire)
    acquired = await r.set(lock_key, "1", nx=True, ex=RELAY_READY_TIMEOUT_SECONDS + 5)

    if acquired:
        # We won the race — send relay_connect and wait for it to establish.
        await send_relay_connect(r, agent_id, relay_bridge)
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


def build_bridge_relay_url(
    relay_bridge: str,
    agent_name: str,
    path: str,
    query: str | None = None,
) -> str:
    """Build the internal bridge relay URL for forwarding requests."""
    headless_svc = settings.bridge_headless_service
    url = (
        f"http://{relay_bridge}.{headless_svc}.{settings.namespace}.svc.cluster.local"
        f":{BRIDGE_INTERNAL_PORT}/relay/{agent_name}{path}"
    )
    if query:
        url += f"?{query}"
    return url


def build_bridge_relay_host(relay_bridge: str) -> str:
    """Return the FQDN of a bridge pod's internal relay endpoint."""
    headless_svc = settings.bridge_headless_service
    return f"{relay_bridge}.{headless_svc}.{settings.namespace}.svc.cluster.local"


async def dial_bridge_relay(
    relay_bridge: str,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open a raw TCP connection to a bridge pod's internal relay port.

    Used for WebSocket upgrade requests where we need a persistent
    bidirectional connection rather than request/response HTTP.
    No TLS needed — bridge:8080 is internal cluster network.
    """
    host = build_bridge_relay_host(relay_bridge)
    return await asyncio.open_connection(host, BRIDGE_INTERNAL_PORT)
