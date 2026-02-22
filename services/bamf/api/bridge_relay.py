"""Shared bridge relay helpers for HTTP proxy and Kubernetes proxy.

Provides common functions for forwarding requests through bridge relay
connections to agents: bridge selection, relay_connect SSE signaling,
and HTTP forwarding.
"""

from __future__ import annotations

import json

import httpx

from bamf.auth.ca import get_ca
from bamf.config import settings
from bamf.logging_config import get_logger

logger = get_logger(__name__)

# Bridge internal health/relay port
BRIDGE_INTERNAL_PORT = 8080

# How long to wait for a relay connection to establish after sending relay_connect
RELAY_CONNECT_WAIT_SECONDS = 5


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
    """Send a relay_connect SSE event to the agent via Redis pub/sub."""
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

    await r.publish(
        f"agent:{agent_id}:commands",
        json.dumps(
            {
                "command": "relay_connect",
                "bridge_host": bridge_host,
                "bridge_port": bridge_port,
                "ca_certificate": ca.ca_cert_pem,
            }
        ),
    )

    logger.info(
        "Sent relay_connect to agent",
        agent_id=agent_id,
        bridge_host=bridge_host,
        bridge_port=bridge_port,
    )


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
