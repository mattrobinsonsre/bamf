"""Agent instance management for multi-replica support.

Each agent pod generates a unique instance UUID on startup. The API tracks
these instances via a Redis hash ``agent:{id}:instances`` and routes commands
(tunnel_request, relay_connect) to specific instances instead of broadcasting.

Go contract:
    - pkg/agent/agent.go — generates instanceID (UUID v4) on startup
    - pkg/agent/api_client.go — sends instance_id in heartbeat, drain, offline
    - pkg/agent/sse.go — connects to instance-specific SSE channel

Redis data model:
    agent:{agent_id}:instances  (HASH)
        {instance_id} → JSON {"last_heartbeat": <unix_ts>, "tunnel_count": 0,
                               "has_relay": false, "status": "active"}

    The hash TTL is refreshed on every heartbeat. Individual instance freshness
    is tracked via the ``last_heartbeat`` field inside each hash entry.
"""

from __future__ import annotations

import json
import time

from bamf.logging_config import get_logger

logger = get_logger(__name__)

# An instance is considered stale if its last heartbeat is older than this.
# 3× the agent heartbeat interval (60s) = 180s.
INSTANCE_STALE_THRESHOLD_SECONDS = 180


async def register_instance(
    r,
    agent_id: str,
    instance_id: str,
    agent_ttl: int,
) -> None:
    """Register or refresh an agent instance in the instances hash."""
    key = f"agent:{agent_id}:instances"
    entry = json.dumps(
        {
            "last_heartbeat": time.time(),
            "tunnel_count": 0,
            "has_relay": False,
            "status": "active",
        }
    )

    # Check if instance already exists to preserve tunnel_count/has_relay
    existing_raw = await r.hget(key, instance_id)
    if existing_raw:
        try:
            existing = json.loads(existing_raw)
            entry = json.dumps(
                {
                    "last_heartbeat": time.time(),
                    "tunnel_count": existing.get("tunnel_count", 0),
                    "has_relay": existing.get("has_relay", False),
                    "status": existing.get("status", "active"),
                }
            )
        except (json.JSONDecodeError, TypeError):
            logger.debug("Failed to parse existing agent instance entry")

    await r.hset(key, instance_id, entry)
    await r.expire(key, agent_ttl)


async def select_agent_instance(
    r,
    agent_id: str,
    *,
    prefer_no_relay: bool = False,
) -> str | None:
    """Pick the best live agent instance for a command.

    Selection strategy:
    - Filter to instances with fresh heartbeats (< 3× heartbeat interval)
    - Skip instances in "draining" status
    - For relay: prefer instance without an active relay (or fewest tunnels)
    - For tunnels: pick instance with fewest active tunnels
    - Returns None if no live instances (caller should raise 502)
    """
    key = f"agent:{agent_id}:instances"
    all_instances = await r.hgetall(key)

    if not all_instances:
        return None

    now = time.time()
    candidates: list[tuple[str, dict]] = []

    for iid, raw in all_instances.items():
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            continue

        # Skip stale instances
        last_hb = data.get("last_heartbeat", 0)
        if now - last_hb > INSTANCE_STALE_THRESHOLD_SECONDS:
            continue

        # Skip draining instances
        if data.get("status") == "draining":
            continue

        candidates.append((iid, data))

    if not candidates:
        return None

    if prefer_no_relay:
        # Prefer instances without an active relay connection
        no_relay = [(iid, d) for iid, d in candidates if not d.get("has_relay", False)]
        if no_relay:
            candidates = no_relay

    # Sort by tunnel count (fewest first)
    candidates.sort(key=lambda x: x[1].get("tunnel_count", 0))
    return candidates[0][0]


async def increment_instance_tunnels(r, agent_id: str, instance_id: str) -> None:
    """Increment active tunnel count for an instance."""
    key = f"agent:{agent_id}:instances"
    raw = await r.hget(key, instance_id)
    if not raw:
        return

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return

    data["tunnel_count"] = data.get("tunnel_count", 0) + 1
    await r.hset(key, instance_id, json.dumps(data))


async def update_instance_tunnel_count(
    r, agent_id: str, instance_id: str, active_tunnels: int
) -> None:
    """Set the tunnel count from agent-reported value (self-correction).

    Called on each heartbeat. The agent knows its true tunnel count from
    its in-memory map. This overwrites the Redis-tracked count, fixing
    any drift from missed tunnel_closed events or Redis key expiry.
    """
    key = f"agent:{agent_id}:instances"
    raw = await r.hget(key, instance_id)
    if not raw:
        return

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return

    data["tunnel_count"] = max(0, active_tunnels)
    await r.hset(key, instance_id, json.dumps(data))


async def decrement_instance_tunnels(r, agent_id: str, instance_id: str) -> None:
    """Decrement active tunnel count for an instance."""
    key = f"agent:{agent_id}:instances"
    raw = await r.hget(key, instance_id)
    if not raw:
        return

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return

    data["tunnel_count"] = max(0, data.get("tunnel_count", 0) - 1)
    await r.hset(key, instance_id, json.dumps(data))


async def set_instance_has_relay(r, agent_id: str, instance_id: str, has_relay: bool) -> None:
    """Update the has_relay flag for an instance."""
    key = f"agent:{agent_id}:instances"
    raw = await r.hget(key, instance_id)
    if not raw:
        return

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return

    data["has_relay"] = has_relay
    await r.hset(key, instance_id, json.dumps(data))


async def drain_instance(r, agent_id: str, instance_id: str) -> None:
    """Mark an instance as draining (shutting down)."""
    key = f"agent:{agent_id}:instances"
    raw = await r.hget(key, instance_id)
    if not raw:
        return

    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return

    data["status"] = "draining"
    await r.hset(key, instance_id, json.dumps(data))

    logger.info(
        "Instance marked as draining",
        agent_id=agent_id,
        instance_id=instance_id,
    )


async def remove_instance(r, agent_id: str, instance_id: str) -> None:
    """Remove an instance from the instances hash."""
    key = f"agent:{agent_id}:instances"
    await r.hdel(key, instance_id)

    logger.info(
        "Instance removed",
        agent_id=agent_id,
        instance_id=instance_id,
    )


async def cleanup_stale_instances(r, agent_id: str) -> int:
    """Remove stale instances from the hash. Returns number removed."""
    key = f"agent:{agent_id}:instances"
    all_instances = await r.hgetall(key)

    if not all_instances:
        return 0

    now = time.time()
    removed = 0

    for iid, raw in all_instances.items():
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            await r.hdel(key, iid)
            removed += 1
            continue

        last_hb = data.get("last_heartbeat", 0)
        if now - last_hb > INSTANCE_STALE_THRESHOLD_SECONDS:
            await r.hdel(key, iid)
            removed += 1
            logger.info(
                "Cleaned up stale instance",
                agent_id=agent_id,
                instance_id=iid,
                last_heartbeat_age=round(now - last_hb),
            )

    return removed
