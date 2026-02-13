"""Redis-backed resource catalog.

Resources are runtime state reported by agents via heartbeats. The agent
config file is the source of truth; the resource catalog in Redis is a
projection. When an agent goes offline, its resources disappear.

Key patterns:
    resource:{name}          — JSON blob with resource info (reverse index)
    agent:{id}:resources     — JSON list of resource names for this agent
    agent:{id}:labels        — JSON dict of agent labels
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass

import redis.asyncio as aioredis


@dataclass
class ResourceInfo:
    """Resource entry in the Redis catalog.

    This replaces the SQLAlchemy Resource model for all runtime lookups.
    The fields mirror what agents report on heartbeat.
    """

    name: str
    resource_type: str
    labels: dict[str, str]
    agent_id: str
    hostname: str | None = None
    port: int | None = None
    tunnel_hostname: str | None = None


async def get_resource(r: aioredis.Redis, resource_name: str) -> ResourceInfo | None:
    """Look up a resource by name from Redis."""
    data = await r.get(f"resource:{resource_name}")
    if data is None:
        return None
    parsed = json.loads(data)
    return ResourceInfo(**parsed)


async def set_agent_resources(
    r: aioredis.Redis,
    agent_id: str,
    resources: list[ResourceInfo],
    ttl: int,
) -> None:
    """Set resources for an agent (called on heartbeat).

    Updates both the per-resource reverse index keys and the
    agent:{id}:resources set. Old resources not in the new list
    are cleaned up.

    Args:
        r: Redis client.
        agent_id: Agent UUID as string.
        resources: Resources reported by this agent.
        ttl: TTL in seconds (should match agent heartbeat TTL).
    """
    new_names = {res.name for res in resources}

    # Get existing resource names for this agent to clean up stale entries
    existing_raw = await r.get(f"agent:{agent_id}:resources")
    if existing_raw:
        existing_names: set[str] = set(json.loads(existing_raw))
    else:
        existing_names = set()

    # Remove stale resource keys
    stale = existing_names - new_names
    if stale:
        await r.delete(*(f"resource:{name}" for name in stale))

    # Set/refresh resource keys
    pipe = r.pipeline()
    for res in resources:
        pipe.setex(f"resource:{res.name}", ttl, json.dumps(asdict(res)))
    pipe.setex(f"agent:{agent_id}:resources", ttl, json.dumps(sorted(new_names)))
    await pipe.execute()


async def get_agent_resource_count(r: aioredis.Redis, agent_id: str) -> int:
    """Get number of resources for an agent."""
    data = await r.get(f"agent:{agent_id}:resources")
    if data is None:
        return 0
    return len(json.loads(data))


async def get_agent_labels(r: aioredis.Redis, agent_id: str) -> dict[str, str]:
    """Get labels for an agent from Redis."""
    data = await r.get(f"agent:{agent_id}:labels")
    if data is None:
        return {}
    return json.loads(data)


async def get_resource_by_tunnel_hostname(
    r: aioredis.Redis, tunnel_hostname: str
) -> ResourceInfo | None:
    """Look up a resource by its tunnel hostname (reverse index)."""
    resource_name = await r.get(f"tunnel:{tunnel_hostname}")
    if resource_name is None:
        return None
    return await get_resource(r, resource_name)


async def set_tunnel_hostnames(
    r: aioredis.Redis,
    resources: list[ResourceInfo],
    ttl: int,
) -> None:
    """Set tunnel hostname reverse-lookup keys for HTTP resources."""
    pipe = r.pipeline()
    for res in resources:
        if res.tunnel_hostname:
            pipe.setex(f"tunnel:{res.tunnel_hostname}", ttl, res.name)
    await pipe.execute()


async def set_agent_labels(
    r: aioredis.Redis, agent_id: str, labels: dict[str, str], ttl: int
) -> None:
    """Set labels for an agent in Redis."""
    await r.setex(f"agent:{agent_id}:labels", ttl, json.dumps(labels))
