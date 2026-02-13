"""Resources router.

Lists resources reported by agents via heartbeats (stored in Redis).
"""

from __future__ import annotations

import json

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.api.dependencies import get_current_user
from bamf.api.models.common import BAMFBaseModel
from bamf.auth.sessions import Session
from bamf.db.models import Agent
from bamf.db.session import get_db_read
from bamf.redis.client import get_redis

router = APIRouter(prefix="/resources", tags=["resources"])


class ResourceResponse(BAMFBaseModel):
    """A resource reported by an agent."""

    name: str
    resource_type: str
    labels: dict[str, str] = {}
    agent_id: str
    agent_name: str | None = None
    status: str = "available"
    hostname: str | None = None
    port: int | None = None


class ResourceListResponse(BAMFBaseModel):
    """Response for the resource list endpoint."""

    resources: list[ResourceResponse] = []


@router.get("", response_model=ResourceListResponse)
async def list_resources(
    current_user: Session = Depends(get_current_user),
    r: aioredis.Redis = Depends(get_redis),
    db: AsyncSession = Depends(get_db_read),
) -> ResourceListResponse:
    """List accessible resources from the Redis catalog."""
    resources: list[ResourceResponse] = []

    # Build agent_id → name lookup from DB
    result = await db.execute(select(Agent.id, Agent.name))
    agent_names: dict[str, str] = {str(row.id): row.name for row in result}

    # Scan for all resource:* keys
    async for key in r.scan_iter(match="resource:*", count=100):
        data = await r.get(key)
        if data is None:
            continue
        parsed = json.loads(data)
        agent_id = parsed["agent_id"]

        # Check agent online status
        agent_status = await r.get(f"agent:{agent_id}:status")
        status = "available" if agent_status else "offline"

        resources.append(
            ResourceResponse(
                name=parsed["name"],
                resource_type=parsed["resource_type"],
                labels=parsed.get("labels", {}),
                agent_id=agent_id,
                agent_name=agent_names.get(agent_id),
                status=status,
                hostname=parsed.get("hostname"),
                port=parsed.get("port"),
            )
        )

    resources.sort(key=lambda r: r.name)
    return ResourceListResponse(resources=resources)
