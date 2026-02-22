"""Resources router.

Lists resources reported by agents via heartbeats (stored in Redis).
"""

from __future__ import annotations

import json

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.api.dependencies import get_current_user
from bamf.api.models.common import BAMFBaseModel
from bamf.auth.sessions import Session
from bamf.config import settings
from bamf.db.models import Agent
from bamf.db.session import get_db_read
from bamf.redis.client import get_redis
from bamf.services.rbac_service import check_access
from bamf.services.resource_catalog import ResourceInfo

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
    connect_url: str | None = None


class ResourceListResponse(BAMFBaseModel):
    """Response for the resource list endpoint."""

    resources: list[ResourceResponse] = []


def _build_connect_url(parsed: dict) -> str | None:
    """Build a connect URL for HTTP resources from tunnel_hostname + config."""
    tunnel_hostname = parsed.get("tunnel_hostname")
    if not tunnel_hostname or not settings.tunnel_domain:
        return None
    return f"https://{tunnel_hostname}.{settings.tunnel_domain}"


async def _build_resource(
    parsed: dict,
    agent_names: dict[str, str],
    r: aioredis.Redis,
) -> ResourceResponse:
    """Build a ResourceResponse from parsed Redis data."""
    agent_id = parsed["agent_id"]
    agent_status = await r.get(f"agent:{agent_id}:status")
    return ResourceResponse(
        name=parsed["name"],
        resource_type=parsed["resource_type"],
        labels=parsed.get("labels", {}),
        agent_id=agent_id,
        agent_name=agent_names.get(agent_id),
        status="available" if agent_status else "offline",
        hostname=parsed.get("hostname"),
        port=parsed.get("port"),
        connect_url=_build_connect_url(parsed),
    )


async def _agent_name_lookup(db: AsyncSession) -> dict[str, str]:
    """Build agent_id → name lookup from DB."""
    result = await db.execute(select(Agent.id, Agent.name))
    return {str(row.id): row.name for row in result}


@router.get("", response_model=ResourceListResponse)
async def list_resources(
    current_user: Session = Depends(get_current_user),
    r: aioredis.Redis = Depends(get_redis),
    db: AsyncSession = Depends(get_db_read),
) -> ResourceListResponse:
    """List accessible resources from the Redis catalog.

    Resources are filtered by the user's RBAC roles — users only see
    resources they are allowed to access.
    """
    resources: list[ResourceResponse] = []
    agent_names = await _agent_name_lookup(db)

    async for key in r.scan_iter(match="resource:*", count=100):
        data = await r.get(key)
        if data is None:
            continue
        parsed = json.loads(data)

        # RBAC filter: only include resources the user can access
        info = ResourceInfo(
            name=parsed["name"],
            resource_type=parsed["resource_type"],
            labels=parsed.get("labels", {}),
            agent_id=parsed["agent_id"],
        )
        if not await check_access(db, current_user, info, current_user.roles):
            continue

        resources.append(await _build_resource(parsed, agent_names, r))

    resources.sort(key=lambda r: r.name)
    return ResourceListResponse(resources=resources)


@router.get("/{name}", response_model=ResourceResponse)
async def get_resource_by_name(
    name: str,
    current_user: Session = Depends(get_current_user),
    r: aioredis.Redis = Depends(get_redis),
    db: AsyncSession = Depends(get_db_read),
) -> ResourceResponse:
    """Get a single resource by name from the Redis catalog."""
    data = await r.get(f"resource:{name}")
    if data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Resource '{name}' not found",
        )
    parsed = json.loads(data)

    # RBAC check: user must have access to this resource
    info = ResourceInfo(
        name=parsed["name"],
        resource_type=parsed["resource_type"],
        labels=parsed.get("labels", {}),
        agent_id=parsed["agent_id"],
    )
    if not await check_access(db, current_user, info, current_user.roles):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied",
        )

    agent_names = await _agent_name_lookup(db)
    return await _build_resource(parsed, agent_names, r)
