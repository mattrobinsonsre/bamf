"""Active tunnels dashboard endpoint.

Provides visibility into live tunnel sessions by reading from the
`sessions:active` Redis Set and resolving individual session data.
Stale entries (sessions that expired via TTL without explicit close)
are lazily cleaned up on read.
"""

import json
import time
from collections import Counter
from datetime import UTC, datetime

import redis.asyncio as aioredis
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.api.dependencies import get_current_user, require_admin_or_audit
from bamf.api.models.common import SuccessResponse
from bamf.api.models.tunnels import ActiveTunnel, ActiveTunnelsResponse
from bamf.auth.sessions import Session
from bamf.db.session import get_db
from bamf.logging_config import get_logger
from bamf.redis.client import get_redis
from bamf.services.audit_service import log_audit_event

router = APIRouter(prefix="/tunnels", tags=["tunnels"])
logger = get_logger(__name__)


@router.get("/active", response_model=ActiveTunnelsResponse)
async def list_active_tunnels(
    r: aioredis.Redis = Depends(get_redis),
    _current_user: Session = Depends(require_admin_or_audit),
) -> ActiveTunnelsResponse:
    """List all active tunnel sessions with summary statistics.

    Reads the `sessions:active` Redis Set, resolves each session's data,
    and lazily removes stale entries whose session keys have expired.
    """
    # 1. Get all tracked session IDs
    session_ids: set[str] = await r.smembers("sessions:active")
    if not session_ids:
        return ActiveTunnelsResponse(
            tunnels=[],
            total=0,
            by_user={},
            by_resource={},
            by_bridge={},
            by_protocol={},
        )

    # 2. Pipeline MGET for all session keys
    session_keys = [f"session:{sid}" for sid in session_ids]
    raw_values = await r.mget(*session_keys)

    # 3. Parse results, collect stale IDs
    tunnels: list[ActiveTunnel] = []
    stale_ids: list[str] = []
    now = time.time()

    for sid, raw in zip(session_ids, raw_values, strict=True):
        if raw is None:
            stale_ids.append(sid)
            continue

        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            stale_ids.append(sid)
            continue

        established_at_ts = data.get("established_at")
        established_at = None
        duration_seconds = None
        if established_at_ts is not None:
            established_at = datetime.fromtimestamp(float(established_at_ts), tz=UTC)
            duration_seconds = round(now - float(established_at_ts), 1)

        created_at_str = data.get("created_at", "")
        try:
            created_at = datetime.fromisoformat(created_at_str)
        except (ValueError, TypeError):
            created_at = datetime.now(UTC)

        tunnels.append(
            ActiveTunnel(
                session_id=sid,
                user_email=data.get("user_email", "unknown"),
                resource_name=data.get("resource_name", "unknown"),
                protocol=data.get("protocol", "unknown"),
                bridge_id=data.get("bridge_id", "unknown"),
                status=data.get("status", "pending"),
                created_at=created_at,
                established_at=established_at,
                duration_seconds=duration_seconds,
            )
        )

    # 4. Lazy cleanup of stale entries
    if stale_ids:
        await r.srem("sessions:active", *stale_ids)
        logger.debug("Cleaned stale session IDs from active set", count=len(stale_ids))

    # 5. Compute summary counters
    by_user: Counter[str] = Counter()
    by_resource: Counter[str] = Counter()
    by_bridge: Counter[str] = Counter()
    by_protocol: Counter[str] = Counter()

    for t in tunnels:
        by_user[t.user_email] += 1
        by_resource[t.resource_name] += 1
        by_bridge[t.bridge_id] += 1
        by_protocol[t.protocol] += 1

    # 6. Sort by created_at descending (newest first)
    tunnels.sort(key=lambda t: t.created_at, reverse=True)

    return ActiveTunnelsResponse(
        tunnels=tunnels,
        total=len(tunnels),
        by_user=dict(by_user),
        by_resource=dict(by_resource),
        by_bridge=dict(by_bridge),
        by_protocol=dict(by_protocol),
    )


@router.delete("/{session_id}", response_model=SuccessResponse)
async def terminate_tunnel(
    session_id: str,
    r: aioredis.Redis = Depends(get_redis),
    db: AsyncSession = Depends(get_db),
    current_user: Session = Depends(get_current_user),
) -> SuccessResponse:
    """Terminate an active tunnel session.

    Users can terminate their own tunnels. Admins can terminate any tunnel.
    """
    session_key = f"session:{session_id}"
    raw = await r.get(session_key)
    if not raw:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Tunnel session not found",
        )

    session_data = json.loads(raw)
    owner_email = session_data.get("user_email")
    is_admin = "admin" in current_user.roles

    # Permission check: own tunnel or admin
    if owner_email != current_user.email and not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only terminate your own tunnels",
        )

    resource_name = session_data.get("resource_name")
    protocol = session_data.get("protocol")
    bridge_id = session_data.get("bridge_id")

    # Clean up Redis state
    await r.delete(session_key)
    await r.srem("sessions:active", session_id)
    await r.delete(f"session:{session_id}:client_creds")

    # Audit log
    await log_audit_event(
        db,
        event_type="access",
        action="session_terminated",
        actor_type="user",
        actor_id=current_user.email,
        target_type="resource",
        target_id=resource_name,
        details={
            "session_id": session_id,
            "protocol": protocol,
            "bridge_id": bridge_id,
            "owner_email": owner_email,
            "terminated_by": current_user.email,
        },
        success=True,
    )
    await db.commit()

    logger.info(
        "Tunnel terminated",
        session_id=session_id,
        resource_name=resource_name,
        owner_email=owner_email,
        terminated_by=current_user.email,
    )

    return SuccessResponse(message="Tunnel terminated")
