"""Audit log router."""

from datetime import datetime

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.api.dependencies import get_current_user
from bamf.api.models.audit import AuditLogEntry
from bamf.api.models.common import CursorPage, PaginationParams
from bamf.auth.sessions import Session
from bamf.db.models import AuditLog
from bamf.db.session import get_db_read
from bamf.logging_config import get_logger

router = APIRouter(prefix="/audit", tags=["audit"])
logger = get_logger(__name__)


@router.get("", response_model=CursorPage[AuditLogEntry])
async def list_audit_logs(
    pagination: PaginationParams = Depends(),
    event_type: str | None = Query(default=None),
    action: str | None = Query(default=None),
    actor_id: str | None = Query(default=None),
    target_type: str | None = Query(default=None),
    target_id: str | None = Query(default=None),
    success: bool | None = Query(default=None),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    db: AsyncSession = Depends(get_db_read),
    current_user: Session = Depends(get_current_user),
) -> CursorPage[AuditLogEntry]:
    """
    List audit log entries with filtering and pagination.

    Supports filtering by event type, action, actor, target, success status, and time range.
    Results are ordered by timestamp descending (newest first).
    """
    query = select(AuditLog).order_by(AuditLog.timestamp.desc()).limit(pagination.limit + 1)

    # Apply filters
    if event_type:
        query = query.where(AuditLog.event_type == event_type)
    if action:
        query = query.where(AuditLog.action == action)
    if actor_id:
        query = query.where(AuditLog.actor_id == actor_id)
    if target_type:
        query = query.where(AuditLog.target_type == target_type)
    if target_id:
        query = query.where(AuditLog.target_id == target_id)
    if success is not None:
        query = query.where(AuditLog.success == success)
    if since:
        query = query.where(AuditLog.timestamp >= since)
    if until:
        query = query.where(AuditLog.timestamp <= until)

    # Cursor pagination
    if pagination.cursor:
        import base64
        from uuid import UUID

        cursor_id = UUID(base64.b64decode(pagination.cursor).decode())
        cursor_entry = await db.get(AuditLog, cursor_id)
        if cursor_entry:
            query = query.where(AuditLog.timestamp < cursor_entry.timestamp)

    result = await db.execute(query)
    entries = list(result.scalars().all())

    has_more = len(entries) > pagination.limit
    if has_more:
        entries = entries[: pagination.limit]

    next_cursor = None
    if has_more and entries:
        import base64

        next_cursor = base64.b64encode(str(entries[-1].id).encode()).decode()

    items = [
        AuditLogEntry(
            id=e.id,
            timestamp=e.timestamp,
            event_type=e.event_type,
            action=e.action,
            actor_type=e.actor_type,
            actor_id=e.actor_id,
            actor_ip=e.actor_ip,
            target_type=e.target_type,
            target_id=e.target_id,
            request_id=e.request_id,
            details=e.details,
            success=e.success,
            error_message=e.error_message,
        )
        for e in entries
    ]

    return CursorPage(
        items=items,
        next_cursor=next_cursor,
        has_more=has_more,
    )
