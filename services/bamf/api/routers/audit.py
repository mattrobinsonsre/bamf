"""Audit log router."""

import base64
import uuid as _uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.api.dependencies import require_admin_or_audit
from bamf.api.models.audit import AuditLogEntry, RecordingListEntry, SessionRecordingResponse
from bamf.api.models.common import CursorPage, PaginationParams
from bamf.auth.sessions import Session
from bamf.db.models import AuditLog, SessionRecording
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
    current_user: Session = Depends(require_admin_or_audit),
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
        cursor_id = _uuid.UUID(base64.b64decode(pagination.cursor).decode())
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


@router.get("/recordings", response_model=CursorPage[RecordingListEntry])
async def list_recordings(
    pagination: PaginationParams = Depends(),
    user_email: str | None = Query(default=None),
    resource_name: str | None = Query(default=None),
    recording_type: str | None = Query(default=None),
    session_id: str | None = Query(default=None),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    db: AsyncSession = Depends(get_db_read),
    current_user: Session = Depends(require_admin_or_audit),
) -> CursorPage[RecordingListEntry]:
    """List session recordings with filtering and pagination.

    Returns recording summaries (without recording_data) for browsing.
    Requires admin or audit role.
    """
    query = (
        select(SessionRecording)
        .order_by(SessionRecording.started_at.desc())
        .limit(pagination.limit + 1)
    )

    if user_email:
        query = query.where(SessionRecording.user_email == user_email)
    if resource_name:
        query = query.where(SessionRecording.resource_name == resource_name)
    if recording_type:
        query = query.where(SessionRecording.recording_type == recording_type)
    if session_id:
        try:
            sid = _uuid.UUID(session_id)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid session_id format",
            ) from None
        query = query.where(SessionRecording.session_id == sid)
    if since:
        query = query.where(SessionRecording.started_at >= since)
    if until:
        query = query.where(SessionRecording.started_at <= until)

    # Cursor pagination
    if pagination.cursor:
        cursor_id = _uuid.UUID(base64.b64decode(pagination.cursor).decode())
        cursor_entry = await db.get(SessionRecording, cursor_id)
        if cursor_entry:
            query = query.where(SessionRecording.started_at < cursor_entry.started_at)

    result = await db.execute(query)
    recordings = list(result.scalars().all())

    has_more = len(recordings) > pagination.limit
    if has_more:
        recordings = recordings[: pagination.limit]

    next_cursor = None
    if has_more and recordings:
        next_cursor = base64.b64encode(str(recordings[-1].id).encode()).decode()

    items = [
        RecordingListEntry(
            id=r.id,
            session_id=r.session_id,
            user_email=r.user_email,
            resource_name=r.resource_name,
            recording_type=r.recording_type,
            started_at=r.started_at,
            ended_at=r.ended_at,
        )
        for r in recordings
    ]

    return CursorPage(
        items=items,
        next_cursor=next_cursor,
        has_more=has_more,
    )


@router.get("/recordings/{recording_id}", response_model=SessionRecordingResponse)
async def get_recording(
    recording_id: str,
    db: AsyncSession = Depends(get_db_read),
    current_user: Session = Depends(require_admin_or_audit),
) -> SessionRecordingResponse:
    """Retrieve a session recording by its ID.

    Returns the full recording data for playback.
    Requires admin or audit role.
    """
    try:
        rid = _uuid.UUID(recording_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid recording ID format",
        ) from None

    recording = await db.get(SessionRecording, rid)
    if not recording:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recording not found",
        )

    fmt_map = {"queries": "queries-v1", "http": "http-exchange-v1"}
    fmt = fmt_map.get(recording.recording_type, "asciicast-v2")

    return SessionRecordingResponse(
        id=recording.id,
        session_id=recording.session_id,
        user_email=recording.user_email,
        resource_name=recording.resource_name,
        recording_type=recording.recording_type,
        format=fmt,
        recording_data=recording.recording_data,
        started_at=recording.started_at,
        ended_at=recording.ended_at,
    )


@router.get("/sessions/{session_id}/recording", response_model=SessionRecordingResponse)
async def get_session_recording(
    session_id: str,
    db: AsyncSession = Depends(get_db_read),
    current_user: Session = Depends(require_admin_or_audit),
) -> SessionRecordingResponse:
    """Retrieve a session recording by session ID.

    Returns the recording data for playback.
    Requires admin or audit role.
    """
    try:
        sid = _uuid.UUID(session_id)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid session ID format",
        ) from None

    result = await db.execute(
        select(SessionRecording).where(SessionRecording.session_id == sid).limit(1)
    )
    recording = result.scalar_one_or_none()

    if not recording:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Recording not found",
        )

    fmt_map = {"queries": "queries-v1", "http": "http-exchange-v1"}
    fmt = fmt_map.get(recording.recording_type, "asciicast-v2")

    return SessionRecordingResponse(
        id=recording.id,
        session_id=recording.session_id,
        user_email=recording.user_email,
        resource_name=recording.resource_name,
        recording_type=recording.recording_type,
        format=fmt,
        recording_data=recording.recording_data,
        started_at=recording.started_at,
        ended_at=recording.ended_at,
    )
