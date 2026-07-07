"""Audit logging service."""

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import structlog
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.db.models import AuditLog

logger = structlog.get_logger(__name__)

# Audit-log retention pruning. The documented contract is a fixed retention
# window (default 90 days); nothing pruned expired rows before, so the window
# was advisory. This loop enforces it. A retention of 0 (or negative) disables
# pruning entirely — audit rows are then kept indefinitely.
_PRUNE_INTERVAL_SECONDS = (
    6 * 3600
)  # sweep every 6h; each sweep is a cheap no-op when nothing expired
_PRUNE_LOCK_KEY = "bamf:audit:prune:lock"
_PRUNE_LOCK_TTL_SECONDS = 1800
_PRUNE_BATCH_SIZE = 5000


async def log_audit_event(
    db: AsyncSession,
    *,
    event_type: str,
    action: str,
    actor_type: str,
    actor_id: str | None = None,
    actor_ip: str | None = None,
    actor_user_agent: str | None = None,
    target_type: str | None = None,
    target_id: str | None = None,
    request_id: str | None = None,
    details: dict[str, Any] | None = None,
    success: bool = True,
    error_message: str | None = None,
) -> AuditLog:
    """
    Log an audit event to the database.

    Args:
        db: Database session
        event_type: Type of event ('auth', 'access', 'admin')
        action: Specific action ('login', 'logout', 'access_granted', etc.)
        actor_type: Type of actor ('user', 'agent', 'system')
        actor_id: Identifier of the actor (email, agent name, etc.)
        actor_ip: IP address of the actor
        actor_user_agent: User agent string
        target_type: Type of target ('user', 'role', 'resource', etc.)
        target_id: Identifier of the target
        request_id: Request correlation ID
        details: Additional event details
        success: Whether the action was successful
        error_message: Error message if action failed

    Returns:
        The created AuditLog entry
    """
    # Get request_id from structlog context if not provided
    if request_id is None:
        ctx = structlog.contextvars.get_contextvars()
        request_id = ctx.get("request_id")

    entry = AuditLog(
        event_type=event_type,
        action=action,
        actor_type=actor_type,
        actor_id=actor_id,
        actor_ip=actor_ip,
        actor_user_agent=actor_user_agent,
        target_type=target_type,
        target_id=target_id,
        request_id=request_id,
        details=details or {},
        success=success,
        error_message=error_message,
    )

    db.add(entry)

    # Also log to structured logger for real-time monitoring
    log_method = logger.info if success else logger.warning
    log_method(
        "audit_event",
        event_type=event_type,
        action=action,
        actor_type=actor_type,
        actor_id=actor_id,
        target_type=target_type,
        target_id=target_id,
        success=success,
        error_message=error_message,
    )

    return entry


async def prune_audit_logs(
    db: AsyncSession,
    retention_days: int,
    *,
    batch_size: int = _PRUNE_BATCH_SIZE,
) -> int:
    """Delete audit_logs older than ``retention_days``; return the count removed.

    Deletes in batches (committing each) so a large backlog never holds a long
    lock on the table. A ``retention_days`` of 0 or less is a no-op (retention
    disabled), so callers can turn pruning off via config without special-casing.
    """
    if retention_days <= 0:
        return 0

    cutoff = datetime.now(UTC) - timedelta(days=retention_days)
    total = 0
    while True:
        expired_ids = select(AuditLog.id).where(AuditLog.timestamp < cutoff).limit(batch_size)
        result = await db.execute(delete(AuditLog).where(AuditLog.id.in_(expired_ids)))
        deleted = result.rowcount or 0
        await db.commit()
        total += deleted
        if deleted < batch_size:
            break
    return total


async def prune_audit_logs_loop(interval_seconds: int = _PRUNE_INTERVAL_SECONDS) -> None:
    """Background task: periodically prune audit_logs past the retention window.

    Multi-replica safe: a Redis ``SET NX`` lock elects one pruner per interval so
    replicas don't all issue the same DELETE. The delete is idempotent regardless,
    so a lost lock or expired holder never corrupts state — at worst a sweep is
    skipped and retried next interval.
    """
    from bamf.config import settings
    from bamf.db.session import async_session_factory
    from bamf.redis.client import get_redis_client

    while True:
        try:
            await asyncio.sleep(interval_seconds)
            retention_days = settings.audit.retention_days
            if retention_days <= 0:
                continue
            acquired = await get_redis_client().set(
                _PRUNE_LOCK_KEY, "1", nx=True, ex=_PRUNE_LOCK_TTL_SECONDS
            )
            if not acquired:
                continue
            async with async_session_factory() as db:
                deleted = await prune_audit_logs(db, retention_days)
            if deleted:
                logger.info(
                    "pruned expired audit logs",
                    deleted=deleted,
                    retention_days=retention_days,
                )
        except asyncio.CancelledError:
            raise
        except Exception:
            # Never let a transient DB/Redis error kill the pruner.
            logger.warning("audit prune iteration failed", exc_info=True)
