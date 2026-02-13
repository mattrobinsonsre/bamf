"""Audit logging service."""

from typing import Any

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.db.models import AuditLog

logger = structlog.get_logger(__name__)


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
