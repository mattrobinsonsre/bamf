"""Audit log Pydantic models."""

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import Field

from .common import BAMFBaseModel


class AuditLogEntry(BAMFBaseModel):
    """Audit log entry response."""

    id: UUID
    timestamp: datetime
    event_type: str  # 'auth', 'access', 'admin'
    action: str  # 'login', 'logout', 'access_granted', etc.

    actor_type: str  # 'user', 'agent', 'system'
    actor_id: str | None = None
    actor_ip: str | None = None

    target_type: str | None = None
    target_id: str | None = None

    request_id: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)

    success: bool
    error_message: str | None = None
