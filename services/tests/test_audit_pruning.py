"""Tests for audit-log retention pruning (services.audit_service.prune_audit_logs).

Enforces the documented retention window: expired rows are deleted, everything
inside the window is kept, retention_days=0 disables pruning, and the batched
delete loop drains a backlog larger than one batch.
"""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.db.models import AuditLog
from bamf.services.audit_service import prune_audit_logs


async def _add_entry(db: AsyncSession, ts: datetime) -> None:
    db.add(
        AuditLog(
            event_type="admin",
            action="test",
            actor_type="user",
            actor_id="a@example.com",
            details={},
            success=True,
            timestamp=ts,
        )
    )


async def _count(db: AsyncSession) -> int:
    return (await db.execute(select(func.count()).select_from(AuditLog))).scalar_one()


@pytest.mark.asyncio
async def test_prune_removes_only_expired(db_session: AsyncSession):
    now = datetime.now(UTC)
    await _add_entry(db_session, now - timedelta(days=120))  # expired
    await _add_entry(db_session, now - timedelta(days=91))  # expired
    await _add_entry(db_session, now - timedelta(days=10))  # kept
    await _add_entry(db_session, now)  # kept
    await db_session.commit()

    deleted = await prune_audit_logs(db_session, retention_days=90)

    assert deleted == 2
    assert await _count(db_session) == 2


@pytest.mark.asyncio
async def test_prune_disabled_when_retention_zero(db_session: AsyncSession):
    await _add_entry(db_session, datetime.now(UTC) - timedelta(days=1000))
    await db_session.commit()

    deleted = await prune_audit_logs(db_session, retention_days=0)

    assert deleted == 0
    assert await _count(db_session) == 1


@pytest.mark.asyncio
async def test_prune_drains_backlog_larger_than_one_batch(db_session: AsyncSession):
    old = datetime.now(UTC) - timedelta(days=200)
    for _ in range(7):
        await _add_entry(db_session, old)
    await db_session.commit()

    # batch_size=3 forces the loop to iterate (3 + 3 + 1) rather than one delete.
    deleted = await prune_audit_logs(db_session, retention_days=90, batch_size=3)

    assert deleted == 7
    assert await _count(db_session) == 0
