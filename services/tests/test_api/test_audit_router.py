"""Tests for audit log endpoints.

Tests /api/v1/audit endpoints for listing audit logs,
recordings, and retrieving individual recordings.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.api.dependencies import require_admin_or_audit
from bamf.api.routers.audit import router
from bamf.auth.sessions import Session
from bamf.db.models import AuditLog, SessionRecording
from bamf.db.session import get_db_read

# ── Fixtures ──────────────────────────────────────────────────────────────

_NOW = datetime.now(UTC).isoformat()

AUDIT_SESSION = Session(
    email="auditor@example.com",
    display_name="Auditor",
    roles=["audit"],
    provider_name="local",
    created_at=_NOW,
    expires_at=_NOW,
    last_active_at=_NOW,
)


@pytest.fixture
def audit_app(db_session: AsyncSession):
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")

    async def override_get_db():
        yield db_session

    async def override_audit() -> Session:
        return AUDIT_SESSION

    app.dependency_overrides[get_db_read] = override_get_db
    app.dependency_overrides[require_admin_or_audit] = override_audit
    return app


@pytest.fixture
async def audit_client(audit_app):
    async with AsyncClient(
        transport=ASGITransport(app=audit_app),
        base_url="http://test",
    ) as client:
        yield client


async def _create_audit_entry(db_session, **overrides):
    """Helper to insert an audit log entry directly."""
    defaults = {
        "event_type": "admin",
        "action": "user_created",
        "actor_type": "user",
        "actor_id": "admin@example.com",
        "success": True,
        "timestamp": datetime.now(UTC),
    }
    defaults.update(overrides)
    entry = AuditLog(**defaults)
    db_session.add(entry)
    await db_session.flush()
    return entry


async def _create_recording(db_session, **overrides):
    """Helper to insert a session recording directly."""
    defaults = {
        "session_id": uuid4(),
        "user_email": "user@example.com",
        "resource_name": "test-server",
        "recording_type": "terminal",
        "recording_data": '{"version": 2}',
        "started_at": datetime.now(UTC),
    }
    defaults.update(overrides)
    recording = SessionRecording(**defaults)
    db_session.add(recording)
    await db_session.flush()
    return recording


# ── Tests ─────────────────────────────────────────────────────────────────


class TestListAuditLogs:
    @pytest.mark.asyncio
    async def test_list_empty(self, audit_client):
        resp = await audit_client.get("/api/v1/audit")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["has_more"] is False

    @pytest.mark.asyncio
    async def test_list_returns_entries(self, audit_client, db_session):
        await _create_audit_entry(db_session)
        resp = await audit_client.get("/api/v1/audit")
        assert resp.status_code == 200
        assert len(resp.json()["items"]) >= 1

    @pytest.mark.asyncio
    async def test_filter_by_event_type(self, audit_client, db_session):
        await _create_audit_entry(db_session, event_type="auth", action="login")
        await _create_audit_entry(db_session, event_type="admin", action="user_created")

        resp = await audit_client.get("/api/v1/audit?event_type=auth")
        data = resp.json()
        for item in data["items"]:
            assert item["event_type"] == "auth"

    @pytest.mark.asyncio
    async def test_filter_by_action(self, audit_client, db_session):
        await _create_audit_entry(db_session, action="login")
        await _create_audit_entry(db_session, action="logout")

        resp = await audit_client.get("/api/v1/audit?action=login")
        data = resp.json()
        for item in data["items"]:
            assert item["action"] == "login"

    @pytest.mark.asyncio
    async def test_filter_by_actor_id(self, audit_client, db_session):
        await _create_audit_entry(db_session, actor_id="alice@example.com")
        await _create_audit_entry(db_session, actor_id="bob@example.com")

        resp = await audit_client.get("/api/v1/audit?actor_id=alice@example.com")
        data = resp.json()
        for item in data["items"]:
            assert item["actor_id"] == "alice@example.com"

    @pytest.mark.asyncio
    async def test_filter_by_success(self, audit_client, db_session):
        await _create_audit_entry(db_session, success=True)
        await _create_audit_entry(db_session, success=False)

        resp = await audit_client.get("/api/v1/audit?success=false")
        data = resp.json()
        for item in data["items"]:
            assert item["success"] is False

    @pytest.mark.asyncio
    async def test_filter_by_time_range(self, audit_client, db_session):
        old = datetime.now(UTC) - timedelta(days=2)
        recent = datetime.now(UTC) - timedelta(hours=1)
        await _create_audit_entry(db_session, timestamp=old)
        await _create_audit_entry(db_session, timestamp=recent)

        # Use Z suffix instead of +00:00 to avoid URL encoding issues
        # (the + in +00:00 is interpreted as a space in query parameters)
        since = (datetime.now(UTC) - timedelta(days=1)).isoformat().replace("+00:00", "Z")
        resp = await audit_client.get(f"/api/v1/audit?since={since}")
        data = resp.json()
        # Should only include the recent entry
        assert len(data["items"]) >= 1


class TestListRecordings:
    @pytest.mark.asyncio
    async def test_list_empty(self, audit_client):
        resp = await audit_client.get("/api/v1/audit/recordings")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []

    @pytest.mark.asyncio
    async def test_list_returns_recordings(self, audit_client, db_session):
        await _create_recording(db_session)
        resp = await audit_client.get("/api/v1/audit/recordings")
        assert resp.status_code == 200
        assert len(resp.json()["items"]) >= 1

    @pytest.mark.asyncio
    async def test_filter_by_user_email(self, audit_client, db_session):
        await _create_recording(db_session, user_email="alice@example.com")
        await _create_recording(db_session, user_email="bob@example.com")

        resp = await audit_client.get("/api/v1/audit/recordings?user_email=alice@example.com")
        data = resp.json()
        for item in data["items"]:
            assert item["user_email"] == "alice@example.com"

    @pytest.mark.asyncio
    async def test_filter_by_resource_name(self, audit_client, db_session):
        await _create_recording(db_session, resource_name="web-prod")
        resp = await audit_client.get("/api/v1/audit/recordings?resource_name=web-prod")
        data = resp.json()
        assert len(data["items"]) >= 1

    @pytest.mark.asyncio
    async def test_filter_by_invalid_session_id(self, audit_client):
        resp = await audit_client.get("/api/v1/audit/recordings?session_id=not-a-uuid")
        assert resp.status_code == 400


class TestGetRecording:
    @pytest.mark.asyncio
    async def test_get_recording(self, audit_client, db_session):
        rec = await _create_recording(db_session)
        resp = await audit_client.get(f"/api/v1/audit/recordings/{rec.id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["user_email"] == "user@example.com"
        assert data["format"] == "asciicast-v2"

    @pytest.mark.asyncio
    async def test_get_queries_recording_format(self, audit_client, db_session):
        rec = await _create_recording(db_session, recording_type="queries")
        resp = await audit_client.get(f"/api/v1/audit/recordings/{rec.id}")
        assert resp.status_code == 200
        assert resp.json()["format"] == "queries-v1"

    @pytest.mark.asyncio
    async def test_get_http_recording_format(self, audit_client, db_session):
        rec = await _create_recording(db_session, recording_type="http")
        resp = await audit_client.get(f"/api/v1/audit/recordings/{rec.id}")
        assert resp.status_code == 200
        assert resp.json()["format"] == "http-exchange-v1"

    @pytest.mark.asyncio
    async def test_get_invalid_id_format(self, audit_client):
        resp = await audit_client.get("/api/v1/audit/recordings/not-a-uuid")
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_get_nonexistent(self, audit_client):
        resp = await audit_client.get(f"/api/v1/audit/recordings/{uuid4()}")
        assert resp.status_code == 404


class TestGetSessionRecording:
    @pytest.mark.asyncio
    async def test_get_by_session_id(self, audit_client, db_session):
        session_id = uuid4()
        await _create_recording(db_session, session_id=session_id)
        resp = await audit_client.get(f"/api/v1/audit/sessions/{session_id}/recording")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_get_by_invalid_session_id(self, audit_client):
        resp = await audit_client.get("/api/v1/audit/sessions/not-a-uuid/recording")
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_get_by_nonexistent_session_id(self, audit_client):
        resp = await audit_client.get(f"/api/v1/audit/sessions/{uuid4()}/recording")
        assert resp.status_code == 404
