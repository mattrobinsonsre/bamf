"""Tests for recordings list and detail endpoints."""

import json
import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.api.dependencies import get_current_session, require_admin_or_audit
from bamf.api.proxy.handler import (
    HTTP_RECORDING_BODY_MAX,
    _capture_body,
    _is_binary_content_type,
)
from bamf.auth.sessions import Session
from bamf.db.models import SessionRecording
from bamf.db.session import get_db_read


@pytest.fixture
def admin_session() -> Session:
    """Create a mock admin session."""
    return Session(
        email="admin@example.com",
        display_name="Admin",
        roles=["admin"],
        provider_name="local",
        created_at=datetime.now(UTC).isoformat(),
        expires_at=datetime.now(UTC).isoformat(),
        last_active_at=datetime.now(UTC).isoformat(),
    )


@pytest.fixture
def admin_app(app: FastAPI, admin_session: Session, db_session: AsyncSession) -> FastAPI:
    """App with admin auth overrides."""

    async def override_session() -> Session:
        return admin_session

    async def override_db_read() -> AsyncGenerator[AsyncSession]:
        yield db_session

    app.dependency_overrides[get_current_session] = override_session
    app.dependency_overrides[require_admin_or_audit] = override_session
    app.dependency_overrides[get_db_read] = override_db_read
    return app


@pytest.fixture
async def admin_async_client(admin_app: FastAPI) -> AsyncGenerator[AsyncClient]:
    """Async test client with admin auth (shares event loop with db_session)."""
    async with AsyncClient(
        transport=ASGITransport(app=admin_app),
        base_url="http://test",
    ) as client:
        yield client


@pytest.fixture
async def sample_recordings(db_session: AsyncSession) -> list[SessionRecording]:
    """Create sample recordings in the database."""
    recordings = [
        SessionRecording(
            id=uuid.uuid4(),
            session_id=uuid.uuid4(),
            user_email="alice@example.com",
            resource_name="web-prod-01",
            recording_data='{"version": 2}\n[0.5, "o", "$ ls\\r\\n"]',
            recording_type="terminal",
            started_at=datetime(2026, 2, 17, 10, 0, 0, tzinfo=UTC),
            ended_at=datetime(2026, 2, 17, 10, 5, 0, tzinfo=UTC),
        ),
        SessionRecording(
            id=uuid.uuid4(),
            session_id=uuid.uuid4(),
            user_email="bob@example.com",
            resource_name="orders-db",
            recording_data='[{"timestamp": "2026-02-17T10:00:00Z", "query": "SELECT 1", "type": "simple"}]',
            recording_type="queries",
            started_at=datetime(2026, 2, 17, 11, 0, 0, tzinfo=UTC),
            ended_at=datetime(2026, 2, 17, 11, 3, 0, tzinfo=UTC),
        ),
    ]
    for r in recordings:
        db_session.add(r)
    await db_session.commit()
    return recordings


async def test_list_recordings_empty(admin_async_client: AsyncClient):
    """Empty database returns empty recordings list."""
    response = await admin_async_client.get("/api/v1/audit/recordings")
    assert response.status_code == 200
    data = response.json()
    assert data["items"] == []
    assert data["has_more"] is False


async def test_list_recordings_with_data(
    admin_async_client: AsyncClient, sample_recordings: list[SessionRecording]
):
    """Returns recordings when data exists."""
    response = await admin_async_client.get("/api/v1/audit/recordings")
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) == 2
    # Newest first.
    assert data["items"][0]["resource_name"] == "orders-db"
    assert data["items"][1]["resource_name"] == "web-prod-01"


async def test_list_recordings_filter_by_type(
    admin_async_client: AsyncClient, sample_recordings: list[SessionRecording]
):
    """Filter by recording_type returns only matching recordings."""
    response = await admin_async_client.get("/api/v1/audit/recordings?recording_type=queries")
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) == 1
    assert data["items"][0]["recording_type"] == "queries"
    assert data["items"][0]["resource_name"] == "orders-db"


async def test_list_recordings_filter_by_user(
    admin_async_client: AsyncClient, sample_recordings: list[SessionRecording]
):
    """Filter by user_email returns only matching recordings."""
    response = await admin_async_client.get("/api/v1/audit/recordings?user_email=alice@example.com")
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) == 1
    assert data["items"][0]["user_email"] == "alice@example.com"


async def test_get_recording_by_id(
    admin_async_client: AsyncClient, sample_recordings: list[SessionRecording]
):
    """Get a recording by its UUID returns full data."""
    rec = sample_recordings[0]
    response = await admin_async_client.get(f"/api/v1/audit/recordings/{rec.id}")
    assert response.status_code == 200
    data = response.json()
    assert data["id"] == str(rec.id)
    assert data["user_email"] == "alice@example.com"
    assert data["recording_type"] == "terminal"
    assert "recording_data" in data
    assert data["recording_data"] == rec.recording_data


async def test_get_recording_not_found(admin_async_client: AsyncClient):
    """Non-existent recording returns 404."""
    fake_id = str(uuid.uuid4())
    response = await admin_async_client.get(f"/api/v1/audit/recordings/{fake_id}")
    assert response.status_code == 404


def test_recordings_require_auth(client: TestClient):
    """Recordings endpoints require authentication."""
    response = client.get("/api/v1/audit/recordings")
    assert response.status_code in (401, 403)


async def test_get_session_recording(
    admin_async_client: AsyncClient, sample_recordings: list[SessionRecording]
):
    """Get a recording by session_id returns full data."""
    rec = sample_recordings[1]
    response = await admin_async_client.get(f"/api/v1/audit/sessions/{rec.session_id}/recording")
    assert response.status_code == 200
    data = response.json()
    assert data["session_id"] == str(rec.session_id)
    assert data["recording_type"] == "queries"
    assert data["format"] == "queries-v1"


# --- HTTP audit recording tests ---


async def test_http_audit_recording_stored(
    admin_async_client: AsyncClient, db_session: AsyncSession
):
    """HTTP recording stored with recording_type='http' is retrievable and has correct format."""
    exchange = {
        "version": 1,
        "request": {
            "method": "GET",
            "path": "/api/dashboards",
            "query": "",
            "headers": {"accept": "application/json"},
            "body": "",
            "body_truncated": False,
        },
        "response": {
            "status": 200,
            "headers": {"content-type": "application/json"},
            "body": '{"ok": true}',
            "body_truncated": False,
        },
        "timing": {"duration_ms": 42},
    }
    rec_id = uuid.uuid4()
    recording = SessionRecording(
        id=rec_id,
        session_id=rec_id,
        user_email="alice@example.com",
        resource_name="grafana",
        recording_data=json.dumps(exchange),
        recording_type="http",
        started_at=datetime(2026, 2, 17, 12, 0, 0, tzinfo=UTC),
        ended_at=datetime(2026, 2, 17, 12, 0, 0, tzinfo=UTC),
    )
    db_session.add(recording)
    await db_session.commit()

    response = await admin_async_client.get(f"/api/v1/audit/recordings/{rec_id}")
    assert response.status_code == 200
    data = response.json()
    assert data["recording_type"] == "http"
    assert data["format"] == "http-exchange-v1"
    parsed = json.loads(data["recording_data"])
    assert parsed["version"] == 1
    assert parsed["request"]["method"] == "GET"
    assert parsed["response"]["status"] == 200


async def test_http_recording_filter_by_type(
    admin_async_client: AsyncClient, db_session: AsyncSession
):
    """Filter recordings list by recording_type=http returns only HTTP recordings."""
    rec_id = uuid.uuid4()
    db_session.add(
        SessionRecording(
            id=rec_id,
            session_id=rec_id,
            user_email="bob@example.com",
            resource_name="jenkins",
            recording_data='{"version":1}',
            recording_type="http",
            started_at=datetime(2026, 2, 17, 13, 0, 0, tzinfo=UTC),
            ended_at=datetime(2026, 2, 17, 13, 0, 0, tzinfo=UTC),
        )
    )
    db_session.add(
        SessionRecording(
            id=uuid.uuid4(),
            session_id=uuid.uuid4(),
            user_email="bob@example.com",
            resource_name="web-prod-01",
            recording_data="header\ndata",
            recording_type="terminal",
            started_at=datetime(2026, 2, 17, 14, 0, 0, tzinfo=UTC),
            ended_at=datetime(2026, 2, 17, 14, 5, 0, tzinfo=UTC),
        )
    )
    await db_session.commit()

    response = await admin_async_client.get("/api/v1/audit/recordings?recording_type=http")
    assert response.status_code == 200
    data = response.json()
    assert len(data["items"]) == 1
    assert data["items"][0]["recording_type"] == "http"
    assert data["items"][0]["resource_name"] == "jenkins"


def test_capture_body_normal_text():
    """Normal text body is captured as-is."""
    result = _capture_body(b'{"key": "value"}', "application/json")
    assert result["body"] == '{"key": "value"}'
    assert result["body_truncated"] is False
    assert "body_size" not in result


def test_capture_body_truncation():
    """Bodies exceeding 256KB are truncated."""
    large_body = b"x" * (HTTP_RECORDING_BODY_MAX + 100)
    result = _capture_body(large_body, "text/plain")
    assert result["body_truncated"] is True
    assert len(result["body"]) == HTTP_RECORDING_BODY_MAX
    assert "body_size" not in result


def test_capture_body_binary():
    """Binary content types store null body with size."""
    result = _capture_body(b"\x89PNG\r\n\x1a\n" + b"\x00" * 1000, "image/png")
    assert result["body"] is None
    assert result["body_size"] == 1008
    assert result["body_truncated"] is False


def test_capture_body_empty():
    """Empty body returns empty string."""
    result = _capture_body(b"", "text/plain")
    assert result["body"] == ""
    assert result["body_truncated"] is False


def test_is_binary_content_type():
    """Binary content type detection works for common types."""
    assert _is_binary_content_type("image/png") is True
    assert _is_binary_content_type("image/jpeg; charset=utf-8") is True
    assert _is_binary_content_type("application/octet-stream") is True
    assert _is_binary_content_type("application/pdf") is True
    assert _is_binary_content_type("video/mp4") is True
    assert _is_binary_content_type("font/woff2") is True
    assert _is_binary_content_type("application/json") is False
    assert _is_binary_content_type("text/html") is False
    assert _is_binary_content_type("text/plain; charset=utf-8") is False
    assert _is_binary_content_type("") is False
