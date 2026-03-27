"""Tests for resources endpoints.

Tests /api/v1/resources endpoints for listing and getting resources.
Resources live in Redis (reported by agents), not in PostgreSQL.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.api.dependencies import get_current_user
from bamf.api.routers.resources import router
from bamf.auth.sessions import Session
from bamf.db.session import get_db_read
from bamf.redis.client import get_redis

# ── Fixtures ──────────────────────────────────────────────────────────────

_NOW = datetime.now(UTC).isoformat()

USER_SESSION = Session(
    email="user@example.com",
    display_name="User",
    roles=["admin"],  # admin so check_access passes
    provider_name="local",
    created_at=_NOW,
    expires_at=_NOW,
    last_active_at=_NOW,
)

SAMPLE_RESOURCE = {
    "name": "web-prod-01",
    "resource_type": "ssh",
    "labels": {"env": "prod", "team": "platform"},
    "agent_id": "agent-uuid-1",
    "hostname": "web-prod-01.internal",
    "port": 22,
}

MANAGED_RESOURCE = {
    "name": "kubamf-sidecar",
    "resource_type": "http",
    "labels": {"managed-by": "bamf"},
    "agent_id": "agent-uuid-1",
}


class FakeRedis:
    """Minimal Redis mock for resource tests."""

    def __init__(self, data: dict[str, str] | None = None):
        self._data = data or {}

    async def get(self, key: str) -> str | None:
        return self._data.get(key)

    async def scan_iter(self, match: str = "*", count: int = 100):
        for key in self._data:
            if key.startswith(match.replace("*", "")):
                yield key


@pytest.fixture
def resources_app(db_session: AsyncSession):
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")

    async def override_get_db():
        yield db_session

    async def override_user() -> Session:
        return USER_SESSION

    redis = FakeRedis(
        {
            "resource:web-prod-01": json.dumps(SAMPLE_RESOURCE),
        }
    )

    app.dependency_overrides[get_db_read] = override_get_db
    app.dependency_overrides[get_current_user] = override_user
    app.dependency_overrides[get_redis] = lambda: redis
    return app


@pytest.fixture
async def resources_client(resources_app):
    async with AsyncClient(
        transport=ASGITransport(app=resources_app),
        base_url="http://test",
    ) as client:
        yield client


# ── Tests ─────────────────────────────────────────────────────────────────


class TestListResources:
    @pytest.mark.asyncio
    async def test_list_returns_resources(self, resources_client):
        with patch(
            "bamf.api.routers.resources.check_access", new_callable=AsyncMock, return_value=True
        ):
            resp = await resources_client.get("/api/v1/resources")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["resources"]) >= 1
        assert data["resources"][0]["name"] == "web-prod-01"

    @pytest.mark.asyncio
    async def test_list_rbac_filters(self, resources_app, db_session):
        """Resources the user can't access are excluded."""
        async with AsyncClient(
            transport=ASGITransport(app=resources_app),
            base_url="http://test",
        ) as client:
            with patch(
                "bamf.api.routers.resources.check_access",
                new_callable=AsyncMock,
                return_value=False,
            ):
                resp = await client.get("/api/v1/resources")
        assert resp.status_code == 200
        assert resp.json()["resources"] == []

    @pytest.mark.asyncio
    async def test_list_hides_managed_by_bamf(self, db_session):
        """Resources with managed-by=bamf label are hidden."""
        app = FastAPI()
        app.include_router(router, prefix="/api/v1")

        async def override_get_db():
            yield db_session

        async def override_user() -> Session:
            return USER_SESSION

        redis = FakeRedis(
            {
                "resource:kubamf-sidecar": json.dumps(MANAGED_RESOURCE),
            }
        )

        app.dependency_overrides[get_db_read] = override_get_db
        app.dependency_overrides[get_current_user] = override_user
        app.dependency_overrides[get_redis] = lambda: redis

        async with AsyncClient(
            transport=ASGITransport(app=app),
            base_url="http://test",
        ) as client:
            with patch(
                "bamf.api.routers.resources.check_access", new_callable=AsyncMock, return_value=True
            ):
                resp = await client.get("/api/v1/resources")
        assert resp.status_code == 200
        assert resp.json()["resources"] == []


class TestGetResource:
    @pytest.mark.asyncio
    async def test_get_existing_resource(self, resources_client):
        with patch(
            "bamf.api.routers.resources.check_access", new_callable=AsyncMock, return_value=True
        ):
            resp = await resources_client.get("/api/v1/resources/web-prod-01")
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "web-prod-01"
        assert data["resource_type"] == "ssh"

    @pytest.mark.asyncio
    async def test_get_nonexistent_resource(self, resources_client):
        resp = await resources_client.get("/api/v1/resources/no-such-resource")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_get_access_denied(self, resources_client):
        with patch(
            "bamf.api.routers.resources.check_access", new_callable=AsyncMock, return_value=False
        ):
            resp = await resources_client.get("/api/v1/resources/web-prod-01")
        assert resp.status_code == 403
