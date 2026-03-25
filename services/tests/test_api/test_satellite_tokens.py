"""Tests for satellite token CRUD endpoints.

Tests /api/v1/satellite-tokens endpoints for creating, listing,
revoking, and getting satellite join tokens.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.api.routers.satellite_tokens import router
from bamf.auth.sessions import Session
from bamf.db.session import get_db

# ── Fixtures ──────────────────────────────────────────────────────────────

_NOW = datetime.now(UTC).isoformat()

ADMIN_SESSION = Session(
    email="admin@example.com",
    display_name="Admin",
    roles=["admin"],
    provider_name="local",
    created_at=_NOW,
    expires_at=_NOW,
    last_active_at=_NOW,
)

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
def sat_token_app(db_session: AsyncSession):
    """Minimal app with satellite-tokens router."""
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    return app


@pytest.fixture
async def sat_token_client(sat_token_app):
    async with AsyncClient(
        transport=ASGITransport(app=sat_token_app),
        base_url="http://test",
    ) as client:
        yield client


def _patch_admin():
    """Patch require_admin to return ADMIN_SESSION."""
    return patch(
        "bamf.api.routers.satellite_tokens.require_admin",
        return_value=ADMIN_SESSION,
    )


def _patch_audit():
    """Patch require_admin_or_audit to return AUDIT_SESSION."""
    return patch(
        "bamf.api.routers.satellite_tokens.require_admin_or_audit",
        return_value=AUDIT_SESSION,
    )


def _patch_audit_log():
    """Patch audit logging to no-op."""
    return patch(
        "bamf.api.routers.satellite_tokens.log_audit_event",
        new_callable=AsyncMock,
    )


# ── Tests ─────────────────────────────────────────────────────────────────


class TestCreateSatelliteToken:
    @pytest.mark.asyncio
    async def test_create_returns_token(self, sat_token_client, db_session):
        with _patch_admin(), _patch_audit_log():
            resp = await sat_token_client.post(
                "/api/v1/satellite-tokens",
                json={
                    "name": "eu-prod",
                    "satellite_name": "eu",
                    "expires_in_hours": 24,
                },
            )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "eu-prod"
        assert data["satellite_name"] == "eu"
        assert data["token"].startswith("bamf_sat_")
        assert data["is_revoked"] is False
        assert data["use_count"] == 0

    @pytest.mark.asyncio
    async def test_create_with_region_and_max_uses(self, sat_token_client, db_session):
        with _patch_admin(), _patch_audit_log():
            resp = await sat_token_client.post(
                "/api/v1/satellite-tokens",
                json={
                    "name": "apac-token",
                    "satellite_name": "apac",
                    "region": "Asia Pacific (Tokyo)",
                    "expires_in_hours": 48,
                    "max_uses": 3,
                },
            )
        assert resp.status_code == 201
        data = resp.json()
        assert data["region"] == "Asia Pacific (Tokyo)"
        assert data["max_uses"] == 3

    @pytest.mark.asyncio
    async def test_create_duplicate_name_fails(self, sat_token_client, db_session):
        with _patch_admin(), _patch_audit_log():
            await sat_token_client.post(
                "/api/v1/satellite-tokens",
                json={
                    "name": "dupe-test",
                    "satellite_name": "eu",
                    "expires_in_hours": 24,
                },
            )
            resp = await sat_token_client.post(
                "/api/v1/satellite-tokens",
                json={
                    "name": "dupe-test",
                    "satellite_name": "us",
                    "expires_in_hours": 24,
                },
            )
        assert resp.status_code == 409


class TestListSatelliteTokens:
    @pytest.mark.asyncio
    async def test_list_empty(self, sat_token_client):
        with _patch_audit():
            resp = await sat_token_client.get("/api/v1/satellite-tokens")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["has_more"] is False

    @pytest.mark.asyncio
    async def test_list_includes_created_token(self, sat_token_client, db_session):
        with _patch_admin(), _patch_audit_log():
            await sat_token_client.post(
                "/api/v1/satellite-tokens",
                json={
                    "name": "list-test",
                    "satellite_name": "eu",
                    "expires_in_hours": 24,
                },
            )
        with _patch_audit():
            resp = await sat_token_client.get("/api/v1/satellite-tokens")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) >= 1
        names = [t["name"] for t in data["items"]]
        assert "list-test" in names


class TestRevokeSatelliteToken:
    @pytest.mark.asyncio
    async def test_revoke_by_id(self, sat_token_client, db_session):
        with _patch_admin(), _patch_audit_log():
            create_resp = await sat_token_client.post(
                "/api/v1/satellite-tokens",
                json={
                    "name": "revoke-test",
                    "satellite_name": "eu",
                    "expires_in_hours": 24,
                },
            )
        token_id = create_resp.json()["id"]

        with _patch_admin(), _patch_audit_log():
            resp = await sat_token_client.delete(f"/api/v1/satellite-tokens/{token_id}")
        assert resp.status_code == 200
        assert "revoked" in resp.json()["message"].lower()

    @pytest.mark.asyncio
    async def test_revoke_by_name(self, sat_token_client, db_session):
        with _patch_admin(), _patch_audit_log():
            await sat_token_client.post(
                "/api/v1/satellite-tokens",
                json={
                    "name": "revoke-name-test",
                    "satellite_name": "eu",
                    "expires_in_hours": 24,
                },
            )
            resp = await sat_token_client.post("/api/v1/satellite-tokens/revoke-name-test/revoke")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_revoke_already_revoked_fails(self, sat_token_client, db_session):
        with _patch_admin(), _patch_audit_log():
            create_resp = await sat_token_client.post(
                "/api/v1/satellite-tokens",
                json={
                    "name": "double-revoke",
                    "satellite_name": "eu",
                    "expires_in_hours": 24,
                },
            )
            token_id = create_resp.json()["id"]
            await sat_token_client.delete(f"/api/v1/satellite-tokens/{token_id}")
            resp = await sat_token_client.delete(f"/api/v1/satellite-tokens/{token_id}")
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_revoke_nonexistent_fails(self, sat_token_client):
        with _patch_admin(), _patch_audit_log():
            resp = await sat_token_client.delete(
                "/api/v1/satellite-tokens/00000000-0000-0000-0000-000000000000"
            )
        assert resp.status_code == 404
