"""Tests for outpost token CRUD endpoints.

Tests /api/v1/outpost-tokens endpoints for creating, listing,
revoking, and getting outpost join tokens.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.api.dependencies import require_admin, require_admin_or_audit
from bamf.api.routers.outpost_tokens import router
from bamf.auth.sessions import Session
from bamf.db.session import get_db, get_db_read

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
def outpost_token_app(db_session: AsyncSession):
    """Minimal app with outpost-tokens router and auth overrides."""
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")

    async def override_get_db():
        yield db_session

    async def override_admin() -> Session:
        return ADMIN_SESSION

    async def override_audit() -> Session:
        return AUDIT_SESSION

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_db_read] = override_get_db
    app.dependency_overrides[require_admin] = override_admin
    app.dependency_overrides[require_admin_or_audit] = override_audit
    return app


@pytest.fixture
async def outpost_token_client(outpost_token_app):
    async with AsyncClient(
        transport=ASGITransport(app=outpost_token_app),
        base_url="http://test",
    ) as client:
        yield client


def _patch_audit_log():
    """Patch audit logging to no-op."""
    return patch(
        "bamf.api.routers.outpost_tokens.log_audit_event",
        new_callable=AsyncMock,
    )


# ── Tests ─────────────────────────────────────────────────────────────────


class TestCreateOutpostToken:
    @pytest.mark.asyncio
    async def test_create_returns_token(self, outpost_token_client, db_session):
        with _patch_audit_log():
            resp = await outpost_token_client.post(
                "/api/v1/outpost-tokens",
                json={
                    "name": "eu-prod",
                    "outpost_name": "eu",
                    "expires_in_hours": 24,
                },
            )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "eu-prod"
        assert data["outpost_name"] == "eu"
        assert data["token"].startswith("bamf_out_")
        assert data["is_revoked"] is False
        assert data["use_count"] == 0

    @pytest.mark.asyncio
    async def test_create_with_region_and_max_uses(self, outpost_token_client, db_session):
        with _patch_audit_log():
            resp = await outpost_token_client.post(
                "/api/v1/outpost-tokens",
                json={
                    "name": "apac-token",
                    "outpost_name": "apac",
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
    async def test_create_duplicate_name_fails(self, outpost_token_client, db_session):
        with _patch_audit_log():
            await outpost_token_client.post(
                "/api/v1/outpost-tokens",
                json={
                    "name": "dupe-test",
                    "outpost_name": "eu",
                    "expires_in_hours": 24,
                },
            )
            resp = await outpost_token_client.post(
                "/api/v1/outpost-tokens",
                json={
                    "name": "dupe-test",
                    "outpost_name": "us",
                    "expires_in_hours": 24,
                },
            )
        assert resp.status_code == 409


class TestListOutpostTokens:
    @pytest.mark.asyncio
    async def test_list_empty(self, outpost_token_client):
        resp = await outpost_token_client.get("/api/v1/outpost-tokens")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["has_more"] is False

    @pytest.mark.asyncio
    async def test_list_includes_created_token(self, outpost_token_client, db_session):
        with _patch_audit_log():
            await outpost_token_client.post(
                "/api/v1/outpost-tokens",
                json={
                    "name": "list-test",
                    "outpost_name": "eu",
                    "expires_in_hours": 24,
                },
            )
        resp = await outpost_token_client.get("/api/v1/outpost-tokens")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) >= 1
        names = [t["name"] for t in data["items"]]
        assert "list-test" in names


class TestRevokeOutpostToken:
    @pytest.mark.asyncio
    async def test_revoke_by_id(self, outpost_token_client, db_session):
        with _patch_audit_log():
            create_resp = await outpost_token_client.post(
                "/api/v1/outpost-tokens",
                json={
                    "name": "revoke-test",
                    "outpost_name": "eu",
                    "expires_in_hours": 24,
                },
            )
        token_id = create_resp.json()["id"]

        with _patch_audit_log():
            resp = await outpost_token_client.delete(f"/api/v1/outpost-tokens/{token_id}")
        assert resp.status_code == 200
        assert "revoked" in resp.json()["message"].lower()

    @pytest.mark.asyncio
    async def test_revoke_by_name(self, outpost_token_client, db_session):
        with _patch_audit_log():
            await outpost_token_client.post(
                "/api/v1/outpost-tokens",
                json={
                    "name": "revoke-name-test",
                    "outpost_name": "eu",
                    "expires_in_hours": 24,
                },
            )
            resp = await outpost_token_client.post("/api/v1/outpost-tokens/revoke-name-test/revoke")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_revoke_already_revoked_fails(self, outpost_token_client, db_session):
        with _patch_audit_log():
            create_resp = await outpost_token_client.post(
                "/api/v1/outpost-tokens",
                json={
                    "name": "double-revoke",
                    "outpost_name": "eu",
                    "expires_in_hours": 24,
                },
            )
            token_id = create_resp.json()["id"]
            await outpost_token_client.delete(f"/api/v1/outpost-tokens/{token_id}")
            resp = await outpost_token_client.delete(f"/api/v1/outpost-tokens/{token_id}")
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_revoke_nonexistent_fails(self, outpost_token_client):
        with _patch_audit_log():
            resp = await outpost_token_client.delete(
                "/api/v1/outpost-tokens/00000000-0000-0000-0000-000000000000"
            )
        assert resp.status_code == 404
