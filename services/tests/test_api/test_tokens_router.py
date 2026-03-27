"""Tests for join token CRUD endpoints.

Tests /api/v1/tokens endpoints for creating, listing, getting,
and revoking join tokens.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.api.dependencies import require_admin, require_admin_or_audit
from bamf.api.routers.tokens import router
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


@pytest.fixture
def tokens_app(db_session: AsyncSession):
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")

    async def override_get_db():
        yield db_session

    async def override_admin() -> Session:
        return ADMIN_SESSION

    async def override_audit() -> Session:
        return ADMIN_SESSION

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_db_read] = override_get_db
    app.dependency_overrides[require_admin] = override_admin
    app.dependency_overrides[require_admin_or_audit] = override_audit
    return app


@pytest.fixture
async def tokens_client(tokens_app):
    async with AsyncClient(
        transport=ASGITransport(app=tokens_app),
        base_url="http://test",
    ) as client:
        yield client


def _patch_audit_log():
    return patch(
        "bamf.api.routers.tokens.log_audit_event",
        new_callable=AsyncMock,
    )


# ── Tests ─────────────────────────────────────────────────────────────────


class TestCreateToken:
    @pytest.mark.asyncio
    async def test_create_returns_token(self, tokens_client, db_session):
        with _patch_audit_log():
            resp = await tokens_client.post(
                "/api/v1/tokens",
                json={"name": "prod-agents", "expires_in_hours": 24},
            )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "prod-agents"
        assert data["token"].startswith("bamf_")
        assert data["is_revoked"] is False
        assert data["use_count"] == 0

    @pytest.mark.asyncio
    async def test_create_with_max_uses_and_labels(self, tokens_client, db_session):
        with _patch_audit_log():
            resp = await tokens_client.post(
                "/api/v1/tokens",
                json={
                    "name": "labeled-token",
                    "expires_in_hours": 48,
                    "max_uses": 5,
                    "agent_labels": {"env": "prod", "region": "us-east"},
                },
            )
        assert resp.status_code == 201
        data = resp.json()
        assert data["max_uses"] == 5
        assert data["agent_labels"]["env"] == "prod"

    @pytest.mark.asyncio
    async def test_create_duplicate_name_fails(self, tokens_client, db_session):
        with _patch_audit_log():
            await tokens_client.post(
                "/api/v1/tokens",
                json={"name": "dupe-token", "expires_in_hours": 24},
            )
            resp = await tokens_client.post(
                "/api/v1/tokens",
                json={"name": "dupe-token", "expires_in_hours": 24},
            )
        assert resp.status_code == 409


class TestListTokens:
    @pytest.mark.asyncio
    async def test_list_empty(self, tokens_client):
        resp = await tokens_client.get("/api/v1/tokens")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["has_more"] is False

    @pytest.mark.asyncio
    async def test_list_includes_created(self, tokens_client, db_session):
        with _patch_audit_log():
            await tokens_client.post(
                "/api/v1/tokens",
                json={"name": "list-test", "expires_in_hours": 24},
            )
        resp = await tokens_client.get("/api/v1/tokens")
        data = resp.json()
        assert len(data["items"]) >= 1
        names = [t["name"] for t in data["items"]]
        assert "list-test" in names

    @pytest.mark.asyncio
    async def test_list_excludes_revoked_by_default(self, tokens_client, db_session):
        with _patch_audit_log():
            create_resp = await tokens_client.post(
                "/api/v1/tokens",
                json={"name": "revoke-hide-test", "expires_in_hours": 24},
            )
            token_id = create_resp.json()["id"]
            await tokens_client.delete(f"/api/v1/tokens/{token_id}")

        resp = await tokens_client.get("/api/v1/tokens")
        names = [t["name"] for t in resp.json()["items"]]
        assert "revoke-hide-test" not in names

    @pytest.mark.asyncio
    async def test_list_includes_revoked_with_flag(self, tokens_client, db_session):
        with _patch_audit_log():
            create_resp = await tokens_client.post(
                "/api/v1/tokens",
                json={"name": "revoke-show-test", "expires_in_hours": 24},
            )
            token_id = create_resp.json()["id"]
            await tokens_client.delete(f"/api/v1/tokens/{token_id}")

        resp = await tokens_client.get("/api/v1/tokens?include_revoked=true")
        names = [t["name"] for t in resp.json()["items"]]
        assert "revoke-show-test" in names


class TestGetToken:
    @pytest.mark.asyncio
    async def test_get_token(self, tokens_client, db_session):
        with _patch_audit_log():
            create_resp = await tokens_client.post(
                "/api/v1/tokens",
                json={"name": "get-test", "expires_in_hours": 24},
            )
        token_id = create_resp.json()["id"]

        resp = await tokens_client.get(f"/api/v1/tokens/{token_id}")
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "get-test"
        # Secret token should NOT be in the get response
        assert "token" not in data or data.get("token") is None

    @pytest.mark.asyncio
    async def test_get_nonexistent_token(self, tokens_client):
        resp = await tokens_client.get("/api/v1/tokens/00000000-0000-0000-0000-000000000000")
        assert resp.status_code == 404


class TestRevokeToken:
    @pytest.mark.asyncio
    async def test_revoke_by_id(self, tokens_client, db_session):
        with _patch_audit_log():
            create_resp = await tokens_client.post(
                "/api/v1/tokens",
                json={"name": "revoke-by-id", "expires_in_hours": 24},
            )
            token_id = create_resp.json()["id"]
            resp = await tokens_client.delete(f"/api/v1/tokens/{token_id}")
        assert resp.status_code == 200
        assert "revoked" in resp.json()["message"].lower()

    @pytest.mark.asyncio
    async def test_revoke_by_name(self, tokens_client, db_session):
        with _patch_audit_log():
            await tokens_client.post(
                "/api/v1/tokens",
                json={"name": "revoke-by-name", "expires_in_hours": 24},
            )
            resp = await tokens_client.post("/api/v1/tokens/revoke-by-name/revoke")
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_revoke_already_revoked_fails(self, tokens_client, db_session):
        with _patch_audit_log():
            create_resp = await tokens_client.post(
                "/api/v1/tokens",
                json={"name": "double-revoke", "expires_in_hours": 24},
            )
            token_id = create_resp.json()["id"]
            await tokens_client.delete(f"/api/v1/tokens/{token_id}")
            resp = await tokens_client.delete(f"/api/v1/tokens/{token_id}")
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_revoke_nonexistent_fails(self, tokens_client):
        with _patch_audit_log():
            resp = await tokens_client.delete("/api/v1/tokens/00000000-0000-0000-0000-000000000000")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_revoke_by_name_nonexistent_fails(self, tokens_client):
        with _patch_audit_log():
            resp = await tokens_client.post("/api/v1/tokens/no-such-token/revoke")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_revoke_by_name_already_revoked_fails(self, tokens_client, db_session):
        with _patch_audit_log():
            await tokens_client.post(
                "/api/v1/tokens",
                json={"name": "name-double-revoke", "expires_in_hours": 24},
            )
            await tokens_client.post("/api/v1/tokens/name-double-revoke/revoke")
            resp = await tokens_client.post("/api/v1/tokens/name-double-revoke/revoke")
        assert resp.status_code == 400
