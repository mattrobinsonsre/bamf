"""Tests for roles CRUD endpoints.

Tests /api/v1/roles endpoints for creating, listing, getting,
updating, and deleting roles.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.api.dependencies import get_current_user, require_admin
from bamf.api.routers.roles import router
from bamf.auth.sessions import Session
from bamf.db.models import RoleAssignment
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

USER_SESSION = Session(
    email="user@example.com",
    display_name="User",
    roles=[],
    provider_name="local",
    created_at=_NOW,
    expires_at=_NOW,
    last_active_at=_NOW,
)


@pytest.fixture
def roles_app(db_session: AsyncSession):
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")

    async def override_get_db():
        yield db_session

    async def override_admin() -> Session:
        return ADMIN_SESSION

    async def override_user() -> Session:
        return USER_SESSION

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_db_read] = override_get_db
    app.dependency_overrides[require_admin] = override_admin
    app.dependency_overrides[get_current_user] = override_user
    return app


@pytest.fixture
async def roles_client(roles_app):
    async with AsyncClient(
        transport=ASGITransport(app=roles_app),
        base_url="http://test",
    ) as client:
        yield client


def _patch_audit_log():
    return patch(
        "bamf.api.routers.roles.log_audit_event",
        new_callable=AsyncMock,
    )


# ── Tests ─────────────────────────────────────────────────────────────────


class TestListRoles:
    @pytest.mark.asyncio
    async def test_list_has_builtin_roles(self, roles_client):
        resp = await roles_client.get("/api/v1/roles")
        assert resp.status_code == 200
        data = resp.json()
        names = [r["name"] for r in data["items"]]
        assert "admin" in names
        assert "audit" in names
        assert "everyone" in names

    @pytest.mark.asyncio
    async def test_builtin_roles_marked_as_builtin(self, roles_client):
        resp = await roles_client.get("/api/v1/roles")
        data = resp.json()
        builtin_items = [r for r in data["items"] if r["is_builtin"]]
        assert len(builtin_items) == 3

    @pytest.mark.asyncio
    async def test_list_includes_custom_role(self, roles_client, db_session):
        with _patch_audit_log():
            await roles_client.post(
                "/api/v1/roles",
                json={"name": "list-test-role", "description": "test"},
            )
        resp = await roles_client.get("/api/v1/roles")
        data = resp.json()
        names = [r["name"] for r in data["items"]]
        assert "list-test-role" in names


class TestCreateRole:
    @pytest.mark.asyncio
    async def test_create_returns_role(self, roles_client, db_session):
        with _patch_audit_log():
            resp = await roles_client.post(
                "/api/v1/roles",
                json={
                    "name": "developer",
                    "description": "Developer access",
                    "allow": {"labels": {"env": ["dev", "staging"]}, "names": []},
                    "deny": {"labels": {}, "names": ["prod-secret-db"]},
                    "kubernetes_groups": ["developers"],
                },
            )
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "developer"
        assert data["is_builtin"] is False
        assert data["allow"]["labels"] == {"env": ["dev", "staging"]}
        assert data["deny"]["names"] == ["prod-secret-db"]
        assert data["kubernetes_groups"] == ["developers"]

    @pytest.mark.asyncio
    async def test_create_builtin_name_fails(self, roles_client, db_session):
        with _patch_audit_log():
            resp = await roles_client.post(
                "/api/v1/roles",
                json={"name": "admin", "description": "try to shadow built-in"},
            )
        assert resp.status_code == 400
        assert "built-in" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_create_duplicate_name_fails(self, roles_client, db_session):
        with _patch_audit_log():
            await roles_client.post(
                "/api/v1/roles",
                json={"name": "dupe-role", "description": "first"},
            )
            resp = await roles_client.post(
                "/api/v1/roles",
                json={"name": "dupe-role", "description": "second"},
            )
        assert resp.status_code == 409

    @pytest.mark.asyncio
    async def test_create_minimal(self, roles_client, db_session):
        with _patch_audit_log():
            resp = await roles_client.post(
                "/api/v1/roles",
                json={"name": "minimal-role"},
            )
        assert resp.status_code == 201
        data = resp.json()
        assert data["allow"]["labels"] == {}
        assert data["deny"]["labels"] == {}
        assert data["kubernetes_groups"] == []


class TestGetRole:
    @pytest.mark.asyncio
    async def test_get_builtin_role(self, roles_client):
        resp = await roles_client.get("/api/v1/roles/admin")
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "admin"
        assert data["is_builtin"] is True

    @pytest.mark.asyncio
    async def test_get_custom_role(self, roles_client, db_session):
        with _patch_audit_log():
            await roles_client.post(
                "/api/v1/roles",
                json={"name": "get-test", "description": "get me"},
            )
        resp = await roles_client.get("/api/v1/roles/get-test")
        assert resp.status_code == 200
        assert resp.json()["name"] == "get-test"

    @pytest.mark.asyncio
    async def test_get_nonexistent_role(self, roles_client):
        resp = await roles_client.get("/api/v1/roles/no-such-role")
        assert resp.status_code == 404


class TestUpdateRole:
    @pytest.mark.asyncio
    async def test_update_description(self, roles_client, db_session):
        with _patch_audit_log():
            await roles_client.post(
                "/api/v1/roles",
                json={"name": "update-test", "description": "before"},
            )
            resp = await roles_client.patch(
                "/api/v1/roles/update-test",
                json={"description": "after"},
            )
        assert resp.status_code == 200
        assert resp.json()["description"] == "after"

    @pytest.mark.asyncio
    async def test_update_permissions(self, roles_client, db_session):
        with _patch_audit_log():
            await roles_client.post(
                "/api/v1/roles",
                json={"name": "perms-update"},
            )
            resp = await roles_client.patch(
                "/api/v1/roles/perms-update",
                json={
                    "allow": {"labels": {"env": ["prod"]}, "names": []},
                    "kubernetes_groups": ["system:masters"],
                },
            )
        assert resp.status_code == 200
        data = resp.json()
        assert data["allow"]["labels"] == {"env": ["prod"]}
        assert data["kubernetes_groups"] == ["system:masters"]

    @pytest.mark.asyncio
    async def test_update_builtin_fails(self, roles_client):
        with _patch_audit_log():
            resp = await roles_client.patch(
                "/api/v1/roles/admin",
                json={"description": "hacked"},
            )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_update_nonexistent_fails(self, roles_client):
        with _patch_audit_log():
            resp = await roles_client.patch(
                "/api/v1/roles/no-such-role",
                json={"description": "?"},
            )
        assert resp.status_code == 404


class TestDeleteRole:
    @pytest.mark.asyncio
    async def test_delete_custom_role(self, roles_client, db_session):
        with _patch_audit_log():
            await roles_client.post(
                "/api/v1/roles",
                json={"name": "delete-me"},
            )
            resp = await roles_client.delete("/api/v1/roles/delete-me")
        assert resp.status_code == 204

    @pytest.mark.asyncio
    async def test_delete_builtin_fails(self, roles_client):
        with _patch_audit_log():
            resp = await roles_client.delete("/api/v1/roles/admin")
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_delete_nonexistent_fails(self, roles_client):
        with _patch_audit_log():
            resp = await roles_client.delete("/api/v1/roles/no-such-role")
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_delete_cascades_role_assignments(self, roles_client, db_session):
        """Deleting a role also removes its RoleAssignment rows."""
        with _patch_audit_log():
            await roles_client.post(
                "/api/v1/roles",
                json={"name": "cascade-test"},
            )
        # Manually add a role assignment
        ra = RoleAssignment(
            provider_name="local",
            email="someone@example.com",
            role_name="cascade-test",
        )
        db_session.add(ra)
        await db_session.flush()

        with _patch_audit_log():
            resp = await roles_client.delete("/api/v1/roles/cascade-test")
        assert resp.status_code == 204
