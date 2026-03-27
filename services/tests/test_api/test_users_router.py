"""Tests for users CRUD endpoints.

Tests /api/v1/users endpoints for creating, listing, getting,
updating, and deleting users.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.api.dependencies import get_current_user, require_admin, require_admin_or_audit
from bamf.api.routers.users import router
from bamf.auth.sessions import Session
from bamf.db.models import Role
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
def users_app(db_session: AsyncSession):
    """Minimal app with users router and auth overrides."""
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")

    async def override_get_db():
        yield db_session

    async def override_admin() -> Session:
        return ADMIN_SESSION

    async def override_user() -> Session:
        return USER_SESSION

    async def override_audit() -> Session:
        return ADMIN_SESSION

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_db_read] = override_get_db
    app.dependency_overrides[require_admin] = override_admin
    app.dependency_overrides[get_current_user] = override_user
    app.dependency_overrides[require_admin_or_audit] = override_audit
    return app


@pytest.fixture
async def users_client(users_app):
    async with AsyncClient(
        transport=ASGITransport(app=users_app),
        base_url="http://test",
    ) as client:
        yield client


def _patch_audit_log():
    return patch(
        "bamf.api.routers.users.log_audit_event",
        new_callable=AsyncMock,
    )


def _patch_recent_users(users=None):
    return patch(
        "bamf.api.routers.users.list_recent_users",
        new_callable=AsyncMock,
        return_value=users or [],
    )


# ── Tests ─────────────────────────────────────────────────────────────────


class TestListUsers:
    @pytest.mark.asyncio
    async def test_list_empty(self, users_client):
        resp = await users_client.get("/api/v1/users")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["has_more"] is False

    @pytest.mark.asyncio
    async def test_list_includes_created_user(self, users_client, db_session):
        with _patch_audit_log():
            await users_client.post(
                "/api/v1/users",
                json={
                    "email": "list-test@example.com",
                    "password": "StrongP@ss123!",
                },
            )
        resp = await users_client.get("/api/v1/users")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data["items"]) >= 1
        emails = [u["email"] for u in data["items"]]
        assert "list-test@example.com" in emails


class TestCreateUser:
    @pytest.mark.asyncio
    async def test_create_returns_user(self, users_client, db_session):
        with _patch_audit_log():
            resp = await users_client.post(
                "/api/v1/users",
                json={
                    "email": "newuser@example.com",
                    "password": "StrongP@ss123!",
                },
            )
        assert resp.status_code == 201
        data = resp.json()
        assert data["email"] == "newuser@example.com"
        assert data["is_active"] is True
        assert data["roles"] == []

    @pytest.mark.asyncio
    async def test_create_duplicate_email_fails(self, users_client, db_session):
        with _patch_audit_log():
            await users_client.post(
                "/api/v1/users",
                json={"email": "dupe@example.com", "password": "StrongP@ss123!"},
            )
            resp = await users_client.post(
                "/api/v1/users",
                json={"email": "dupe@example.com", "password": "StrongP@ss123!"},
            )
        assert resp.status_code == 409

    @pytest.mark.asyncio
    async def test_create_with_everyone_role_fails(self, users_client, db_session):
        with _patch_audit_log():
            resp = await users_client.post(
                "/api/v1/users",
                json={
                    "email": "everyone@example.com",
                    "password": "StrongP@ss123!",
                    "roles": ["everyone"],
                },
            )
        assert resp.status_code == 400
        assert "everyone" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_create_with_nonexistent_role_fails(self, users_client, db_session):
        with _patch_audit_log():
            resp = await users_client.post(
                "/api/v1/users",
                json={
                    "email": "norole@example.com",
                    "password": "StrongP@ss123!",
                    "roles": ["nonexistent-role"],
                },
            )
        assert resp.status_code == 400
        assert "not found" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_create_with_platform_role(self, users_client, db_session):
        """Platform roles (admin, audit) go to PlatformRoleAssignment table."""
        with _patch_audit_log():
            resp = await users_client.post(
                "/api/v1/users",
                json={
                    "email": "platformrole@example.com",
                    "password": "StrongP@ss123!",
                    "roles": ["admin"],
                },
            )
        assert resp.status_code == 201
        data = resp.json()
        assert len(data["roles"]) == 1
        assert data["roles"][0]["name"] == "admin"

    @pytest.mark.asyncio
    async def test_create_with_custom_role(self, users_client, db_session):
        """Custom roles go to RoleAssignment table (need Role row first)."""
        role = Role(
            name="developer",
            description="Dev role",
            allow_labels={"env": ["dev"]},
            allow_names=[],
            deny_labels={},
            deny_names=[],
            kubernetes_groups=[],
        )
        db_session.add(role)
        await db_session.flush()

        with _patch_audit_log():
            resp = await users_client.post(
                "/api/v1/users",
                json={
                    "email": "devrole@example.com",
                    "password": "StrongP@ss123!",
                    "roles": ["developer"],
                },
            )
        assert resp.status_code == 201
        data = resp.json()
        assert len(data["roles"]) == 1
        assert data["roles"][0]["name"] == "developer"

    @pytest.mark.asyncio
    async def test_create_without_password(self, users_client, db_session):
        """SSO-only users can be created without a password."""
        with _patch_audit_log():
            resp = await users_client.post(
                "/api/v1/users",
                json={"email": "sso@example.com"},
            )
        assert resp.status_code == 201
        data = resp.json()
        assert data["email"] == "sso@example.com"


class TestGetUser:
    @pytest.mark.asyncio
    async def test_get_existing_user(self, users_client, db_session):
        with _patch_audit_log():
            await users_client.post(
                "/api/v1/users",
                json={"email": "getme@example.com", "password": "StrongP@ss123!"},
            )
        resp = await users_client.get("/api/v1/users/getme@example.com")
        assert resp.status_code == 200
        assert resp.json()["email"] == "getme@example.com"

    @pytest.mark.asyncio
    async def test_get_nonexistent_user(self, users_client):
        resp = await users_client.get("/api/v1/users/nobody@example.com")
        assert resp.status_code == 404


class TestUpdateUser:
    @pytest.mark.asyncio
    async def test_update_is_active(self, users_client, db_session):
        with _patch_audit_log():
            await users_client.post(
                "/api/v1/users",
                json={"email": "toggle@example.com", "password": "StrongP@ss123!"},
            )
            resp = await users_client.patch(
                "/api/v1/users/toggle@example.com",
                json={"is_active": False},
            )
        assert resp.status_code == 200
        assert resp.json()["is_active"] is False

    @pytest.mark.asyncio
    async def test_update_nonexistent_user(self, users_client):
        with _patch_audit_log():
            resp = await users_client.patch(
                "/api/v1/users/nobody@example.com",
                json={"is_active": False},
            )
        assert resp.status_code == 404

    @pytest.mark.asyncio
    async def test_update_roles_replaces(self, users_client, db_session):
        """Updating roles replaces the existing role assignments."""
        with _patch_audit_log():
            await users_client.post(
                "/api/v1/users",
                json={
                    "email": "roleupdate@example.com",
                    "password": "StrongP@ss123!",
                    "roles": ["admin"],
                },
            )
            resp = await users_client.patch(
                "/api/v1/users/roleupdate@example.com",
                json={"roles": ["audit"]},
            )
        assert resp.status_code == 200
        roles = [r["name"] for r in resp.json()["roles"]]
        assert "audit" in roles
        assert "admin" not in roles

    @pytest.mark.asyncio
    async def test_update_with_everyone_role_fails(self, users_client, db_session):
        with _patch_audit_log():
            await users_client.post(
                "/api/v1/users",
                json={"email": "evr@example.com", "password": "StrongP@ss123!"},
            )
            resp = await users_client.patch(
                "/api/v1/users/evr@example.com",
                json={"roles": ["everyone"]},
            )
        assert resp.status_code == 400


class TestDeleteUser:
    @pytest.mark.asyncio
    async def test_delete_existing_user(self, users_client, db_session):
        with _patch_audit_log():
            await users_client.post(
                "/api/v1/users",
                json={"email": "deleteme@example.com", "password": "StrongP@ss123!"},
            )
            resp = await users_client.delete("/api/v1/users/deleteme@example.com")
        assert resp.status_code == 204

    @pytest.mark.asyncio
    async def test_delete_nonexistent_user(self, users_client):
        with _patch_audit_log():
            resp = await users_client.delete("/api/v1/users/nobody@example.com")
        assert resp.status_code == 404


class TestRecentUsers:
    @pytest.mark.asyncio
    async def test_recent_users_empty(self, users_client):
        with _patch_recent_users([]):
            resp = await users_client.get("/api/v1/users/recent")
        assert resp.status_code == 200
        assert resp.json() == []
