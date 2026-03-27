"""Tests for role assignments CRUD endpoints.

Tests /api/v1/role-assignments endpoints for listing, setting, and
deleting role assignments for (provider, email) pairs.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.api.dependencies import require_admin, require_admin_or_audit
from bamf.api.routers.role_assignments import router
from bamf.auth.sessions import Session
from bamf.db.models import Role, User
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
def role_assignments_app(db_session: AsyncSession):
    """Minimal app with role-assignments router and auth overrides."""
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
async def role_assignments_client(role_assignments_app):
    async with AsyncClient(
        transport=ASGITransport(app=role_assignments_app),
        base_url="http://test",
    ) as client:
        yield client


def _patch_audit_log():
    """Patch audit logging to no-op."""
    return patch(
        "bamf.api.routers.role_assignments.log_audit_event",
        new_callable=AsyncMock,
    )


async def _create_custom_role(db_session: AsyncSession, name: str) -> None:
    """Insert a custom role into the roles table so FK constraints pass."""
    db_session.add(
        Role(
            name=name,
            description=f"Test role: {name}",
            allow_labels={},
            allow_names=[],
            deny_labels={},
            deny_names=[],
            kubernetes_groups=[],
        )
    )
    await db_session.flush()


# ── Tests ─────────────────────────────────────────────────────────────────


class TestListRoleAssignments:
    @pytest.mark.asyncio
    async def test_list_empty(self, role_assignments_client):
        resp = await role_assignments_client.get("/api/v1/role-assignments")
        assert resp.status_code == 200
        assert resp.json() == []

    @pytest.mark.asyncio
    async def test_list_includes_created_assignments(self, role_assignments_client, db_session):
        await _create_custom_role(db_session, "developer")
        with _patch_audit_log():
            await role_assignments_client.put(
                "/api/v1/role-assignments",
                json={
                    "provider_name": "local",
                    "email": "alice@example.com",
                    "roles": ["developer"],
                },
            )

        resp = await role_assignments_client.get("/api/v1/role-assignments")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["provider_name"] == "local"
        assert data[0]["email"] == "alice@example.com"
        assert data[0]["role_name"] == "developer"
        assert data[0]["is_platform_role"] is False


class TestSetRoleAssignments:
    @pytest.mark.asyncio
    async def test_put_custom_role(self, role_assignments_client, db_session):
        await _create_custom_role(db_session, "sre")
        with _patch_audit_log():
            resp = await role_assignments_client.put(
                "/api/v1/role-assignments",
                json={
                    "provider_name": "auth0",
                    "email": "bob@example.com",
                    "roles": ["sre"],
                },
            )
        assert resp.status_code == 200
        assert resp.json() == ["sre"]

    @pytest.mark.asyncio
    async def test_put_platform_role(self, role_assignments_client, db_session):
        with _patch_audit_log():
            resp = await role_assignments_client.put(
                "/api/v1/role-assignments",
                json={
                    "provider_name": "local",
                    "email": "ops@example.com",
                    "roles": ["admin"],
                },
            )
        assert resp.status_code == 200
        assert resp.json() == ["admin"]

        # Verify it appears in list as a platform role
        resp = await role_assignments_client.get("/api/v1/role-assignments")
        data = resp.json()
        admin_assignments = [a for a in data if a["role_name"] == "admin"]
        assert len(admin_assignments) == 1
        assert admin_assignments[0]["is_platform_role"] is True

    @pytest.mark.asyncio
    async def test_put_mixed_roles(self, role_assignments_client, db_session):
        """PUT with both platform and custom roles splits correctly."""
        await _create_custom_role(db_session, "viewer")
        with _patch_audit_log():
            resp = await role_assignments_client.put(
                "/api/v1/role-assignments",
                json={
                    "provider_name": "okta",
                    "email": "mixed@example.com",
                    "roles": ["admin", "audit", "viewer"],
                },
            )
        assert resp.status_code == 200
        assert resp.json() == ["admin", "audit", "viewer"]

        # Verify split in list
        resp = await role_assignments_client.get("/api/v1/role-assignments")
        data = resp.json()
        mixed = [a for a in data if a["email"] == "mixed@example.com"]
        assert len(mixed) == 3
        platform = {a["role_name"] for a in mixed if a["is_platform_role"]}
        custom = {a["role_name"] for a in mixed if not a["is_platform_role"]}
        assert platform == {"admin", "audit"}
        assert custom == {"viewer"}

    @pytest.mark.asyncio
    async def test_put_replaces_existing(self, role_assignments_client, db_session):
        """PUT replaces all existing assignments for the identity."""
        await _create_custom_role(db_session, "role-a")
        await _create_custom_role(db_session, "role-b")

        with _patch_audit_log():
            # First set
            await role_assignments_client.put(
                "/api/v1/role-assignments",
                json={
                    "provider_name": "local",
                    "email": "replace@example.com",
                    "roles": ["role-a", "admin"],
                },
            )
            # Replace with different roles
            resp = await role_assignments_client.put(
                "/api/v1/role-assignments",
                json={
                    "provider_name": "local",
                    "email": "replace@example.com",
                    "roles": ["role-b"],
                },
            )
        assert resp.status_code == 200
        assert resp.json() == ["role-b"]

        # Verify old roles are gone
        resp = await role_assignments_client.get("/api/v1/role-assignments")
        data = resp.json()
        user_roles = [a for a in data if a["email"] == "replace@example.com"]
        assert len(user_roles) == 1
        assert user_roles[0]["role_name"] == "role-b"

    @pytest.mark.asyncio
    async def test_put_rejects_everyone_role(self, role_assignments_client):
        with _patch_audit_log():
            resp = await role_assignments_client.put(
                "/api/v1/role-assignments",
                json={
                    "provider_name": "local",
                    "email": "user@example.com",
                    "roles": ["everyone"],
                },
            )
        assert resp.status_code == 400
        assert "everyone" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_put_rejects_nonexistent_custom_role(self, role_assignments_client):
        with _patch_audit_log():
            resp = await role_assignments_client.put(
                "/api/v1/role-assignments",
                json={
                    "provider_name": "local",
                    "email": "user@example.com",
                    "roles": ["nonexistent-role"],
                },
            )
        assert resp.status_code == 400
        assert "nonexistent-role" in resp.json()["detail"]


class TestDeleteRoleAssignment:
    @pytest.mark.asyncio
    async def test_delete_custom_role(self, role_assignments_client, db_session):
        await _create_custom_role(db_session, "to-delete")
        with _patch_audit_log():
            await role_assignments_client.put(
                "/api/v1/role-assignments",
                json={
                    "provider_name": "local",
                    "email": "del@example.com",
                    "roles": ["to-delete"],
                },
            )
            resp = await role_assignments_client.delete(
                "/api/v1/role-assignments/local/del@example.com/to-delete"
            )
        assert resp.status_code == 204

        # Verify it's gone
        resp = await role_assignments_client.get("/api/v1/role-assignments")
        data = resp.json()
        remaining = [a for a in data if a["email"] == "del@example.com"]
        assert remaining == []

    @pytest.mark.asyncio
    async def test_delete_platform_role(self, role_assignments_client, db_session):
        with _patch_audit_log():
            await role_assignments_client.put(
                "/api/v1/role-assignments",
                json={
                    "provider_name": "local",
                    "email": "plat-del@example.com",
                    "roles": ["audit"],
                },
            )
            resp = await role_assignments_client.delete(
                "/api/v1/role-assignments/local/plat-del@example.com/audit"
            )
        assert resp.status_code == 204

    @pytest.mark.asyncio
    async def test_delete_nonexistent_returns_404(self, role_assignments_client):
        with _patch_audit_log():
            resp = await role_assignments_client.delete(
                "/api/v1/role-assignments/local/nobody@example.com/admin"
            )
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()


# ── Helper: create a local user in the users table ────────────────────────


async def _create_local_user(
    db_session: AsyncSession,
    email: str,
    display_name: str | None = None,
) -> None:
    """Insert a local user into the users table."""
    db_session.add(
        User(
            email=email,
            display_name=display_name,
            is_active=True,
        )
    )
    await db_session.flush()


def _patch_recent_users(users: list | None = None):
    """Patch list_recent_users to return the given list."""
    if users is None:
        users = []

    async def _mock_list():
        return users

    return patch(
        "bamf.api.routers.role_assignments.list_recent_users",
        side_effect=_mock_list,
    )


# ── Tests: list_identities ───────────────────────────────────────────────


class TestListIdentities:
    """Tests for GET /role-assignments/identities."""

    @pytest.mark.asyncio
    async def test_empty_returns_empty_list(self, role_assignments_client):
        """No users, no recent logins, no assignments => empty list."""
        with _patch_recent_users([]):
            resp = await role_assignments_client.get("/api/v1/role-assignments/identities")
        assert resp.status_code == 200
        assert resp.json() == []

    @pytest.mark.asyncio
    async def test_local_users_from_db(self, role_assignments_client, db_session):
        """Local users from the users table appear with provider_name='local'."""
        await _create_local_user(db_session, "alice@example.com", "Alice")
        await _create_local_user(db_session, "bob@example.com", "Bob")

        with _patch_recent_users([]):
            resp = await role_assignments_client.get("/api/v1/role-assignments/identities")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2
        assert data[0]["provider_name"] == "local"
        assert data[0]["email"] == "alice@example.com"
        assert data[0]["display_name"] == "Alice"
        assert data[0]["roles"] == []
        assert data[1]["email"] == "bob@example.com"

    @pytest.mark.asyncio
    async def test_local_user_with_roles(self, role_assignments_client, db_session):
        """Local user with assigned roles shows them in the response."""
        await _create_local_user(db_session, "admin-user@example.com", "Admin User")
        await _create_custom_role(db_session, "developer")

        with _patch_audit_log():
            await role_assignments_client.put(
                "/api/v1/role-assignments",
                json={
                    "provider_name": "local",
                    "email": "admin-user@example.com",
                    "roles": ["admin", "developer"],
                },
            )

        with _patch_recent_users([]):
            resp = await role_assignments_client.get("/api/v1/role-assignments/identities")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["email"] == "admin-user@example.com"
        assert sorted(data[0]["roles"]) == ["admin", "developer"]

    @pytest.mark.asyncio
    async def test_sso_recent_user_included(self, role_assignments_client, db_session):
        """SSO user from Redis recent cache appears in the list."""
        from bamf.auth.recent_users import RecentUser

        recent = [
            RecentUser(
                provider_name="auth0",
                email="sso-user@example.com",
                display_name="SSO User",
                last_seen="2026-03-27T10:00:00+00:00",
            ),
        ]

        with _patch_recent_users(recent):
            resp = await role_assignments_client.get("/api/v1/role-assignments/identities")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["provider_name"] == "auth0"
        assert data[0]["email"] == "sso-user@example.com"
        assert data[0]["display_name"] == "SSO User"
        assert data[0]["roles"] == []

    @pytest.mark.asyncio
    async def test_sso_recent_user_with_roles(self, role_assignments_client, db_session):
        """SSO user from Redis with role assignments shows the roles."""
        from bamf.auth.recent_users import RecentUser

        # Assign a platform role to the SSO user
        with _patch_audit_log():
            await role_assignments_client.put(
                "/api/v1/role-assignments",
                json={
                    "provider_name": "auth0",
                    "email": "sso-with-roles@example.com",
                    "roles": ["admin"],
                },
            )

        recent = [
            RecentUser(
                provider_name="auth0",
                email="sso-with-roles@example.com",
                display_name="SSO Admin",
                last_seen="2026-03-27T10:00:00+00:00",
            ),
        ]

        with _patch_recent_users(recent):
            resp = await role_assignments_client.get("/api/v1/role-assignments/identities")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["email"] == "sso-with-roles@example.com"
        assert data[0]["roles"] == ["admin"]

    @pytest.mark.asyncio
    async def test_deduplication_local_user_and_recent_login(
        self, role_assignments_client, db_session
    ):
        """If a local user also appears in Redis, they are deduplicated."""
        from bamf.auth.recent_users import RecentUser

        await _create_local_user(db_session, "shared@example.com", "From DB")

        recent = [
            RecentUser(
                provider_name="local",
                email="shared@example.com",
                display_name="From Redis",
                last_seen="2026-03-27T10:00:00+00:00",
            ),
        ]

        with _patch_recent_users(recent):
            resp = await role_assignments_client.get("/api/v1/role-assignments/identities")
        assert resp.status_code == 200
        data = resp.json()
        # Should have exactly one entry (deduplicated)
        shared = [d for d in data if d["email"] == "shared@example.com"]
        assert len(shared) == 1
        # Display name comes from DB (source 1 wins)
        assert shared[0]["display_name"] == "From DB"

    @pytest.mark.asyncio
    async def test_dedup_updates_display_name_if_db_has_none(
        self, role_assignments_client, db_session
    ):
        """If DB user has no display_name but Redis does, Redis display_name is used."""
        from bamf.auth.recent_users import RecentUser

        await _create_local_user(db_session, "no-name@example.com", None)

        recent = [
            RecentUser(
                provider_name="local",
                email="no-name@example.com",
                display_name="Redis Name",
                last_seen="2026-03-27T10:00:00+00:00",
            ),
        ]

        with _patch_recent_users(recent):
            resp = await role_assignments_client.get("/api/v1/role-assignments/identities")
        assert resp.status_code == 200
        data = resp.json()
        entry = [d for d in data if d["email"] == "no-name@example.com"]
        assert len(entry) == 1
        assert entry[0]["display_name"] == "Redis Name"

    @pytest.mark.asyncio
    async def test_local_recent_user_without_roles_excluded(
        self, role_assignments_client, db_session
    ):
        """Local provider users from Redis with no roles and no DB entry are excluded."""
        from bamf.auth.recent_users import RecentUser

        # A local recent user NOT in the users table and with no role assignments
        recent = [
            RecentUser(
                provider_name="local",
                email="stale-local@example.com",
                display_name="Stale Local",
                last_seen="2026-03-27T10:00:00+00:00",
            ),
        ]

        with _patch_recent_users(recent):
            resp = await role_assignments_client.get("/api/v1/role-assignments/identities")
        assert resp.status_code == 200
        data = resp.json()
        # The stale local user should not appear
        stale = [d for d in data if d["email"] == "stale-local@example.com"]
        assert stale == []

    @pytest.mark.asyncio
    async def test_local_recent_user_with_roles_included(self, role_assignments_client, db_session):
        """Local provider user from Redis with role assignments IS included."""
        from bamf.auth.recent_users import RecentUser

        # Assign a role to this local user (not in users table)
        with _patch_audit_log():
            await role_assignments_client.put(
                "/api/v1/role-assignments",
                json={
                    "provider_name": "local",
                    "email": "local-with-roles@example.com",
                    "roles": ["admin"],
                },
            )

        recent = [
            RecentUser(
                provider_name="local",
                email="local-with-roles@example.com",
                display_name="Local With Roles",
                last_seen="2026-03-27T10:00:00+00:00",
            ),
        ]

        with _patch_recent_users(recent):
            resp = await role_assignments_client.get("/api/v1/role-assignments/identities")
        assert resp.status_code == 200
        data = resp.json()
        entry = [d for d in data if d["email"] == "local-with-roles@example.com"]
        assert len(entry) == 1
        assert entry[0]["roles"] == ["admin"]

    @pytest.mark.asyncio
    async def test_source3_pre_provisioned_assignment(self, role_assignments_client, db_session):
        """Identities with role assignments but not in users table or Redis appear."""
        # Pre-provision a role assignment for an SSO user who hasn't logged in
        with _patch_audit_log():
            await role_assignments_client.put(
                "/api/v1/role-assignments",
                json={
                    "provider_name": "okta",
                    "email": "preprovisioned@example.com",
                    "roles": ["audit"],
                },
            )

        # No recent users in Redis
        with _patch_recent_users([]):
            resp = await role_assignments_client.get("/api/v1/role-assignments/identities")
        assert resp.status_code == 200
        data = resp.json()
        entry = [d for d in data if d["email"] == "preprovisioned@example.com"]
        assert len(entry) == 1
        assert entry[0]["provider_name"] == "okta"
        assert entry[0]["display_name"] is None
        assert entry[0]["roles"] == ["audit"]

    @pytest.mark.asyncio
    async def test_source3_not_duplicated_if_in_recent(self, role_assignments_client, db_session):
        """Source 3 does not duplicate an identity already seen in Redis."""
        from bamf.auth.recent_users import RecentUser

        # Assign roles to an SSO user
        with _patch_audit_log():
            await role_assignments_client.put(
                "/api/v1/role-assignments",
                json={
                    "provider_name": "auth0",
                    "email": "seen-in-redis@example.com",
                    "roles": ["admin"],
                },
            )

        recent = [
            RecentUser(
                provider_name="auth0",
                email="seen-in-redis@example.com",
                display_name="Seen",
                last_seen="2026-03-27T10:00:00+00:00",
            ),
        ]

        with _patch_recent_users(recent):
            resp = await role_assignments_client.get("/api/v1/role-assignments/identities")
        assert resp.status_code == 200
        data = resp.json()
        entries = [d for d in data if d["email"] == "seen-in-redis@example.com"]
        assert len(entries) == 1
        # display_name comes from Redis (source 2), not None (source 3)
        assert entries[0]["display_name"] == "Seen"

    @pytest.mark.asyncio
    async def test_sorting_local_first_then_by_email(self, role_assignments_client, db_session):
        """Results are sorted: local provider first, then alphabetically by email."""
        from bamf.auth.recent_users import RecentUser

        await _create_local_user(db_session, "zara@example.com", "Zara")
        await _create_local_user(db_session, "alice@example.com", "Alice")

        recent = [
            RecentUser(
                provider_name="auth0",
                email="bob@example.com",
                display_name="Bob",
                last_seen="2026-03-27T10:00:00+00:00",
            ),
            RecentUser(
                provider_name="okta",
                email="adam@example.com",
                display_name="Adam",
                last_seen="2026-03-27T10:00:00+00:00",
            ),
        ]

        with _patch_recent_users(recent):
            resp = await role_assignments_client.get("/api/v1/role-assignments/identities")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 4

        # Local users first, sorted by email
        assert data[0]["provider_name"] == "local"
        assert data[0]["email"] == "alice@example.com"
        assert data[1]["provider_name"] == "local"
        assert data[1]["email"] == "zara@example.com"
        # Then external, sorted by email
        assert data[2]["email"] == "adam@example.com"
        assert data[3]["email"] == "bob@example.com"

    @pytest.mark.asyncio
    async def test_all_three_sources_merged(self, role_assignments_client, db_session):
        """Full scenario: users table + Redis recent + pre-provisioned assignments."""
        from bamf.auth.recent_users import RecentUser

        # Source 1: local user in DB
        await _create_local_user(db_session, "local-user@example.com", "Local")

        # Source 2: SSO user in Redis
        recent = [
            RecentUser(
                provider_name="auth0",
                email="sso-user@example.com",
                display_name="SSO",
                last_seen="2026-03-27T10:00:00+00:00",
            ),
        ]

        # Source 3: pre-provisioned assignment (not in users or Redis)
        with _patch_audit_log():
            await role_assignments_client.put(
                "/api/v1/role-assignments",
                json={
                    "provider_name": "okta",
                    "email": "future-user@example.com",
                    "roles": ["audit"],
                },
            )

        with _patch_recent_users(recent):
            resp = await role_assignments_client.get("/api/v1/role-assignments/identities")
        assert resp.status_code == 200
        data = resp.json()
        emails = [d["email"] for d in data]
        assert "local-user@example.com" in emails
        assert "sso-user@example.com" in emails
        assert "future-user@example.com" in emails
        assert len(data) == 3


# ── Tests: list_stale_assignments ─────────────────────────────────────────


class TestListStaleAssignments:
    """Tests for GET /role-assignments/stale."""

    @pytest.mark.asyncio
    async def test_empty_when_no_assignments(self, role_assignments_client):
        """No assignments at all => empty stale list."""
        with _patch_recent_users([]):
            resp = await role_assignments_client.get("/api/v1/role-assignments/stale")
        assert resp.status_code == 200
        assert resp.json() == []

    @pytest.mark.asyncio
    async def test_no_stale_when_all_recently_seen(self, role_assignments_client, db_session):
        """All assigned identities have recent logins => no stale entries."""
        from bamf.auth.recent_users import RecentUser

        with _patch_audit_log():
            await role_assignments_client.put(
                "/api/v1/role-assignments",
                json={
                    "provider_name": "auth0",
                    "email": "active@example.com",
                    "roles": ["admin"],
                },
            )

        recent = [
            RecentUser(
                provider_name="auth0",
                email="active@example.com",
                display_name="Active",
                last_seen="2026-03-27T10:00:00+00:00",
            ),
        ]

        with _patch_recent_users(recent):
            resp = await role_assignments_client.get("/api/v1/role-assignments/stale")
        assert resp.status_code == 200
        assert resp.json() == []

    @pytest.mark.asyncio
    async def test_stale_when_not_in_recent(self, role_assignments_client, db_session):
        """Assignment exists but no recent login => stale."""
        with _patch_audit_log():
            await role_assignments_client.put(
                "/api/v1/role-assignments",
                json={
                    "provider_name": "auth0",
                    "email": "stale@example.com",
                    "roles": ["audit"],
                },
            )

        # No recent users at all
        with _patch_recent_users([]):
            resp = await role_assignments_client.get("/api/v1/role-assignments/stale")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["provider_name"] == "auth0"
        assert data[0]["email"] == "stale@example.com"
        assert data[0]["roles"] == ["audit"]
        assert data[0]["display_name"] is None

    @pytest.mark.asyncio
    async def test_mixed_stale_and_active(self, role_assignments_client, db_session):
        """Some assigned identities are recent, some are stale."""
        from bamf.auth.recent_users import RecentUser

        with _patch_audit_log():
            # Active user
            await role_assignments_client.put(
                "/api/v1/role-assignments",
                json={
                    "provider_name": "auth0",
                    "email": "active@example.com",
                    "roles": ["admin"],
                },
            )
            # Stale user
            await role_assignments_client.put(
                "/api/v1/role-assignments",
                json={
                    "provider_name": "okta",
                    "email": "stale@example.com",
                    "roles": ["audit"],
                },
            )

        recent = [
            RecentUser(
                provider_name="auth0",
                email="active@example.com",
                display_name="Active",
                last_seen="2026-03-27T10:00:00+00:00",
            ),
        ]

        with _patch_recent_users(recent):
            resp = await role_assignments_client.get("/api/v1/role-assignments/stale")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["email"] == "stale@example.com"
        assert data[0]["provider_name"] == "okta"

    @pytest.mark.asyncio
    async def test_stale_with_custom_and_platform_roles(self, role_assignments_client, db_session):
        """Stale identity with both custom and platform roles shows all roles."""
        await _create_custom_role(db_session, "developer")

        with _patch_audit_log():
            await role_assignments_client.put(
                "/api/v1/role-assignments",
                json={
                    "provider_name": "auth0",
                    "email": "stale-mixed@example.com",
                    "roles": ["admin", "developer"],
                },
            )

        with _patch_recent_users([]):
            resp = await role_assignments_client.get("/api/v1/role-assignments/stale")
        assert resp.status_code == 200
        data = resp.json()
        entry = [d for d in data if d["email"] == "stale-mixed@example.com"]
        assert len(entry) == 1
        assert sorted(entry[0]["roles"]) == ["admin", "developer"]

    @pytest.mark.asyncio
    async def test_stale_sorting(self, role_assignments_client, db_session):
        """Stale results are sorted: local first, then by email."""
        with _patch_audit_log():
            await role_assignments_client.put(
                "/api/v1/role-assignments",
                json={
                    "provider_name": "okta",
                    "email": "zara@example.com",
                    "roles": ["audit"],
                },
            )
            await role_assignments_client.put(
                "/api/v1/role-assignments",
                json={
                    "provider_name": "local",
                    "email": "bob@example.com",
                    "roles": ["admin"],
                },
            )
            await role_assignments_client.put(
                "/api/v1/role-assignments",
                json={
                    "provider_name": "auth0",
                    "email": "alice@example.com",
                    "roles": ["audit"],
                },
            )

        with _patch_recent_users([]):
            resp = await role_assignments_client.get("/api/v1/role-assignments/stale")
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 3
        # Local first
        assert data[0]["provider_name"] == "local"
        assert data[0]["email"] == "bob@example.com"
        # Then external, sorted by email
        assert data[1]["email"] == "alice@example.com"
        assert data[2]["email"] == "zara@example.com"

    @pytest.mark.asyncio
    async def test_stale_provider_must_match(self, role_assignments_client, db_session):
        """Same email on different providers: one stale, one active."""
        from bamf.auth.recent_users import RecentUser

        with _patch_audit_log():
            # Same email, two providers
            await role_assignments_client.put(
                "/api/v1/role-assignments",
                json={
                    "provider_name": "auth0",
                    "email": "user@example.com",
                    "roles": ["admin"],
                },
            )
            await role_assignments_client.put(
                "/api/v1/role-assignments",
                json={
                    "provider_name": "okta",
                    "email": "user@example.com",
                    "roles": ["audit"],
                },
            )

        # Only auth0 login is recent
        recent = [
            RecentUser(
                provider_name="auth0",
                email="user@example.com",
                display_name="User",
                last_seen="2026-03-27T10:00:00+00:00",
            ),
        ]

        with _patch_recent_users(recent):
            resp = await role_assignments_client.get("/api/v1/role-assignments/stale")
        assert resp.status_code == 200
        data = resp.json()
        # Only the okta entry is stale
        assert len(data) == 1
        assert data[0]["provider_name"] == "okta"
        assert data[0]["email"] == "user@example.com"
