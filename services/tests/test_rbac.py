"""Tests for RBAC functionality.

Tests label matching, label merging, and the main check_access() function
with admin bypass, deny-wins semantics, and everyone role handling.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock

import pytest

from bamf.services.rbac_service import _matches_labels, _merge_labels, check_access
from bamf.services.resource_catalog import ResourceInfo


class TestLabelMatching:
    """Test label matching logic."""

    def test_matches_labels_exact_match(self):
        """Test exact label match."""
        resource_labels = {"env": "prod", "team": "platform"}
        permission_labels = {"env": {"prod"}}

        assert _matches_labels(resource_labels, permission_labels) is True

    def test_matches_labels_no_match(self):
        """Test no label match."""
        resource_labels = {"env": "dev", "team": "platform"}
        permission_labels = {"env": {"prod"}}

        assert _matches_labels(resource_labels, permission_labels) is False

    def test_matches_labels_key_not_present(self):
        """Test when permission key not in resource labels."""
        resource_labels = {"team": "platform"}
        permission_labels = {"env": {"prod"}}

        assert _matches_labels(resource_labels, permission_labels) is False

    def test_matches_labels_multiple_values(self):
        """Test matching with multiple allowed values."""
        resource_labels = {"env": "staging"}
        permission_labels = {"env": {"prod", "staging"}}

        assert _matches_labels(resource_labels, permission_labels) is True

    def test_matches_labels_multiple_keys(self):
        """Test matching with multiple permission keys (any match)."""
        resource_labels = {"env": "prod", "region": "us-east-1"}
        permission_labels = {"env": {"prod"}, "team": {"platform"}}

        # Should match because env=prod matches
        assert _matches_labels(resource_labels, permission_labels) is True

    def test_matches_labels_empty_permissions(self):
        """Test empty permission labels."""
        resource_labels = {"env": "prod"}
        permission_labels: dict[str, set[str]] = {}

        assert _matches_labels(resource_labels, permission_labels) is False

    def test_matches_labels_empty_resource(self):
        """Test empty resource labels."""
        resource_labels: dict = {}
        permission_labels = {"env": {"prod"}}

        assert _matches_labels(resource_labels, permission_labels) is False


class TestLabelMerging:
    """Test label merging logic."""

    def test_merge_labels_empty_target(self):
        """Test merging into empty target."""
        target: dict[str, set[str]] = {}
        source = {"env": ["prod", "staging"]}

        _merge_labels(target, source)

        assert target == {"env": {"prod", "staging"}}

    def test_merge_labels_existing_key(self):
        """Test merging with existing key."""
        target: dict[str, set[str]] = {"env": {"prod"}}
        source = {"env": ["staging"]}

        _merge_labels(target, source)

        assert target == {"env": {"prod", "staging"}}

    def test_merge_labels_new_key(self):
        """Test merging new key."""
        target: dict[str, set[str]] = {"env": {"prod"}}
        source = {"team": ["platform"]}

        _merge_labels(target, source)

        assert target == {"env": {"prod"}, "team": {"platform"}}

    def test_merge_labels_single_value(self):
        """Test merging single value (not list)."""
        target: dict[str, set[str]] = {}
        source = {"env": "prod"}

        _merge_labels(target, source)

        assert target == {"env": {"prod"}}


# ── Tests: check_access ────────────────────────────────────────────────


def _make_resource(**overrides) -> ResourceInfo:
    defaults = {
        "name": "web-01",
        "resource_type": "ssh",
        "labels": {"env": "dev"},
        "agent_id": "agent-1",
    }
    defaults.update(overrides)
    return ResourceInfo(**defaults)


def _make_user(email: str = "user@example.com") -> MagicMock:
    user = MagicMock()
    user.email = email
    return user


def _make_role(
    name: str = "developer",
    allow_labels: dict | None = None,
    allow_names: list | None = None,
    deny_labels: dict | None = None,
    deny_names: list | None = None,
) -> MagicMock:
    role = MagicMock()
    role.name = name
    role.allow_labels = allow_labels or {}
    role.allow_names = allow_names or []
    role.deny_labels = deny_labels or {}
    role.deny_names = deny_names or []
    return role


def _mock_db_with_roles(roles: list) -> AsyncMock:
    db = AsyncMock()
    result = MagicMock()
    scalars = MagicMock()
    scalars.all.return_value = roles
    result.scalars.return_value = scalars
    db.execute.return_value = result
    return db


class TestCheckAccess:
    """Test the main check_access() function."""

    @pytest.mark.asyncio
    async def test_admin_bypass(self):
        """Admin role bypasses all checks."""
        db = AsyncMock()
        user = _make_user()
        resource = _make_resource()

        result = await check_access(db, user, resource, ["admin"])

        assert result is True
        db.execute.assert_not_called()

    @pytest.mark.asyncio
    async def test_admin_with_other_roles(self):
        """Admin role mixed with others still bypasses."""
        db = AsyncMock()
        user = _make_user()
        resource = _make_resource()

        result = await check_access(db, user, resource, ["developer", "admin"])

        assert result is True

    @pytest.mark.asyncio
    async def test_default_deny(self):
        """No matching allow rule results in deny."""
        db = _mock_db_with_roles([])
        user = _make_user()
        resource = _make_resource(labels={"env": "prod"})

        result = await check_access(db, user, resource, [])

        assert result is False

    @pytest.mark.asyncio
    async def test_everyone_role_access_everyone_label(self):
        """Resources labeled access=everyone are accessible to all users."""
        db = _mock_db_with_roles([])
        user = _make_user()
        resource = _make_resource(labels={"access": "everyone"})

        result = await check_access(db, user, resource, [])

        assert result is True

    @pytest.mark.asyncio
    async def test_everyone_role_no_match(self):
        """Resources without access=everyone are not granted by everyone role."""
        db = _mock_db_with_roles([])
        user = _make_user()
        resource = _make_resource(labels={"env": "prod"})

        result = await check_access(db, user, resource, [])

        assert result is False

    @pytest.mark.asyncio
    async def test_allow_by_label(self):
        """Custom role allows access via label match."""
        role = _make_role(allow_labels={"env": ["dev", "staging"]})
        db = _mock_db_with_roles([role])
        user = _make_user()
        resource = _make_resource(labels={"env": "dev"})

        result = await check_access(db, user, resource, ["developer"])

        assert result is True

    @pytest.mark.asyncio
    async def test_allow_by_name(self):
        """Custom role allows access via explicit name."""
        role = _make_role(allow_names=["web-01"])
        db = _mock_db_with_roles([role])
        user = _make_user()
        resource = _make_resource(name="web-01", labels={})

        result = await check_access(db, user, resource, ["developer"])

        assert result is True

    @pytest.mark.asyncio
    async def test_deny_name_wins_over_allow_label(self):
        """Deny by name overrides allow by label."""
        role = _make_role(
            allow_labels={"env": ["dev"]},
            deny_names=["web-01"],
        )
        db = _mock_db_with_roles([role])
        user = _make_user()
        resource = _make_resource(name="web-01", labels={"env": "dev"})

        result = await check_access(db, user, resource, ["developer"])

        assert result is False

    @pytest.mark.asyncio
    async def test_deny_label_wins_over_allow_name(self):
        """Deny by label overrides allow by name."""
        role = _make_role(
            allow_names=["web-01"],
            deny_labels={"team": ["hr"]},
        )
        db = _mock_db_with_roles([role])
        user = _make_user()
        resource = _make_resource(name="web-01", labels={"team": "hr"})

        result = await check_access(db, user, resource, ["developer"])

        assert result is False

    @pytest.mark.asyncio
    async def test_multiple_roles_merged(self):
        """Allow/deny from multiple roles are merged."""
        role1 = _make_role(name="dev", allow_labels={"env": ["dev"]})
        role2 = _make_role(name="sre", allow_labels={"env": ["prod"]})
        db = _mock_db_with_roles([role1, role2])
        user = _make_user()
        resource = _make_resource(labels={"env": "prod"})

        result = await check_access(db, user, resource, ["dev", "sre"])

        assert result is True

    @pytest.mark.asyncio
    async def test_builtin_roles_not_queried(self):
        """Built-in role names are not queried from DB."""
        db = _mock_db_with_roles([])
        user = _make_user()
        resource = _make_resource(labels={"access": "everyone"})

        # "everyone" and "audit" are built-in
        result = await check_access(db, user, resource, ["everyone", "audit"])

        assert result is True
        # DB should not be called since all roles are built-in
        db.execute.assert_not_called()

    @pytest.mark.asyncio
    async def test_no_roles_default_deny(self):
        """User with no roles is denied (except access=everyone)."""
        db = _mock_db_with_roles([])
        user = _make_user()
        resource = _make_resource(labels={"env": "prod"})

        result = await check_access(db, user, resource, [])

        assert result is False

    @pytest.mark.asyncio
    async def test_deny_name_overrides_everyone_allow(self):
        """Deny by name overrides even the everyone role."""
        role = _make_role(deny_names=["public-app"])
        db = _mock_db_with_roles([role])
        user = _make_user()
        resource = _make_resource(name="public-app", labels={"access": "everyone"})

        result = await check_access(db, user, resource, ["developer"])

        assert result is False
