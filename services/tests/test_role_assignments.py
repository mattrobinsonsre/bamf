"""Tests for dual-source role model and role prefix stripping."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bamf.auth.connectors.oidc import _strip_role_prefixes
from bamf.auth.sso import AuthenticatedIdentity


class TestRolePrefixStripping:
    """Test configurable role prefix stripping."""

    def test_strip_default_prefixes(self):
        """Groups with bamf: or bamf- prefix should have them stripped."""
        groups = ["bamf:admin", "bamf-ssh-access", "bamf:k8s-access"]
        result = _strip_role_prefixes(groups, ["bamf:", "bamf-"])
        assert result == ["admin", "ssh-access", "k8s-access"]

    def test_pass_through_unprefixed_groups(self):
        """Groups without a matching prefix are passed through unchanged."""
        groups = ["viewer", "readonly"]
        result = _strip_role_prefixes(groups, ["bamf:", "bamf-"])
        assert result == ["viewer", "readonly"]

    def test_mixed_prefixed_and_unprefixed(self):
        """Mix of prefixed and unprefixed groups."""
        groups = ["bamf:admin", "unrelated-group", "bamf-ssh-access"]
        result = _strip_role_prefixes(groups, ["bamf:", "bamf-"])
        assert result == ["admin", "unrelated-group", "ssh-access"]

    def test_empty_groups(self):
        """Empty groups list returns empty list."""
        assert _strip_role_prefixes([], ["bamf:", "bamf-"]) == []

    def test_custom_prefix(self):
        """Custom prefixes work correctly."""
        groups = ["myorg:admin", "myorg:viewer", "other-group"]
        result = _strip_role_prefixes(groups, ["myorg:"])
        assert result == ["admin", "viewer", "other-group"]

    def test_empty_prefixes_passthrough(self):
        """Empty prefix list passes all groups through unchanged."""
        groups = ["bamf:admin", "bamf-viewer"]
        result = _strip_role_prefixes(groups, [])
        assert result == ["bamf:admin", "bamf-viewer"]

    def test_first_matching_prefix_wins(self):
        """When multiple prefixes could match, the first one wins."""
        groups = ["bamf:admin"]
        # "bamf:" matches before "bamf" would
        result = _strip_role_prefixes(groups, ["bamf:", "bamf"])
        assert result == ["admin"]


class TestProcessLoginRoleMerge:
    """Test that process_login merges roles from all three sources."""

    @pytest.fixture
    def mock_db(self):
        """Create a mock database session."""
        db = AsyncMock()
        return db

    @pytest.fixture
    def base_identity(self):
        """Create a base identity for testing.

        Groups are already prefix-stripped (connectors handle this before
        process_login is called).
        """
        return AuthenticatedIdentity(
            provider_name="auth0",
            subject="auth0|12345",
            email="alice@corp.com",
            display_name="Alice",
            groups=["viewer"],  # Already stripped by connector
            raw_claims={
                "sub": "auth0|12345",
                "email": "alice@corp.com",
                "groups": ["bamf:viewer"],  # Raw claims retain original values
            },
        )

    @pytest.fixture
    def local_identity(self):
        """Create a local identity for testing."""
        return AuthenticatedIdentity(
            provider_name="local",
            subject="alice@corp.com",
            email="alice@corp.com",
            display_name="Alice",
            groups=[],
            raw_claims={"sub": "alice@corp.com", "auth_method": "password"},
        )

    @pytest.mark.asyncio
    async def test_external_sso_merges_three_sources(self, mock_db, base_identity):
        """External SSO login merges IDP groups, claims mapping, and internal assignments."""
        from bamf.services.sso_service import process_login

        # Mock the DB queries (custom roles, platform roles, k8s groups)
        # Custom role assignments
        mock_result_custom_roles = MagicMock()
        mock_result_custom_roles.scalars.return_value.all.return_value = ["ssh-access"]

        # Platform role assignments
        mock_result_platform_roles = MagicMock()
        mock_result_platform_roles.scalars.return_value.all.return_value = []

        # _resolve_kubernetes_groups: query for custom role k8s groups
        mock_result_k8s_groups = MagicMock()
        mock_result_k8s_groups.all.return_value = []

        # For external SSO (auth0), there's no user lookup — DB queries are:
        # custom role assignments, platform role assignments, kubernetes_groups
        mock_db.execute = AsyncMock(
            side_effect=[
                mock_result_custom_roles,
                mock_result_platform_roles,
                mock_result_k8s_groups,
            ]
        )
        mock_db.flush = AsyncMock()
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()

        # Claims mapping rules: "groups" containing "bamf:viewer" → ["developer"]
        # (raw_claims still contain the original prefixed values)
        from bamf.config import ClaimsToRolesMapping

        rules = [ClaimsToRolesMapping(claim="groups", value="bamf:viewer", roles=["developer"])]

        with patch("bamf.services.sso_service.record_recent_user", new_callable=AsyncMock):
            result = await process_login(mock_db, base_identity, rules)

        # Source 1: IDP groups (already stripped by connector) → ["viewer"]
        # Source 2: claims mapping → ["developer"]
        # Source 3: internal assignments → ["ssh-access"]
        assert "viewer" in result.roles
        assert "developer" in result.roles
        assert "ssh-access" in result.roles

    @pytest.mark.asyncio
    async def test_local_login_uses_internal_assignments(self, mock_db, local_identity):
        """Local login uses only internal role assignments (no IDP groups)."""
        from bamf.services.sso_service import process_login

        mock_user = MagicMock()
        mock_user.email = "alice@corp.com"
        mock_user.display_name = None
        mock_result_user = MagicMock()
        mock_result_user.scalar_one_or_none.return_value = mock_user

        # Custom role assignments
        mock_result_custom_roles = MagicMock()
        mock_result_custom_roles.scalars.return_value.all.return_value = ["ssh-access"]

        # Platform role assignments (admin is a platform role)
        mock_result_platform_roles = MagicMock()
        mock_result_platform_roles.scalars.return_value.all.return_value = ["admin"]

        # _resolve_kubernetes_groups: query for custom role k8s groups
        mock_result_k8s_groups = MagicMock()
        mock_result_k8s_groups.all.return_value = []

        mock_db.execute = AsyncMock(
            side_effect=[
                mock_result_user,
                mock_result_custom_roles,
                mock_result_platform_roles,
                mock_result_k8s_groups,
            ]
        )
        mock_db.flush = AsyncMock()
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()

        with patch("bamf.services.sso_service.record_recent_user", new_callable=AsyncMock):
            result = await process_login(mock_db, local_identity, [])

        # Source 1: empty (local connector)
        # Source 2: no claims rules
        # Source 3: internal assignments → ["ssh-access"] (custom) + ["admin"] (platform)
        assert result.roles == ["admin", "ssh-access"]

    @pytest.mark.asyncio
    async def test_roles_are_deduplicated(self, mock_db, base_identity):
        """Duplicate roles from different sources are deduplicated."""
        from bamf.services.sso_service import process_login

        # Custom assignments include "viewer" which is also from IDP groups
        mock_result_custom_roles = MagicMock()
        mock_result_custom_roles.scalars.return_value.all.return_value = ["viewer"]

        # Platform assignments include "admin"
        mock_result_platform_roles = MagicMock()
        mock_result_platform_roles.scalars.return_value.all.return_value = ["admin"]

        # _resolve_kubernetes_groups: query for custom role k8s groups
        mock_result_k8s_groups = MagicMock()
        mock_result_k8s_groups.all.return_value = []

        # For external SSO (auth0), there's no user lookup — DB queries are:
        # custom role assignments, platform role assignments, kubernetes_groups
        mock_db.execute = AsyncMock(
            side_effect=[
                mock_result_custom_roles,
                mock_result_platform_roles,
                mock_result_k8s_groups,
            ]
        )
        mock_db.flush = AsyncMock()
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()

        with patch("bamf.services.sso_service.record_recent_user", new_callable=AsyncMock):
            result = await process_login(mock_db, base_identity, [])

        # "viewer" appears in both IDP groups and custom assignments
        # Should only appear once in the result
        assert result.roles.count("viewer") == 1
        assert "admin" in result.roles

    @pytest.mark.asyncio
    async def test_local_groups_not_stripped(self, mock_db):
        """Local auth groups are passed through unchanged."""
        from bamf.services.sso_service import process_login

        # A local identity that has groups (passed through as-is)
        identity = AuthenticatedIdentity(
            provider_name="local",
            subject="bob@corp.com",
            email="bob@corp.com",
            display_name=None,
            groups=["admin"],  # No prefix for local
            raw_claims={"sub": "bob@corp.com"},
        )

        mock_user = MagicMock()
        mock_user.email = "bob@corp.com"
        mock_user.display_name = None
        mock_result_user = MagicMock()
        mock_result_user.scalar_one_or_none.return_value = mock_user

        # Custom role assignments (empty)
        mock_result_custom_roles = MagicMock()
        mock_result_custom_roles.scalars.return_value.all.return_value = []

        # Platform role assignments (empty)
        mock_result_platform_roles = MagicMock()
        mock_result_platform_roles.scalars.return_value.all.return_value = []

        mock_db.execute = AsyncMock(
            side_effect=[mock_result_user, mock_result_custom_roles, mock_result_platform_roles]
        )
        mock_db.flush = AsyncMock()
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()

        with patch("bamf.services.sso_service.record_recent_user", new_callable=AsyncMock):
            result = await process_login(mock_db, identity, [])

        # "admin" should pass through unchanged
        assert result.roles == ["admin"]
