"""Tests for dual-source role model and bamf: prefix stripping."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bamf.auth.sso import AuthenticatedIdentity
from bamf.services.sso_service import BAMF_CLAIM_PREFIX, _strip_bamf_prefix


class TestBamfPrefixStripping:
    """Test bamf: prefix stripping for external SSO claims."""

    def test_strip_prefix_from_groups(self):
        """Groups with bamf: prefix should have it stripped."""
        groups = ["bamf:admin", "bamf:ssh-access", "bamf:k8s-access"]
        result = _strip_bamf_prefix(groups)
        assert result == ["admin", "ssh-access", "k8s-access"]

    def test_pass_through_unprefixed_groups(self):
        """Groups without bamf: prefix are passed through unchanged."""
        groups = ["viewer", "readonly"]
        result = _strip_bamf_prefix(groups)
        assert result == ["viewer", "readonly"]

    def test_mixed_prefixed_and_unprefixed(self):
        """Mix of prefixed and unprefixed groups."""
        groups = ["bamf:admin", "unrelated-group", "bamf:ssh-access"]
        result = _strip_bamf_prefix(groups)
        assert result == ["admin", "unrelated-group", "ssh-access"]

    def test_empty_groups(self):
        """Empty groups list returns empty list."""
        assert _strip_bamf_prefix([]) == []

    def test_prefix_constant(self):
        """Verify the prefix constant value."""
        assert BAMF_CLAIM_PREFIX == "bamf:"


class TestProcessLoginRoleMerge:
    """Test that process_login merges roles from all three sources."""

    @pytest.fixture
    def mock_db(self):
        """Create a mock database session."""
        db = AsyncMock()
        return db

    @pytest.fixture
    def base_identity(self):
        """Create a base identity for testing."""
        return AuthenticatedIdentity(
            provider_name="auth0",
            subject="auth0|12345",
            email="alice@corp.com",
            display_name="Alice",
            groups=["bamf:viewer"],
            raw_claims={
                "sub": "auth0|12345",
                "email": "alice@corp.com",
                "groups": ["bamf:viewer"],
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

        # Mock the DB queries (3 queries: find/create user, custom roles, platform roles)
        # _find_or_create_user returns a mock user
        mock_user = MagicMock()
        mock_user.email = "alice@corp.com"
        mock_user.display_name = None
        mock_result_user = MagicMock()
        mock_result_user.scalar_one_or_none.return_value = mock_user

        # _load_internal_assignments: custom role assignments
        mock_result_custom_roles = MagicMock()
        mock_result_custom_roles.scalars.return_value.all.return_value = ["ssh-access"]

        # _load_internal_assignments: platform role assignments
        mock_result_platform_roles = MagicMock()
        mock_result_platform_roles.scalars.return_value.all.return_value = []

        # Set up execute to return different results for different queries
        mock_db.execute = AsyncMock(
            side_effect=[mock_result_user, mock_result_custom_roles, mock_result_platform_roles]
        )
        mock_db.flush = AsyncMock()
        mock_db.commit = AsyncMock()
        mock_db.refresh = AsyncMock()

        # Claims mapping rules: "groups" containing "bamf:viewer" → ["developer"]
        from bamf.config import ClaimsToRolesMapping

        rules = [ClaimsToRolesMapping(claim="groups", value="bamf:viewer", roles=["developer"])]

        with patch("bamf.services.sso_service.record_recent_user", new_callable=AsyncMock):
            result = await process_login(mock_db, base_identity, rules)

        # Source 1: IDP groups ["bamf:viewer"] → ["viewer"] after prefix stripping
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
    async def test_no_bamf_prefix_stripping_for_local(self, mock_db):
        """Local auth groups are NOT stripped (they shouldn't have bamf: prefix anyway)."""
        from bamf.services.sso_service import process_login

        # A hypothetical local identity that somehow has groups
        identity = AuthenticatedIdentity(
            provider_name="local",
            subject="bob@corp.com",
            email="bob@corp.com",
            display_name=None,
            groups=["admin"],  # No bamf: prefix for local
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

        # "admin" should pass through unchanged (no stripping for local)
        assert result.roles == ["admin"]
