"""Tests for claims-to-roles mapper."""

from bamf.auth.claims_mapper import map_claims_to_roles
from bamf.config import ClaimsToRolesMapping


class TestMapClaimsToRoles:
    """Test claims-to-roles mapping logic."""

    def test_string_claim_match(self):
        """Test matching a string claim value."""
        claims = {"role": "platform-eng"}
        rules = [
            ClaimsToRolesMapping(claim="role", value="platform-eng", roles=["admin", "ssh-access"]),
        ]

        result = map_claims_to_roles(claims, rules)
        assert result == ["admin", "ssh-access"]

    def test_list_claim_match(self):
        """Test matching a value in a list claim."""
        claims = {"groups": ["engineering", "devops", "platform"]}
        rules = [
            ClaimsToRolesMapping(claim="groups", value="devops", roles=["admin"]),
        ]

        result = map_claims_to_roles(claims, rules)
        assert result == ["admin"]

    def test_no_match(self):
        """Test no matching claims."""
        claims = {"role": "marketing"}
        rules = [
            ClaimsToRolesMapping(claim="role", value="platform-eng", roles=["admin"]),
        ]

        result = map_claims_to_roles(claims, rules)
        assert result == []

    def test_missing_claim(self):
        """Test claim not present in claims dict."""
        claims = {"email": "user@example.com"}
        rules = [
            ClaimsToRolesMapping(claim="role", value="admin", roles=["admin"]),
        ]

        result = map_claims_to_roles(claims, rules)
        assert result == []

    def test_multiple_rules_deduplicated(self):
        """Test multiple rules matching produce deduplicated roles."""
        claims = {
            "role": "platform-eng",
            "groups": ["engineering"],
        }
        rules = [
            ClaimsToRolesMapping(claim="role", value="platform-eng", roles=["admin", "ssh-access"]),
            ClaimsToRolesMapping(
                claim="groups", value="engineering", roles=["ssh-access", "k8s-access"]
            ),
        ]

        result = map_claims_to_roles(claims, rules)
        assert result == ["admin", "k8s-access", "ssh-access"]

    def test_empty_rules(self):
        """Test empty rules list."""
        claims = {"role": "admin"}
        result = map_claims_to_roles(claims, [])
        assert result == []

    def test_empty_claims(self):
        """Test empty claims dict."""
        rules = [
            ClaimsToRolesMapping(claim="role", value="admin", roles=["admin"]),
        ]
        result = map_claims_to_roles({}, rules)
        assert result == []

    def test_list_claim_no_match(self):
        """Test list claim where rule value is not in the list."""
        claims = {"groups": ["engineering", "devops"]}
        rules = [
            ClaimsToRolesMapping(claim="groups", value="marketing", roles=["admin"]),
        ]

        result = map_claims_to_roles(claims, rules)
        assert result == []
