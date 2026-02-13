"""Tests for RBAC functionality."""

from bamf.services.rbac_service import _matches_labels, _merge_labels


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
