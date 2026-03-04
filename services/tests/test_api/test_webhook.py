"""Tests for webhook passthrough matching logic."""

from dataclasses import dataclass, field

from bamf.api.proxy.handler import _match_webhook


@dataclass
class FakeResource:
    """Minimal resource stub for testing webhook matching."""

    webhooks: list[dict] = field(default_factory=list)


class TestMatchWebhook:
    """Test _match_webhook() path/method/CIDR matching."""

    def test_exact_path_match(self):
        """Exact path match returns the webhook config."""
        resource = FakeResource(webhooks=[{"path": "/webhook", "methods": ["POST"]}])
        result = _match_webhook(resource, "POST", "/webhook", "10.0.0.1")
        assert result is not None
        assert result["path"] == "/webhook"

    def test_prefix_path_match(self):
        """Path prefix matches sub-paths."""
        resource = FakeResource(webhooks=[{"path": "/webhook/", "methods": ["POST"]}])
        result = _match_webhook(resource, "POST", "/webhook/foo/bar", "10.0.0.1")
        assert result is not None

    def test_trailing_slash_strict(self):
        """Trailing slash in config means path without trailing slash does NOT match."""
        resource = FakeResource(webhooks=[{"path": "/webhook/", "methods": ["POST"]}])
        result = _match_webhook(resource, "POST", "/webhook", "10.0.0.1")
        assert result is None

    def test_no_trailing_slash_matches_exact(self):
        """Path without trailing slash matches exact path."""
        resource = FakeResource(webhooks=[{"path": "/webhook", "methods": ["POST"]}])
        result = _match_webhook(resource, "POST", "/webhook", "10.0.0.1")
        assert result is not None

    def test_no_trailing_slash_matches_subpath(self):
        """Path without trailing slash also matches sub-paths (prefix match)."""
        resource = FakeResource(webhooks=[{"path": "/webhook", "methods": ["POST"]}])
        result = _match_webhook(resource, "POST", "/webhookx", "10.0.0.1")
        # /webhookx starts with /webhook — this is prefix matching
        # The plan says /webhook/ does NOT match /webhookx, but /webhook does
        # because it's strict prefix. To avoid matching /webhookx, use /webhook/
        assert result is not None

    def test_different_prefix_no_match(self):
        """Path that doesn't share prefix does not match."""
        resource = FakeResource(webhooks=[{"path": "/webhook/", "methods": ["POST"]}])
        result = _match_webhook(resource, "POST", "/api/webhook/", "10.0.0.1")
        assert result is None

    def test_method_mismatch(self):
        """Request method not in allowed list → no match."""
        resource = FakeResource(webhooks=[{"path": "/webhook", "methods": ["POST"]}])
        result = _match_webhook(resource, "GET", "/webhook", "10.0.0.1")
        assert result is None

    def test_method_case_insensitive(self):
        """Method comparison is case-insensitive."""
        resource = FakeResource(webhooks=[{"path": "/webhook", "methods": ["post"]}])
        result = _match_webhook(resource, "POST", "/webhook", "10.0.0.1")
        assert result is not None

    def test_multiple_methods(self):
        """Multiple methods allowed."""
        resource = FakeResource(webhooks=[{"path": "/webhook", "methods": ["POST", "PUT"]}])
        assert _match_webhook(resource, "POST", "/webhook", "10.0.0.1") is not None
        assert _match_webhook(resource, "PUT", "/webhook", "10.0.0.1") is not None
        assert _match_webhook(resource, "DELETE", "/webhook", "10.0.0.1") is None

    def test_source_cidr_allow(self):
        """Request from allowed CIDR passes."""
        resource = FakeResource(
            webhooks=[
                {
                    "path": "/webhook",
                    "methods": ["POST"],
                    "source_cidrs": ["140.82.112.0/20"],
                }
            ]
        )
        result = _match_webhook(resource, "POST", "/webhook", "140.82.115.10")
        assert result is not None

    def test_source_cidr_deny(self):
        """Request from non-allowed CIDR is rejected."""
        resource = FakeResource(
            webhooks=[
                {
                    "path": "/webhook",
                    "methods": ["POST"],
                    "source_cidrs": ["140.82.112.0/20"],
                }
            ]
        )
        result = _match_webhook(resource, "POST", "/webhook", "10.0.0.1")
        assert result is None

    def test_no_source_cidrs_allows_all(self):
        """No source_cidrs configured → all IPs allowed."""
        resource = FakeResource(
            webhooks=[{"path": "/webhook", "methods": ["POST"], "source_cidrs": []}]
        )
        result = _match_webhook(resource, "POST", "/webhook", "10.0.0.1")
        assert result is not None

    def test_empty_webhooks_no_match(self):
        """Empty webhooks list → no match."""
        resource = FakeResource(webhooks=[])
        result = _match_webhook(resource, "POST", "/webhook", "10.0.0.1")
        assert result is None

    def test_no_webhooks_attr_no_match(self):
        """Resource without webhooks attribute → no match."""

        class BareResource:
            pass

        result = _match_webhook(BareResource(), "POST", "/webhook", "10.0.0.1")
        assert result is None

    def test_multiple_webhooks_first_match_wins(self):
        """First matching webhook is returned."""
        resource = FakeResource(
            webhooks=[
                {"path": "/hooks/github", "methods": ["POST"]},
                {"path": "/hooks/", "methods": ["POST"]},
            ]
        )
        result = _match_webhook(resource, "POST", "/hooks/github", "10.0.0.1")
        assert result is not None
        assert result["path"] == "/hooks/github"

    def test_source_cidrs_no_client_ip(self):
        """CIDRs configured but no client IP → denied."""
        resource = FakeResource(
            webhooks=[
                {
                    "path": "/webhook",
                    "methods": ["POST"],
                    "source_cidrs": ["10.0.0.0/8"],
                }
            ]
        )
        result = _match_webhook(resource, "POST", "/webhook", None)
        assert result is None

    def test_multiple_cidrs(self):
        """Multiple CIDRs — match on any."""
        resource = FakeResource(
            webhooks=[
                {
                    "path": "/webhook",
                    "methods": ["POST"],
                    "source_cidrs": ["140.82.112.0/20", "185.199.108.0/22"],
                }
            ]
        )
        assert _match_webhook(resource, "POST", "/webhook", "140.82.115.1") is not None
        assert _match_webhook(resource, "POST", "/webhook", "185.199.109.1") is not None
        assert _match_webhook(resource, "POST", "/webhook", "10.0.0.1") is None
