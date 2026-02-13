"""Tests for SSO connector registry and provider listing."""

from unittest.mock import patch

from bamf.auth.connectors import (
    _connectors,
    get_connector,
    get_default_connector,
    init_connectors,
    list_connectors,
)
from bamf.auth.sso import AuthenticatedIdentity, AuthorizationRequest, SSOConnector
from bamf.config import SSOConfig


class MockOIDCConnector(SSOConnector):
    """Mock OIDC connector for testing."""

    def __init__(self, name: str) -> None:
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    @property
    def provider_type(self) -> str:
        return "oidc"

    async def build_authorization_request(self, callback_url, state):
        return AuthorizationRequest(
            authorize_url=f"https://idp.example.com/authorize?state={state}",
            state=state,
            nonce="test-nonce",
        )

    async def handle_callback(self, callback_url, **kwargs):
        return AuthenticatedIdentity(
            provider_name=self._name,
            subject="user-123",
            email="user@example.com",
            display_name="Test User",
            groups=["engineering"],
            raw_claims={"sub": "user-123", "email": "user@example.com"},
        )


class TestConnectorRegistry:
    """Test connector registry functions."""

    def setup_method(self):
        """Clear registry before each test."""
        _connectors.clear()

    def test_register_and_get_connector(self):
        """Test registering and retrieving a connector."""
        connector = MockOIDCConnector("test-idp")
        _connectors["test-idp"] = connector

        result = get_connector("test-idp")
        assert result is not None
        assert result.name == "test-idp"
        assert result.provider_type == "oidc"

    def test_get_nonexistent_connector(self):
        """Test getting a connector that doesn't exist."""
        result = get_connector("nonexistent")
        assert result is None

    def test_list_connectors(self):
        """Test listing all connectors."""
        _connectors["auth0"] = MockOIDCConnector("auth0")
        _connectors["okta"] = MockOIDCConnector("okta")

        result = list_connectors()
        assert len(result) == 2
        names = {p["name"] for p in result}
        assert names == {"auth0", "okta"}

    def test_list_connectors_empty(self):
        """Test listing with no connectors."""
        result = list_connectors()
        assert result == []

    def test_get_default_connector_configured(self):
        """Test getting the default connector when configured."""
        _connectors["auth0"] = MockOIDCConnector("auth0")
        _connectors["okta"] = MockOIDCConnector("okta")

        with patch("bamf.auth.connectors.settings") as mock_settings:
            mock_settings.auth.sso.default_provider = "okta"
            result = get_default_connector()

        assert result is not None
        assert result.name == "okta"

    def test_get_default_connector_fallback_to_first(self):
        """Test default connector falls back to first registered."""
        _connectors["auth0"] = MockOIDCConnector("auth0")

        with patch("bamf.auth.connectors.settings") as mock_settings:
            mock_settings.auth.sso.default_provider = ""
            result = get_default_connector()

        assert result is not None
        assert result.name == "auth0"

    def test_get_default_connector_none(self):
        """Test default connector when none configured."""
        with patch("bamf.auth.connectors.settings") as mock_settings:
            mock_settings.auth.sso.default_provider = ""
            result = get_default_connector()

        assert result is None

    def test_init_connectors_no_providers_local_disabled(self):
        """Test init with no providers and local auth disabled."""
        with patch("bamf.auth.connectors.settings") as mock_settings:
            mock_settings.auth.sso = SSOConfig()
            mock_settings.auth.local_enabled = False
            init_connectors()

        assert len(_connectors) == 0

    def test_init_connectors_local_enabled(self):
        """Test init registers local connector when local_enabled."""
        with patch("bamf.auth.connectors.settings") as mock_settings:
            mock_settings.auth.sso = SSOConfig()
            mock_settings.auth.local_enabled = True
            init_connectors()

        assert "local" in _connectors
        assert _connectors["local"].provider_type == "local"

    def test_init_connectors_clears_previous(self):
        """Test init clears previously registered connectors."""
        _connectors["old"] = MockOIDCConnector("old")

        with patch("bamf.auth.connectors.settings") as mock_settings:
            mock_settings.auth.sso = SSOConfig()
            mock_settings.auth.local_enabled = False
            init_connectors()

        assert "old" not in _connectors


class TestProviderEndpoint:
    """Test the /auth/providers endpoint response format."""

    def test_provider_info_format(self):
        """Test that list_connectors returns correct format."""
        _connectors.clear()
        _connectors["auth0"] = MockOIDCConnector("auth0")

        result = list_connectors()
        assert result == [{"name": "auth0", "type": "oidc"}]
