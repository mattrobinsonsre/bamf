"""Tests for SAML identity provider connector.

Tests SAML settings construction, authorization request building,
callback handling, and attribute extraction.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from bamf.auth.connectors.saml import SAMLConnector
from bamf.config import SAMLProviderConfig

# ── Fixtures ──────────────────────────────────────────────────────────────


def _make_config(**overrides) -> SAMLProviderConfig:
    defaults = {
        "name": "test-saml",
        "metadata_url": "https://idp.example.com/metadata",
        "entity_id": "https://bamf.example.com",
        "acs_url": "https://bamf.example.com/api/v1/auth/saml/acs",
    }
    defaults.update(overrides)
    return SAMLProviderConfig(**defaults)


@pytest.fixture
def connector():
    return SAMLConnector(_make_config())


# ── Tests: Properties ────────────────────────────────────────────────────


class TestSAMLConnectorProperties:
    def test_name(self, connector):
        assert connector.name == "test-saml"

    def test_display_name_fallback(self, connector):
        assert connector.display_name == "test-saml"

    def test_display_name_custom(self):
        c = SAMLConnector(_make_config(display_name="Azure AD"))
        assert c.display_name == "Azure AD"

    def test_provider_type(self, connector):
        assert connector.provider_type == "saml"


# ── Tests: SAML Settings ─────────────────────────────────────────────────


class TestGetSAMLSettings:
    def test_builds_settings_dict(self, connector):
        settings = connector._get_saml_settings("https://bamf.example.com/api/v1/auth/saml/acs")

        assert settings["strict"] is True
        assert settings["sp"]["entityId"] == "https://bamf.example.com"
        assert (
            settings["sp"]["assertionConsumerService"]["url"]
            == "https://bamf.example.com/api/v1/auth/saml/acs"
        )
        assert (
            settings["sp"]["assertionConsumerService"]["binding"]
            == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        )
        assert settings["idp"] == {}


# ── Tests: Build Authorization Request ────────────────────────────────────


class TestBuildAuthorizationRequest:
    @pytest.mark.asyncio
    async def test_import_error_without_python3_saml(self, connector):
        with patch.dict("sys.modules", {"onelogin": None, "onelogin.saml2": None}):
            # Force reimport failure
            with patch(
                "bamf.auth.connectors.saml.SAMLConnector.build_authorization_request",
                side_effect=RuntimeError("python3-saml is required"),
            ):
                with pytest.raises(RuntimeError, match="python3-saml"):
                    await connector.build_authorization_request(
                        callback_url="https://bamf.example.com/api/v1/auth/saml/acs",
                        state="test-state",
                    )

    @pytest.mark.asyncio
    async def test_builds_authorization_request(self, connector):
        mock_metadata = {"idp": {"singleSignOnService": {"url": "https://idp.example.com/sso"}}}
        mock_auth = MagicMock()
        mock_auth.login.return_value = "https://idp.example.com/sso?SAMLRequest=xxx&RelayState=s1"

        with (
            patch(
                "onelogin.saml2.idp_metadata_parser.OneLogin_Saml2_IdPMetadataParser.parse_remote",
                return_value=mock_metadata,
            ),
            patch("onelogin.saml2.auth.OneLogin_Saml2_Auth", return_value=mock_auth),
        ):
            req = await connector.build_authorization_request(
                callback_url="https://bamf.example.com/api/v1/auth/saml/acs",
                state="test-state",
            )

        assert req.authorize_url == "https://idp.example.com/sso?SAMLRequest=xxx&RelayState=s1"
        assert req.state == "test-state"
        mock_auth.login.assert_called_once_with(return_to="test-state")


# ── Tests: Handle Callback ────────────────────────────────────────────────


class TestHandleCallback:
    @pytest.mark.asyncio
    async def test_successful_callback(self, connector):
        mock_metadata = {"idp": {}}
        mock_auth = MagicMock()
        mock_auth.get_errors.return_value = []
        mock_auth.is_authenticated.return_value = True
        mock_auth.get_nameid.return_value = "alice@example.com"
        mock_auth.get_attributes.return_value = {
            "email": ["alice@example.com"],
            "displayName": ["Alice"],
            "groups": ["developers", "admins"],
        }

        connector._idp_metadata = mock_metadata

        with patch("onelogin.saml2.auth.OneLogin_Saml2_Auth", return_value=mock_auth):
            identity = await connector.handle_callback(
                callback_url="https://bamf.example.com/api/v1/auth/saml/acs",
                saml_response="base64-encoded-response",
                relay_state="test-state",
            )

        assert identity.email == "alice@example.com"
        assert identity.display_name == "Alice"
        assert identity.subject == "alice@example.com"
        assert identity.provider_name == "test-saml"
        assert "developers" in identity.groups
        assert "admins" in identity.groups
        mock_auth.process_response.assert_called_once()

    @pytest.mark.asyncio
    async def test_callback_validation_errors(self, connector):
        mock_metadata = {"idp": {}}
        mock_auth = MagicMock()
        mock_auth.get_errors.return_value = ["invalid_response"]
        mock_auth.is_authenticated.return_value = False

        connector._idp_metadata = mock_metadata

        with (
            patch("onelogin.saml2.auth.OneLogin_Saml2_Auth", return_value=mock_auth),
            pytest.raises(ValueError, match="SAML validation failed"),
        ):
            await connector.handle_callback(
                callback_url="https://bamf.example.com/api/v1/auth/saml/acs",
                saml_response="bad-response",
            )

    @pytest.mark.asyncio
    async def test_callback_not_authenticated(self, connector):
        mock_metadata = {"idp": {}}
        mock_auth = MagicMock()
        mock_auth.get_errors.return_value = []
        mock_auth.is_authenticated.return_value = False

        connector._idp_metadata = mock_metadata

        with (
            patch("onelogin.saml2.auth.OneLogin_Saml2_Auth", return_value=mock_auth),
            pytest.raises(ValueError, match="SAML authentication failed"),
        ):
            await connector.handle_callback(
                callback_url="https://bamf.example.com/api/v1/auth/saml/acs",
                saml_response="response",
            )

    @pytest.mark.asyncio
    async def test_fallback_email_from_nameid(self, connector):
        """When email attributes are missing, falls back to nameId."""
        mock_metadata = {"idp": {}}
        mock_auth = MagicMock()
        mock_auth.get_errors.return_value = []
        mock_auth.is_authenticated.return_value = True
        mock_auth.get_nameid.return_value = "bob@example.com"
        mock_auth.get_attributes.return_value = {}

        connector._idp_metadata = mock_metadata

        with patch("onelogin.saml2.auth.OneLogin_Saml2_Auth", return_value=mock_auth):
            identity = await connector.handle_callback(
                callback_url="https://bamf.example.com/api/v1/auth/saml/acs",
                saml_response="response",
            )

        assert identity.email == "bob@example.com"

    @pytest.mark.asyncio
    async def test_schema_based_attribute_extraction(self, connector):
        """Tests extraction using schema-based attribute names."""
        mock_metadata = {"idp": {}}
        mock_auth = MagicMock()
        mock_auth.get_errors.return_value = []
        mock_auth.is_authenticated.return_value = True
        mock_auth.get_nameid.return_value = "user-123"
        mock_auth.get_attributes.return_value = {
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": [
                "carol@example.com"
            ],
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name": ["Carol"],
            "http://schemas.xmlsoap.org/claims/Group": ["sre-team"],
        }

        connector._idp_metadata = mock_metadata

        with patch("onelogin.saml2.auth.OneLogin_Saml2_Auth", return_value=mock_auth):
            identity = await connector.handle_callback(
                callback_url="https://bamf.example.com/api/v1/auth/saml/acs",
                saml_response="response",
            )

        assert identity.email == "carol@example.com"
        assert identity.display_name == "Carol"
        assert "sre-team" in identity.groups
