"""Tests for OIDC identity provider connector.

Tests discovery, authorization URL building, token exchange,
ID token validation, userinfo merging, and role prefix stripping.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bamf.auth.connectors.oidc import OIDCConnector, _strip_role_prefixes
from bamf.config import OIDCProviderConfig

# ── Fixtures ──────────────────────────────────────────────────────────────

DISCOVERY_DOC = {
    "issuer": "https://idp.example.com/",
    "authorization_endpoint": "https://idp.example.com/authorize",
    "token_endpoint": "https://idp.example.com/oauth/token",
    "userinfo_endpoint": "https://idp.example.com/userinfo",
    "jwks_uri": "https://idp.example.com/.well-known/jwks.json",
}


def _make_config(**overrides) -> OIDCProviderConfig:
    defaults = {
        "name": "test-oidc",
        "issuer_url": "https://idp.example.com/",
        "client_id": "test-client-id",
        "client_secret": "test-client-secret",
        "scopes": ["openid", "profile", "email"],
        "groups_claim": "groups",
    }
    defaults.update(overrides)
    return OIDCProviderConfig(**defaults)


@pytest.fixture
def connector():
    return OIDCConnector(_make_config())


# ── Tests: Properties ────────────────────────────────────────────────────


class TestOIDCConnectorProperties:
    def test_name(self, connector):
        assert connector.name == "test-oidc"

    def test_display_name_fallback(self, connector):
        assert connector.display_name == "test-oidc"

    def test_display_name_custom(self):
        c = OIDCConnector(_make_config(display_name="My IDP"))
        assert c.display_name == "My IDP"

    def test_provider_type(self, connector):
        assert connector.provider_type == "oidc"


# ── Tests: Build Authorization Request ────────────────────────────────────


class TestBuildAuthorizationRequest:
    @pytest.mark.asyncio
    async def test_builds_authorize_url(self):
        connector = OIDCConnector(_make_config())
        # Pre-populate discovery to avoid HTTP call
        connector._discovery = DISCOVERY_DOC

        req = await connector.build_authorization_request(
            callback_url="https://bamf.example.com/auth/callback",
            state="test-state-123",
        )

        assert "https://idp.example.com/authorize?" in req.authorize_url
        assert "client_id=test-client-id" in req.authorize_url
        assert "redirect_uri=https" in req.authorize_url
        assert "response_type=code" in req.authorize_url
        assert "scope=openid+profile+email" in req.authorize_url
        assert "state=test-state-123" in req.authorize_url
        assert req.state == "test-state-123"
        assert req.nonce is not None

    @pytest.mark.asyncio
    async def test_includes_audience_when_configured(self):
        connector = OIDCConnector(_make_config(audience="https://api.example.com"))
        connector._discovery = DISCOVERY_DOC

        req = await connector.build_authorization_request(
            callback_url="https://bamf.example.com/auth/callback",
            state="s1",
        )
        assert "audience=https" in req.authorize_url

    @pytest.mark.asyncio
    async def test_no_audience_when_empty(self):
        connector = OIDCConnector(_make_config(audience=""))
        connector._discovery = DISCOVERY_DOC

        req = await connector.build_authorization_request(
            callback_url="https://bamf.example.com/auth/callback",
            state="s1",
        )
        assert "audience" not in req.authorize_url


# ── Tests: Handle Callback ────────────────────────────────────────────────


class TestHandleCallback:
    @pytest.mark.asyncio
    async def test_successful_callback(self):
        connector = OIDCConnector(_make_config())
        connector._discovery = DISCOVERY_DOC

        # Mock JWKS
        mock_jwks = MagicMock()
        connector._jwks = mock_jwks

        # Mock token exchange
        mock_token_response = {
            "id_token": "fake-id-token",
            "access_token": "fake-access-token",
        }

        # Mock decoded claims
        mock_claims = {
            "sub": "user-123",
            "email": "alice@example.com",
            "name": "Alice",
            "groups": ["developers"],
            "exp": 1900000000,
        }

        with (
            patch("bamf.auth.connectors.oidc.httpx.AsyncClient") as mock_http,
            patch("bamf.auth.connectors.oidc.authlib_jwt") as mock_jwt,
        ):
            # Token exchange response — use MagicMock because httpx
            # Response.json() and .raise_for_status() are synchronous.
            mock_resp = MagicMock()
            mock_resp.json.return_value = mock_token_response
            mock_resp.raise_for_status = MagicMock()
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.get.return_value = MagicMock(
                json=MagicMock(return_value={}),
                raise_for_status=MagicMock(),
            )
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock()
            mock_http.return_value = mock_client

            # JWT decode — use side_effect for magic methods so MagicMock
            # dispatches correctly (class-level __getitem__ → instance side_effect).
            decoded = MagicMock()
            decoded.__getitem__.side_effect = mock_claims.__getitem__
            decoded.get.side_effect = mock_claims.get
            decoded.__contains__.side_effect = mock_claims.__contains__
            decoded.__iter__.side_effect = mock_claims.__iter__
            decoded.keys.side_effect = mock_claims.keys
            decoded.validate.return_value = None
            mock_jwt.decode.return_value = decoded

            identity = await connector.handle_callback(
                callback_url="https://bamf.example.com/auth/callback",
                code="auth-code-123",
            )

        assert identity.email == "alice@example.com"
        assert identity.subject == "user-123"
        assert identity.display_name == "Alice"
        assert identity.provider_name == "test-oidc"

    @pytest.mark.asyncio
    async def test_no_id_token_raises(self):
        connector = OIDCConnector(_make_config())
        connector._discovery = DISCOVERY_DOC

        with patch("bamf.auth.connectors.oidc.httpx.AsyncClient") as mock_http:
            # Use MagicMock because httpx Response.json() is synchronous
            mock_resp = MagicMock()
            mock_resp.json.return_value = {"access_token": "at"}
            mock_resp.raise_for_status = MagicMock()
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_resp
            mock_client.__aenter__ = AsyncMock(return_value=mock_client)
            mock_client.__aexit__ = AsyncMock()
            mock_http.return_value = mock_client

            with pytest.raises(ValueError, match="No id_token"):
                await connector.handle_callback(
                    callback_url="https://bamf.example.com/auth/callback",
                    code="auth-code",
                )


# ── Tests: Userinfo Endpoint ──────────────────────────────────────────────


class TestFetchUserinfo:
    @pytest.mark.asyncio
    async def test_returns_empty_without_access_token(self):
        connector = OIDCConnector(_make_config())
        connector._discovery = DISCOVERY_DOC
        result = await connector._fetch_userinfo("")
        assert result == {}

    @pytest.mark.asyncio
    async def test_returns_empty_without_endpoint(self):
        connector = OIDCConnector(_make_config())
        connector._discovery = {**DISCOVERY_DOC, "userinfo_endpoint": None}
        result = await connector._fetch_userinfo("token")
        assert result == {}

    @pytest.mark.asyncio
    async def test_returns_empty_on_error(self):
        connector = OIDCConnector(_make_config())
        no_userinfo = dict(DISCOVERY_DOC)
        del no_userinfo["userinfo_endpoint"]
        connector._discovery = no_userinfo
        result = await connector._fetch_userinfo("token")
        assert result == {}


# ── Tests: Access Token Permissions ──────────────────────────────────────


class TestExtractAccessTokenPermissions:
    def test_returns_empty_without_audience(self):
        connector = OIDCConnector(_make_config(audience=""))
        result = connector._extract_access_token_permissions("token", MagicMock(), "iss")
        assert result == []

    def test_returns_empty_without_token(self):
        connector = OIDCConnector(_make_config(audience="https://api.example.com"))
        result = connector._extract_access_token_permissions("", MagicMock(), "iss")
        assert result == []

    def test_extracts_permissions(self):
        connector = OIDCConnector(_make_config(audience="https://api.example.com"))
        mock_jwks = MagicMock()

        with patch("bamf.auth.connectors.oidc.authlib_jwt") as mock_jwt:
            decoded = MagicMock()
            decoded.get.return_value = ["read:users", "write:users"]
            decoded.validate.return_value = None
            mock_jwt.decode.return_value = decoded

            result = connector._extract_access_token_permissions(
                "jwt-token", mock_jwks, "https://idp.example.com/"
            )

        assert result == ["read:users", "write:users"]


# ── Tests: Role Prefix Stripping ─────────────────────────────────────────


class TestStripRolePrefixes:
    def test_strip_bamf_prefix(self):
        result = _strip_role_prefixes(["bamf:admin", "bamf:developer"], ["bamf:"])
        assert result == ["admin", "developer"]

    def test_strip_multiple_prefixes(self):
        result = _strip_role_prefixes(
            ["bamf:admin", "bamf-sre", "other"],
            ["bamf:", "bamf-"],
        )
        assert result == ["admin", "sre", "other"]

    def test_no_prefixes_passthrough(self):
        result = _strip_role_prefixes(["admin", "dev"], [])
        assert result == ["admin", "dev"]

    def test_unmatched_groups_passthrough(self):
        result = _strip_role_prefixes(["external-group"], ["bamf:"])
        assert result == ["external-group"]

    def test_first_prefix_wins(self):
        result = _strip_role_prefixes(["bamf:bamf-admin"], ["bamf:", "bamf-"])
        assert result == ["bamf-admin"]
