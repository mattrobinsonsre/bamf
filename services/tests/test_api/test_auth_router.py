"""Tests for auth endpoints.

Tests /api/v1/auth endpoints for provider listing, PKCE verification,
session management, CA certificate retrieval, local authorize, token
exchange, logout-all, admin session revocation, OIDC/SAML authorize
redirect, OIDC callback, SAML ACS, session cookie, external SSO
enforcement, session TTL computation, and claims rules resolution.
"""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI, HTTPException
from httpx import ASGITransport, AsyncClient

from bamf.api.dependencies import get_current_session, require_admin
from bamf.api.routers.auth import _verify_pkce, router
from bamf.auth.auth_state import AuthCode
from bamf.auth.sessions import Session
from bamf.db.session import get_db
from bamf.services.sso_service import LoginResult

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
    token="admin-token",
)

USER_SESSION = Session(
    email="user@example.com",
    display_name="User",
    roles=[],
    provider_name="local",
    created_at=_NOW,
    expires_at=_NOW,
    last_active_at=_NOW,
    token="test-token",
)


@pytest.fixture
def auth_app():
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")

    async def override_admin() -> Session:
        return ADMIN_SESSION

    async def override_session() -> Session:
        return USER_SESSION

    app.dependency_overrides[require_admin] = override_admin
    app.dependency_overrides[get_current_session] = override_session
    return app


@pytest.fixture
async def auth_client(auth_app):
    async with AsyncClient(
        transport=ASGITransport(app=auth_app),
        base_url="http://test",
    ) as client:
        yield client


# ── Tests: Provider listing ──────────────────────────────────────────────


class TestListProviders:
    @pytest.mark.asyncio
    async def test_returns_providers(self, auth_client):
        mock_connectors = [
            {"name": "local", "type": "local", "display_name": "Local"},
            {"name": "auth0", "type": "oidc", "display_name": "Auth0"},
        ]
        with (
            patch("bamf.api.routers.auth.list_connectors", return_value=mock_connectors),
            patch("bamf.api.routers.auth.settings") as mock_settings,
        ):
            mock_settings.auth.sso.default_provider = "local"
            mock_settings.api_prefix = "/api/v1"
            resp = await auth_client.get("/api/v1/auth/providers")

        assert resp.status_code == 200
        data = resp.json()
        assert len(data["providers"]) == 2
        assert data["providers"][0]["name"] == "local"
        assert data["default_provider"] == "local"

    @pytest.mark.asyncio
    async def test_no_default_provider(self, auth_client):
        with (
            patch("bamf.api.routers.auth.list_connectors", return_value=[]),
            patch("bamf.api.routers.auth.settings") as mock_settings,
        ):
            mock_settings.auth.sso.default_provider = ""
            mock_settings.api_prefix = "/api/v1"
            resp = await auth_client.get("/api/v1/auth/providers")

        assert resp.status_code == 200
        assert resp.json()["default_provider"] is None


# ── Tests: Authorize ─────────────────────────────────────────────────────


class TestAuthorize:
    @pytest.mark.asyncio
    async def test_invalid_response_type(self, auth_client):
        resp = await auth_client.get(
            "/api/v1/auth/authorize",
            params={
                "redirect_uri": "http://localhost/callback",
                "code_challenge": "test",
                "state": "test",
                "response_type": "token",
            },
        )
        assert resp.status_code == 400
        assert "response_type=code" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_invalid_challenge_method(self, auth_client):
        resp = await auth_client.get(
            "/api/v1/auth/authorize",
            params={
                "redirect_uri": "http://localhost/callback",
                "code_challenge": "test",
                "state": "test",
                "response_type": "code",
                "code_challenge_method": "plain",
            },
        )
        assert resp.status_code == 400
        assert "S256" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_provider_not_found(self, auth_client):
        with patch("bamf.api.routers.auth.get_connector", return_value=None):
            resp = await auth_client.get(
                "/api/v1/auth/authorize",
                params={
                    "redirect_uri": "http://localhost/callback",
                    "code_challenge": "test",
                    "state": "test",
                    "response_type": "code",
                    "provider": "nonexistent",
                },
            )
        assert resp.status_code == 400
        assert "Provider not found" in resp.json()["detail"]


# ── Tests: CA Certificate ────────────────────────────────────────────────


class TestGetCACertificate:
    @pytest.mark.asyncio
    async def test_returns_ca_pem(self, auth_client):
        fake_ca = MagicMock()
        fake_ca.ca_cert_pem = "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n"
        with patch("bamf.auth.ca.get_ca", return_value=fake_ca):
            resp = await auth_client.get("/api/v1/auth/ca/public")

        assert resp.status_code == 200
        data = resp.json()
        assert "BEGIN CERTIFICATE" in data["certificate"]


# ── Tests: PKCE Verification ─────────────────────────────────────────────


class TestVerifyPKCE:
    def test_valid_pkce(self):
        import base64
        import hashlib

        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        h = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(h).rstrip(b"=").decode()

        assert _verify_pkce(verifier, challenge, "S256") is True

    def test_invalid_pkce(self):
        assert _verify_pkce("wrong-verifier", "wrong-challenge", "S256") is False

    def test_unsupported_method(self):
        assert _verify_pkce("verifier", "challenge", "plain") is False


# ── Tests: Session Management ────────────────────────────────────────────


class TestListSessions:
    @pytest.mark.asyncio
    async def test_list_own_sessions(self, auth_client):
        # _require_session calls get_session from bamf.auth.sessions which
        # calls get_redis_client(). Mock get_session to return our user session
        # and list_user_sessions to return session objects.
        mock_session_obj = Session(
            email="user@example.com",
            display_name="User",
            roles=[],
            provider_name="local",
            created_at=_NOW,
            expires_at=_NOW,
            last_active_at=_NOW,
            token="test-token",
        )
        with (
            patch(
                "bamf.api.routers.auth.get_session",
                new_callable=AsyncMock,
                return_value=mock_session_obj,
            ),
            patch(
                "bamf.api.routers.auth.list_user_sessions",
                new_callable=AsyncMock,
                return_value=[mock_session_obj],
            ),
        ):
            resp = await auth_client.get(
                "/api/v1/auth/sessions",
                headers={"Authorization": "Bearer test-token"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["email"] == "user@example.com"
        assert data[0]["is_current"] is True


class TestListAllSessions:
    @pytest.mark.asyncio
    async def test_list_all_requires_admin(self, auth_client):
        admin_session_obj = Session(
            email="admin@example.com",
            display_name="Admin",
            roles=["admin"],
            provider_name="local",
            created_at=_NOW,
            expires_at=_NOW,
            last_active_at=_NOW,
            token="admin-token",
        )
        with (
            patch(
                "bamf.api.routers.auth.get_session",
                new_callable=AsyncMock,
                return_value=admin_session_obj,
            ),
            patch(
                "bamf.api.routers.auth.list_all_sessions",
                new_callable=AsyncMock,
                return_value=[],
            ),
        ):
            resp = await auth_client.get(
                "/api/v1/auth/sessions/all",
                headers={"Authorization": "Bearer admin-token"},
            )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_list_all_forbidden_for_non_admin(self, auth_client):
        non_admin_session = Session(
            email="user@example.com",
            display_name="User",
            roles=[],
            provider_name="local",
            created_at=_NOW,
            expires_at=_NOW,
            last_active_at=_NOW,
            token="user-token",
        )
        with patch(
            "bamf.api.routers.auth.get_session",
            new_callable=AsyncMock,
            return_value=non_admin_session,
        ):
            resp = await auth_client.get(
                "/api/v1/auth/sessions/all",
                headers={"Authorization": "Bearer user-token"},
            )
        assert resp.status_code == 403


# ── Tests: Logout ────────────────────────────────────────────────────────


class TestLogout:
    @pytest.mark.asyncio
    async def test_logout_revokes_session(self, auth_client):
        mock_session_obj = Session(
            email="user@example.com",
            display_name="User",
            roles=[],
            provider_name="local",
            created_at=_NOW,
            expires_at=_NOW,
            last_active_at=_NOW,
            token="test-token",
        )
        with (
            patch(
                "bamf.api.routers.auth.get_session",
                new_callable=AsyncMock,
                return_value=mock_session_obj,
            ),
            patch(
                "bamf.api.routers.auth.revoke_session",
                new_callable=AsyncMock,
            ),
            patch("bamf.api.routers.auth.settings") as mock_settings,
        ):
            mock_settings.tunnel_domain = ""
            resp = await auth_client.post(
                "/api/v1/auth/logout",
                headers={"Authorization": "Bearer test-token"},
            )
        assert resp.status_code == 200
        assert resp.json()["status"] == "logged_out"


# ── Tests: Local Authorize ──────────────────────────────────────────────


class TestLocalAuthorize:
    """Tests for POST /auth/local/authorize (JSON-based local login + PKCE)."""

    @pytest.fixture
    def local_app(self):
        """App fixture with get_db dependency overridden to a mock session."""
        app = FastAPI()
        app.include_router(router, prefix="/api/v1")

        async def override_db():
            yield AsyncMock()

        app.dependency_overrides[get_db] = override_db
        return app

    @pytest.fixture
    async def local_client(self, local_app):
        async with AsyncClient(
            transport=ASGITransport(app=local_app),
            base_url="http://test",
        ) as client:
            yield client

    @pytest.mark.asyncio
    async def test_valid_login(self, local_client):
        """Successful local login returns a bamf_code and the client state."""
        mock_connector = AsyncMock()
        mock_connector.name = "local"
        mock_identity = MagicMock(
            provider_name="local",
            email="user@example.com",
            display_name="User",
            groups=[],
        )
        mock_connector.handle_callback.return_value = mock_identity

        login_result = LoginResult(
            email="user@example.com",
            display_name="User",
            roles=["developer"],
            provider_name="local",
            kubernetes_groups=[],
        )

        with (
            patch("bamf.api.routers.auth.get_connector", return_value=mock_connector),
            patch(
                "bamf.api.routers.auth.process_login",
                new_callable=AsyncMock,
                return_value=login_result,
            ),
            patch("bamf.api.routers.auth.generate_code", return_value="test-code-123"),
            patch("bamf.api.routers.auth.store_auth_code", new_callable=AsyncMock),
            patch("bamf.api.routers.auth.log_audit_event", new_callable=AsyncMock),
            patch("bamf.api.routers.auth.settings") as mock_settings,
        ):
            mock_settings.auth.require_external_sso_for_roles = []
            mock_settings.auth.sso.oidc = []
            mock_settings.auth.sso.saml = []
            resp = await local_client.post(
                "/api/v1/auth/local/authorize",
                json={
                    "email": "user@example.com",
                    "password": "correct-password",
                    "code_challenge": "test-challenge",
                    "code_challenge_method": "S256",
                    "state": "client-state-xyz",
                },
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["code"] == "test-code-123"
        assert data["state"] == "client-state-xyz"

    @pytest.mark.asyncio
    async def test_invalid_password(self, local_client):
        """Invalid password causes connector to raise ValueError → 401."""
        mock_connector = AsyncMock()
        mock_connector.name = "local"
        mock_connector.handle_callback.side_effect = ValueError("Invalid credentials")

        with (
            patch("bamf.api.routers.auth.get_connector", return_value=mock_connector),
            patch("bamf.api.routers.auth.log_audit_event", new_callable=AsyncMock),
            patch("bamf.api.routers.auth.settings") as mock_settings,
        ):
            mock_settings.auth.sso.oidc = []
            mock_settings.auth.sso.saml = []
            resp = await local_client.post(
                "/api/v1/auth/local/authorize",
                json={
                    "email": "user@example.com",
                    "password": "wrong-password",
                    "code_challenge": "test-challenge",
                    "code_challenge_method": "S256",
                    "state": "client-state",
                },
            )

        assert resp.status_code == 401
        assert "Invalid credentials" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_user_not_found(self, local_client):
        """User not found causes connector to raise ValueError → 401."""
        mock_connector = AsyncMock()
        mock_connector.name = "local"
        mock_connector.handle_callback.side_effect = ValueError("Invalid credentials")

        with (
            patch("bamf.api.routers.auth.get_connector", return_value=mock_connector),
            patch("bamf.api.routers.auth.log_audit_event", new_callable=AsyncMock),
            patch("bamf.api.routers.auth.settings") as mock_settings,
        ):
            mock_settings.auth.sso.oidc = []
            mock_settings.auth.sso.saml = []
            resp = await local_client.post(
                "/api/v1/auth/local/authorize",
                json={
                    "email": "nonexistent@example.com",
                    "password": "any-password",
                    "code_challenge": "test-challenge",
                    "code_challenge_method": "S256",
                    "state": "client-state",
                },
            )

        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_inactive_user(self, local_client):
        """Inactive user causes connector to raise ValueError → 401.

        The LocalConnector raises ValueError("User account is disabled")
        for inactive users, which the router catches in the same try/except
        block as invalid credentials and returns 401.
        """
        mock_connector = AsyncMock()
        mock_connector.name = "local"
        mock_connector.handle_callback.side_effect = ValueError("User account is disabled")

        with (
            patch("bamf.api.routers.auth.get_connector", return_value=mock_connector),
            patch("bamf.api.routers.auth.log_audit_event", new_callable=AsyncMock),
            patch("bamf.api.routers.auth.settings") as mock_settings,
        ):
            mock_settings.auth.sso.oidc = []
            mock_settings.auth.sso.saml = []
            resp = await local_client.post(
                "/api/v1/auth/local/authorize",
                json={
                    "email": "disabled@example.com",
                    "password": "correct-password",
                    "code_challenge": "test-challenge",
                    "code_challenge_method": "S256",
                    "state": "client-state",
                },
            )

        assert resp.status_code == 401
        assert "disabled" in resp.json()["detail"]


# ── Tests: Token Exchange ───────────────────────────────────────────────


class TestExchangeToken:
    """Tests for POST /auth/token (exchange bamf_code + PKCE for session)."""

    @pytest.mark.asyncio
    async def test_valid_exchange(self, auth_client):
        """Valid code + PKCE verifier returns session token, email, roles."""
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        h = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(h).rstrip(b"=").decode()

        auth_code = AuthCode(
            email="alice@example.com",
            roles=["developer"],
            provider_name="local",
            code_challenge=challenge,
            code_challenge_method="S256",
            kubernetes_groups=["view"],
        )

        mock_session = Session(
            email="alice@example.com",
            display_name="Alice",
            roles=["developer"],
            provider_name="local",
            created_at=_NOW,
            expires_at=_NOW,
            last_active_at=_NOW,
            token="new-session-token",
        )

        with (
            patch(
                "bamf.api.routers.auth.consume_auth_code",
                new_callable=AsyncMock,
                return_value=auth_code,
            ),
            patch(
                "bamf.api.routers.auth.create_session",
                new_callable=AsyncMock,
                return_value=mock_session,
            ),
            patch("bamf.api.routers.auth.settings") as mock_settings,
        ):
            mock_settings.tunnel_domain = ""
            resp = await auth_client.post(
                "/api/v1/auth/token",
                data={
                    "grant_type": "authorization_code",
                    "code": "test-bamf-code",
                    "code_verifier": verifier,
                },
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["session_token"] == "new-session-token"
        assert data["email"] == "alice@example.com"
        assert data["roles"] == ["developer"]

    @pytest.mark.asyncio
    async def test_invalid_code(self, auth_client):
        """Non-existent or expired code returns 401."""
        with patch(
            "bamf.api.routers.auth.consume_auth_code",
            new_callable=AsyncMock,
            return_value=None,
        ):
            resp = await auth_client.post(
                "/api/v1/auth/token",
                data={
                    "grant_type": "authorization_code",
                    "code": "invalid-code",
                    "code_verifier": "any-verifier",
                },
            )

        assert resp.status_code == 401
        assert "Invalid or expired" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_invalid_pkce_verifier(self, auth_client):
        """Valid code but wrong PKCE verifier returns 401."""
        auth_code = AuthCode(
            email="alice@example.com",
            roles=[],
            provider_name="local",
            code_challenge="the-real-challenge",
            code_challenge_method="S256",
        )

        with patch(
            "bamf.api.routers.auth.consume_auth_code",
            new_callable=AsyncMock,
            return_value=auth_code,
        ):
            resp = await auth_client.post(
                "/api/v1/auth/token",
                data={
                    "grant_type": "authorization_code",
                    "code": "valid-code",
                    "code_verifier": "wrong-verifier",
                },
            )

        assert resp.status_code == 401
        assert "PKCE" in resp.json()["detail"]


# ── Tests: Logout All ──────────────────────────────────────────────────


class TestLogoutAll:
    """Tests for POST /auth/logout/all (revoke all sessions for current user)."""

    @pytest.mark.asyncio
    async def test_logout_all_revokes_all_sessions(self, auth_client):
        """Logout all revokes every session for the current user."""
        mock_session_obj = Session(
            email="user@example.com",
            display_name="User",
            roles=[],
            provider_name="local",
            created_at=_NOW,
            expires_at=_NOW,
            last_active_at=_NOW,
            token="test-token",
        )
        mock_revoke = AsyncMock(return_value=3)

        with (
            patch(
                "bamf.api.routers.auth.get_session",
                new_callable=AsyncMock,
                return_value=mock_session_obj,
            ),
            patch(
                "bamf.api.routers.auth.revoke_all_user_sessions",
                mock_revoke,
            ),
            patch("bamf.api.routers.auth.settings") as mock_settings,
        ):
            mock_settings.tunnel_domain = ""
            resp = await auth_client.post(
                "/api/v1/auth/logout/all",
                headers={"Authorization": "Bearer test-token"},
            )

        assert resp.status_code == 200
        assert resp.json()["revoked"] == 3
        mock_revoke.assert_called_once_with("user@example.com")


# ── Tests: Revoke User Sessions (admin) ────────────────────────────────


class TestRevokeUserSessions:
    """Tests for DELETE /auth/sessions/user/{email} (admin revoke)."""

    @pytest.mark.asyncio
    async def test_revoke_user_sessions_admin_only(self, auth_client):
        """Admin can revoke all sessions for a given user."""
        admin_session_obj = Session(
            email="admin@example.com",
            display_name="Admin",
            roles=["admin"],
            provider_name="local",
            created_at=_NOW,
            expires_at=_NOW,
            last_active_at=_NOW,
            token="admin-token",
        )
        mock_revoke = AsyncMock(return_value=2)

        with (
            patch(
                "bamf.api.routers.auth.get_session",
                new_callable=AsyncMock,
                return_value=admin_session_obj,
            ),
            patch(
                "bamf.api.routers.auth.revoke_all_user_sessions",
                mock_revoke,
            ),
        ):
            resp = await auth_client.delete(
                "/api/v1/auth/sessions/user/target@example.com",
                headers={"Authorization": "Bearer admin-token"},
            )

        assert resp.status_code == 200
        assert resp.json()["revoked"] == 2
        mock_revoke.assert_called_once_with("target@example.com")

    @pytest.mark.asyncio
    async def test_revoke_user_sessions_forbidden(self, auth_client):
        """Non-admin users get 403 when trying to revoke another user's sessions."""
        non_admin_session = Session(
            email="user@example.com",
            display_name="User",
            roles=[],
            provider_name="local",
            created_at=_NOW,
            expires_at=_NOW,
            last_active_at=_NOW,
            token="user-token",
        )

        with patch(
            "bamf.api.routers.auth.get_session",
            new_callable=AsyncMock,
            return_value=non_admin_session,
        ):
            resp = await auth_client.delete(
                "/api/v1/auth/sessions/user/target@example.com",
                headers={"Authorization": "Bearer user-token"},
            )

        assert resp.status_code == 403


# ── Tests: OIDC Authorize Redirect ───────────────────────────────────


class TestOIDCAuthorize:
    """Tests for GET /authorize with OIDC provider redirect."""

    @pytest.fixture
    def oidc_app(self):
        app = FastAPI()
        app.include_router(router, prefix="/api/v1")

        async def override_db():
            yield AsyncMock()

        app.dependency_overrides[get_db] = override_db
        return app

    @pytest.fixture
    async def oidc_client(self, oidc_app):
        async with AsyncClient(
            transport=ASGITransport(app=oidc_app),
            base_url="http://test",
            follow_redirects=False,
        ) as client:
            yield client

    @pytest.mark.asyncio
    async def test_oidc_redirect(self, oidc_client):
        """OIDC provider returns a 302 redirect to the IDP authorize URL."""
        from bamf.auth.sso import AuthorizationRequest

        mock_connector = AsyncMock()
        mock_connector.name = "auth0"
        mock_connector.provider_type = "oidc"
        mock_connector.build_authorization_request.return_value = AuthorizationRequest(
            authorize_url="https://myorg.auth0.com/authorize?client_id=xxx&state=idp-state",
            state="idp-state",
            nonce="test-nonce",
        )

        with (
            patch("bamf.api.routers.auth.get_connector", return_value=mock_connector),
            patch(
                "bamf.api.routers.auth.store_auth_state",
                new_callable=AsyncMock,
            ),
            patch("bamf.api.routers.auth.settings") as mock_settings,
        ):
            mock_settings.auth.callback_base_url = "https://bamf.example.com"
            mock_settings.api_prefix = "/api/v1"
            resp = await oidc_client.get(
                "/api/v1/auth/authorize",
                params={
                    "redirect_uri": "http://localhost:9999/callback",
                    "code_challenge": "test-challenge",
                    "state": "client-state",
                    "response_type": "code",
                    "provider": "auth0",
                },
            )

        assert resp.status_code == 302
        assert "myorg.auth0.com/authorize" in resp.headers["location"]

    @pytest.mark.asyncio
    async def test_default_connector_fallback(self, oidc_client):
        """When no provider is specified, the default connector is used."""
        from bamf.auth.sso import AuthorizationRequest

        mock_connector = AsyncMock()
        mock_connector.name = "default-oidc"
        mock_connector.provider_type = "oidc"
        mock_connector.build_authorization_request.return_value = AuthorizationRequest(
            authorize_url="https://default-idp.com/authorize",
            state="idp-state",
            nonce=None,
        )

        with (
            patch("bamf.api.routers.auth.get_connector") as mock_get,
            patch(
                "bamf.api.routers.auth.get_default_connector",
                return_value=mock_connector,
            ),
            patch(
                "bamf.api.routers.auth.store_auth_state",
                new_callable=AsyncMock,
            ),
            patch("bamf.api.routers.auth.settings") as mock_settings,
        ):
            # get_connector is not called when provider is empty
            mock_get.return_value = None
            mock_settings.auth.callback_base_url = "https://bamf.example.com"
            mock_settings.api_prefix = "/api/v1"
            resp = await oidc_client.get(
                "/api/v1/auth/authorize",
                params={
                    "redirect_uri": "http://localhost:9999/callback",
                    "code_challenge": "test-challenge",
                    "state": "client-state",
                    "response_type": "code",
                    "provider": "",
                },
            )

        assert resp.status_code == 302
        assert "default-idp.com/authorize" in resp.headers["location"]


# ── Tests: SAML Authorize Redirect ───────────────────────────────────


class TestSAMLAuthorize:
    """Tests for GET /authorize with SAML provider redirect."""

    @pytest.fixture
    def saml_app(self):
        app = FastAPI()
        app.include_router(router, prefix="/api/v1")

        async def override_db():
            yield AsyncMock()

        app.dependency_overrides[get_db] = override_db
        return app

    @pytest.fixture
    async def saml_client(self, saml_app):
        async with AsyncClient(
            transport=ASGITransport(app=saml_app),
            base_url="http://test",
            follow_redirects=False,
        ) as client:
            yield client

    @pytest.mark.asyncio
    async def test_saml_redirect(self, saml_client):
        """SAML provider returns a 302 redirect to the IDP SSO URL."""
        from bamf.auth.sso import AuthorizationRequest

        mock_connector = AsyncMock()
        mock_connector.name = "azure-ad"
        mock_connector.provider_type = "saml"
        mock_connector.build_authorization_request.return_value = AuthorizationRequest(
            authorize_url="https://login.microsoftonline.com/xxx/saml2?SAMLRequest=encoded",
            state="idp-state",
            nonce=None,
        )

        with (
            patch("bamf.api.routers.auth.get_connector", return_value=mock_connector),
            patch(
                "bamf.api.routers.auth.store_auth_state",
                new_callable=AsyncMock,
            ),
            patch("bamf.api.routers.auth.settings") as mock_settings,
        ):
            mock_settings.auth.callback_base_url = "https://bamf.example.com"
            mock_settings.api_prefix = "/api/v1"
            resp = await saml_client.get(
                "/api/v1/auth/authorize",
                params={
                    "redirect_uri": "http://localhost:9999/callback",
                    "code_challenge": "test-challenge",
                    "state": "client-state",
                    "response_type": "code",
                    "provider": "azure-ad",
                },
            )

        assert resp.status_code == 302
        from urllib.parse import urlparse

        location = urlparse(resp.headers["location"])
        assert location.hostname == "login.microsoftonline.com"


# ── Tests: OIDC Callback ────────────────────────────────────────────


class TestOIDCCallback:
    """Tests for GET /callback (OIDC IDP callback handler)."""

    @pytest.fixture
    def callback_app(self):
        app = FastAPI()
        app.include_router(router, prefix="/api/v1")

        async def override_db():
            yield AsyncMock()

        app.dependency_overrides[get_db] = override_db
        return app

    @pytest.fixture
    async def callback_client(self, callback_app):
        async with AsyncClient(
            transport=ASGITransport(app=callback_app),
            base_url="http://test",
            follow_redirects=False,
        ) as client:
            yield client

    @pytest.mark.asyncio
    async def test_successful_callback(self, callback_client):
        """Valid OIDC callback redirects to client with bamf_code."""
        from bamf.auth.auth_state import AuthState
        from bamf.auth.sso import AuthenticatedIdentity

        auth_state = AuthState(
            provider_name="auth0",
            client_redirect_uri="http://localhost:9999/callback",
            client_state="orig-client-state",
            code_challenge="test-challenge",
            code_challenge_method="S256",
            idp_state="idp-state-123",
            nonce="test-nonce",
        )

        mock_identity = AuthenticatedIdentity(
            provider_name="auth0",
            subject="auth0|12345",
            email="alice@example.com",
            display_name="Alice",
            groups=["bamf:developer"],
            id_token_expires_at=None,
        )

        mock_connector = AsyncMock()
        mock_connector.name = "auth0"
        mock_connector.handle_callback.return_value = mock_identity

        login_result = LoginResult(
            email="alice@example.com",
            display_name="Alice",
            roles=["developer"],
            provider_name="auth0",
            kubernetes_groups=["view"],
        )

        with (
            patch(
                "bamf.api.routers.auth.consume_auth_state",
                new_callable=AsyncMock,
                return_value=auth_state,
            ),
            patch("bamf.api.routers.auth.get_connector", return_value=mock_connector),
            patch(
                "bamf.api.routers.auth.process_login",
                new_callable=AsyncMock,
                return_value=login_result,
            ),
            patch("bamf.api.routers.auth.generate_code", return_value="bamf-code-xyz"),
            patch("bamf.api.routers.auth.store_auth_code", new_callable=AsyncMock),
            patch("bamf.api.routers.auth.log_audit_event", new_callable=AsyncMock),
            patch("bamf.api.routers.auth.settings") as mock_settings,
        ):
            mock_settings.auth.callback_base_url = "https://bamf.example.com"
            mock_settings.api_prefix = "/api/v1"
            mock_settings.auth.require_external_sso_for_roles = []
            mock_settings.auth.sso.oidc = []
            mock_settings.auth.sso.saml = []
            mock_settings.auth.session_ttl_hours = 12
            resp = await callback_client.get(
                "/api/v1/auth/callback",
                params={"code": "idp-auth-code", "state": "idp-state-123"},
            )

        assert resp.status_code == 302
        location = resp.headers["location"]
        assert "localhost:9999/callback" in location
        assert "code=bamf-code-xyz" in location
        assert "state=orig-client-state" in location

    @pytest.mark.asyncio
    async def test_callback_expired_state(self, callback_client):
        """Expired or invalid state returns 400."""
        with patch(
            "bamf.api.routers.auth.consume_auth_state",
            new_callable=AsyncMock,
            return_value=None,
        ):
            resp = await callback_client.get(
                "/api/v1/auth/callback",
                params={"code": "some-code", "state": "expired-state"},
            )

        assert resp.status_code == 400
        assert "Invalid or expired" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_callback_connector_gone(self, callback_client):
        """If the provider was removed after /authorize, returns 500."""
        from bamf.auth.auth_state import AuthState

        auth_state = AuthState(
            provider_name="removed-provider",
            client_redirect_uri="http://localhost/callback",
            client_state="client-state",
            code_challenge="challenge",
            code_challenge_method="S256",
            idp_state="idp-state",
        )

        with (
            patch(
                "bamf.api.routers.auth.consume_auth_state",
                new_callable=AsyncMock,
                return_value=auth_state,
            ),
            patch("bamf.api.routers.auth.get_connector", return_value=None),
        ):
            resp = await callback_client.get(
                "/api/v1/auth/callback",
                params={"code": "some-code", "state": "idp-state"},
            )

        assert resp.status_code == 500
        assert "no longer configured" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_callback_idp_error(self, callback_client):
        """IDP returns an error during token exchange → 401."""
        from bamf.auth.auth_state import AuthState

        auth_state = AuthState(
            provider_name="auth0",
            client_redirect_uri="http://localhost/callback",
            client_state="state",
            code_challenge="challenge",
            code_challenge_method="S256",
            idp_state="idp-state",
        )

        mock_connector = AsyncMock()
        mock_connector.name = "auth0"
        mock_connector.handle_callback.side_effect = ValueError("Token exchange failed")

        with (
            patch(
                "bamf.api.routers.auth.consume_auth_state",
                new_callable=AsyncMock,
                return_value=auth_state,
            ),
            patch("bamf.api.routers.auth.get_connector", return_value=mock_connector),
            patch("bamf.api.routers.auth.log_audit_event", new_callable=AsyncMock),
            patch("bamf.api.routers.auth.settings") as mock_settings,
        ):
            mock_settings.auth.callback_base_url = "https://bamf.example.com"
            mock_settings.api_prefix = "/api/v1"
            resp = await callback_client.get(
                "/api/v1/auth/callback",
                params={"code": "bad-code", "state": "idp-state"},
            )

        assert resp.status_code == 401
        assert "Authentication failed" in resp.json()["detail"]


# ── Tests: SAML ACS ─────────────────────────────────────────────────


class TestSAMLAcs:
    """Tests for POST /saml/acs (SAML Assertion Consumer Service)."""

    @pytest.fixture
    def saml_acs_app(self):
        app = FastAPI()
        app.include_router(router, prefix="/api/v1")

        async def override_db():
            yield AsyncMock()

        app.dependency_overrides[get_db] = override_db
        return app

    @pytest.fixture
    async def saml_acs_client(self, saml_acs_app):
        async with AsyncClient(
            transport=ASGITransport(app=saml_acs_app),
            base_url="http://test",
            follow_redirects=False,
        ) as client:
            yield client

    @pytest.mark.asyncio
    async def test_successful_saml_acs(self, saml_acs_client):
        """Valid SAML response redirects to client with bamf_code."""
        from bamf.auth.auth_state import AuthState
        from bamf.auth.sso import AuthenticatedIdentity

        auth_state = AuthState(
            provider_name="azure-ad",
            client_redirect_uri="http://localhost:9999/callback",
            client_state="orig-client-state",
            code_challenge="test-challenge",
            code_challenge_method="S256",
            idp_state="relay-state-123",
        )

        mock_identity = AuthenticatedIdentity(
            provider_name="azure-ad",
            subject="user@corp.onmicrosoft.com",
            email="bob@example.com",
            display_name="Bob",
            groups=["DevOps"],
        )

        mock_connector = AsyncMock()
        mock_connector.name = "azure-ad"
        mock_connector.handle_callback.return_value = mock_identity

        login_result = LoginResult(
            email="bob@example.com",
            display_name="Bob",
            roles=["admin"],
            provider_name="azure-ad",
            kubernetes_groups=["system:masters"],
        )

        with (
            patch(
                "bamf.api.routers.auth.consume_auth_state",
                new_callable=AsyncMock,
                return_value=auth_state,
            ),
            patch("bamf.api.routers.auth.get_connector", return_value=mock_connector),
            patch(
                "bamf.api.routers.auth.process_login",
                new_callable=AsyncMock,
                return_value=login_result,
            ),
            patch("bamf.api.routers.auth.generate_code", return_value="saml-bamf-code"),
            patch("bamf.api.routers.auth.store_auth_code", new_callable=AsyncMock),
            patch("bamf.api.routers.auth.log_audit_event", new_callable=AsyncMock),
            patch("bamf.api.routers.auth.settings") as mock_settings,
        ):
            mock_settings.auth.callback_base_url = "https://bamf.example.com"
            mock_settings.api_prefix = "/api/v1"
            mock_settings.auth.require_external_sso_for_roles = []
            mock_settings.auth.sso.oidc = []
            mock_settings.auth.sso.saml = []
            resp = await saml_acs_client.post(
                "/api/v1/auth/saml/acs",
                data={
                    "SAMLResponse": "base64-encoded-saml-response",
                    "RelayState": "relay-state-123",
                },
            )

        assert resp.status_code == 302
        location = resp.headers["location"]
        assert "localhost:9999/callback" in location
        assert "code=saml-bamf-code" in location
        assert "state=orig-client-state" in location

    @pytest.mark.asyncio
    async def test_missing_saml_response(self, saml_acs_client):
        """Missing SAMLResponse field returns 400."""
        resp = await saml_acs_client.post(
            "/api/v1/auth/saml/acs",
            data={"RelayState": "some-state"},
        )
        assert resp.status_code == 400
        assert "Missing SAMLResponse" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_saml_expired_state(self, saml_acs_client):
        """Expired relay state returns 400."""
        with patch(
            "bamf.api.routers.auth.consume_auth_state",
            new_callable=AsyncMock,
            return_value=None,
        ):
            resp = await saml_acs_client.post(
                "/api/v1/auth/saml/acs",
                data={
                    "SAMLResponse": "base64-saml-data",
                    "RelayState": "expired-state",
                },
            )

        assert resp.status_code == 400
        assert "Invalid or expired" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_saml_connector_gone(self, saml_acs_client):
        """If the SAML provider was removed after /authorize, returns 500."""
        from bamf.auth.auth_state import AuthState

        auth_state = AuthState(
            provider_name="removed-saml",
            client_redirect_uri="http://localhost/callback",
            client_state="client-state",
            code_challenge="challenge",
            code_challenge_method="S256",
            idp_state="relay-state",
        )

        with (
            patch(
                "bamf.api.routers.auth.consume_auth_state",
                new_callable=AsyncMock,
                return_value=auth_state,
            ),
            patch("bamf.api.routers.auth.get_connector", return_value=None),
        ):
            resp = await saml_acs_client.post(
                "/api/v1/auth/saml/acs",
                data={
                    "SAMLResponse": "base64-saml-data",
                    "RelayState": "relay-state",
                },
            )

        assert resp.status_code == 500
        assert "no longer configured" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_saml_validation_error(self, saml_acs_client):
        """SAML assertion validation failure returns 401."""
        from bamf.auth.auth_state import AuthState

        auth_state = AuthState(
            provider_name="azure-ad",
            client_redirect_uri="http://localhost/callback",
            client_state="state",
            code_challenge="challenge",
            code_challenge_method="S256",
            idp_state="relay-state",
        )

        mock_connector = AsyncMock()
        mock_connector.name = "azure-ad"
        mock_connector.handle_callback.side_effect = ValueError("Invalid SAML assertion")

        with (
            patch(
                "bamf.api.routers.auth.consume_auth_state",
                new_callable=AsyncMock,
                return_value=auth_state,
            ),
            patch("bamf.api.routers.auth.get_connector", return_value=mock_connector),
            patch("bamf.api.routers.auth.settings") as mock_settings,
        ):
            mock_settings.auth.callback_base_url = "https://bamf.example.com"
            mock_settings.api_prefix = "/api/v1"
            resp = await saml_acs_client.post(
                "/api/v1/auth/saml/acs",
                data={
                    "SAMLResponse": "bad-saml-data",
                    "RelayState": "relay-state",
                },
            )

        assert resp.status_code == 401
        assert "SAML authentication failed" in resp.json()["detail"]


# ── Tests: Get Session Info ──────────────────────────────────────────


class TestGetSessionInfo:
    """Tests for GET /sessions/me (current session info)."""

    @pytest.mark.asyncio
    async def test_get_current_session(self, auth_client):
        """Authenticated user sees their session info with is_current=True."""
        mock_session_obj = Session(
            email="user@example.com",
            display_name="User",
            roles=["developer"],
            provider_name="auth0",
            created_at=_NOW,
            expires_at=_NOW,
            last_active_at=_NOW,
            token="test-token",
        )
        with (
            patch(
                "bamf.api.routers.auth.get_session",
                new_callable=AsyncMock,
                return_value=mock_session_obj,
            ),
            patch(
                "bamf.api.routers.auth.list_user_sessions",
                new_callable=AsyncMock,
                return_value=[mock_session_obj],
            ),
        ):
            resp = await auth_client.get(
                "/api/v1/auth/sessions",
                headers={"Authorization": "Bearer test-token"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["email"] == "user@example.com"
        assert data[0]["provider_name"] == "auth0"
        assert data[0]["roles"] == ["developer"]
        assert data[0]["is_current"] is True
        assert data[0]["token_hint"] == "st-token"

    @pytest.mark.asyncio
    async def test_multiple_sessions_marks_current(self, auth_client):
        """When multiple sessions exist, only the current one has is_current=True."""
        current_session = Session(
            email="user@example.com",
            display_name="User",
            roles=[],
            provider_name="local",
            created_at=_NOW,
            expires_at=_NOW,
            last_active_at=_NOW,
            token="current-token-abc",
        )
        other_session = Session(
            email="user@example.com",
            display_name="User",
            roles=[],
            provider_name="local",
            created_at=_NOW,
            expires_at=_NOW,
            last_active_at=_NOW,
            token="other-token-xyz",
        )
        with (
            patch(
                "bamf.api.routers.auth.get_session",
                new_callable=AsyncMock,
                return_value=current_session,
            ),
            patch(
                "bamf.api.routers.auth.list_user_sessions",
                new_callable=AsyncMock,
                return_value=[current_session, other_session],
            ),
        ):
            resp = await auth_client.get(
                "/api/v1/auth/sessions",
                headers={"Authorization": "Bearer current-token-abc"},
            )
        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 2
        current = [s for s in data if s["is_current"]]
        not_current = [s for s in data if not s["is_current"]]
        assert len(current) == 1
        assert len(not_current) == 1
        assert current[0]["token_hint"] == "oken-abc"

    @pytest.mark.asyncio
    async def test_sessions_no_auth(self, auth_client):
        """Missing Authorization header returns 401."""
        with patch(
            "bamf.api.routers.auth.get_session",
            new_callable=AsyncMock,
            return_value=None,
        ):
            resp = await auth_client.get("/api/v1/auth/sessions")
        assert resp.status_code == 401


# ── Tests: Enforce External SSO Requirement ──────────────────────────


class TestEnforceExternalSSO:
    """Tests for _enforce_external_sso_requirement helper."""

    def test_no_restrictions(self):
        """No restrictions means no exception."""
        from bamf.api.routers.auth import _enforce_external_sso_requirement

        with patch("bamf.api.routers.auth.settings") as mock_settings:
            mock_settings.auth.require_external_sso_for_roles = []
            # Should not raise
            _enforce_external_sso_requirement("local", ["admin", "developer"])

    def test_external_provider_allowed(self):
        """External providers are never restricted, even for restricted roles."""
        from bamf.api.routers.auth import _enforce_external_sso_requirement

        with patch("bamf.api.routers.auth.settings") as mock_settings:
            mock_settings.auth.require_external_sso_for_roles = ["admin"]
            # Should not raise — provider is external
            _enforce_external_sso_requirement("auth0", ["admin"])

    def test_local_provider_with_restricted_role(self):
        """Local provider with restricted role raises 403."""
        from bamf.api.routers.auth import _enforce_external_sso_requirement

        with patch("bamf.api.routers.auth.settings") as mock_settings:
            mock_settings.auth.require_external_sso_for_roles = ["admin", "k8s-access"]
            with pytest.raises(HTTPException) as exc_info:
                _enforce_external_sso_requirement("local", ["developer", "admin"])
            assert exc_info.value.status_code == 403
            assert "require external SSO" in exc_info.value.detail

    def test_local_provider_without_restricted_role(self):
        """Local provider with non-restricted roles is allowed."""
        from bamf.api.routers.auth import _enforce_external_sso_requirement

        with patch("bamf.api.routers.auth.settings") as mock_settings:
            mock_settings.auth.require_external_sso_for_roles = ["admin"]
            # developer is not restricted — should not raise
            _enforce_external_sso_requirement("local", ["developer"])


# ── Tests: Compute Max Session TTL ───────────────────────────────────


class TestComputeMaxSessionTTL:
    """Tests for _compute_max_session_ttl helper."""

    def test_none_when_no_expiry(self):
        """No id_token expiry returns None."""
        from bamf.api.routers.auth import _compute_max_session_ttl

        assert _compute_max_session_ttl(None) is None

    def test_returns_remaining_when_shorter_than_configured(self):
        """When id_token expires sooner than session TTL, returns remaining seconds."""
        from datetime import timedelta

        from bamf.api.routers.auth import _compute_max_session_ttl

        # id_token expires in 1 hour, session TTL is 12 hours
        future_time = datetime.now(UTC) + timedelta(hours=1)
        with patch("bamf.api.routers.auth.settings") as mock_settings:
            mock_settings.auth.session_ttl_hours = 12
            result = _compute_max_session_ttl(future_time)

        assert result is not None
        assert 3500 < result < 3700  # ~1 hour in seconds, allowing timing tolerance

    def test_none_when_longer_than_configured(self):
        """When id_token expires later than session TTL, returns None."""
        from datetime import timedelta

        from bamf.api.routers.auth import _compute_max_session_ttl

        # id_token expires in 24 hours, session TTL is 12 hours
        future_time = datetime.now(UTC) + timedelta(hours=24)
        with patch("bamf.api.routers.auth.settings") as mock_settings:
            mock_settings.auth.session_ttl_hours = 12
            result = _compute_max_session_ttl(future_time)

        assert result is None

    def test_none_when_already_expired(self):
        """Already-expired id_token returns None (remaining <= 0)."""
        from datetime import timedelta

        from bamf.api.routers.auth import _compute_max_session_ttl

        past_time = datetime.now(UTC) - timedelta(hours=1)
        with patch("bamf.api.routers.auth.settings") as mock_settings:
            mock_settings.auth.session_ttl_hours = 12
            result = _compute_max_session_ttl(past_time)

        assert result is None


# ── Tests: Get Claims Rules ──────────────────────────────────────────


class TestGetClaimsRules:
    """Tests for _get_claims_rules helper."""

    def test_oidc_provider_returns_rules(self):
        """Returns claims_to_roles for a matching OIDC provider."""
        from bamf.api.routers.auth import _get_claims_rules

        mock_oidc = MagicMock()
        mock_oidc.name = "auth0"
        mock_oidc.claims_to_roles = [{"claim": "groups", "value": "dev", "roles": ["developer"]}]

        with patch("bamf.api.routers.auth.settings") as mock_settings:
            mock_settings.auth.sso.oidc = [mock_oidc]
            mock_settings.auth.sso.saml = []
            result = _get_claims_rules("auth0")

        assert len(result) == 1
        assert result[0]["claim"] == "groups"

    def test_saml_provider_returns_rules(self):
        """Returns claims_to_roles for a matching SAML provider."""
        from bamf.api.routers.auth import _get_claims_rules

        mock_saml = MagicMock()
        mock_saml.name = "azure-ad"
        mock_saml.claims_to_roles = [{"claim": "department", "value": "DevOps", "roles": ["admin"]}]

        with patch("bamf.api.routers.auth.settings") as mock_settings:
            mock_settings.auth.sso.oidc = []
            mock_settings.auth.sso.saml = [mock_saml]
            result = _get_claims_rules("azure-ad")

        assert len(result) == 1
        assert result[0]["claim"] == "department"

    def test_unknown_provider_returns_empty(self):
        """Unknown provider name returns empty list."""
        from bamf.api.routers.auth import _get_claims_rules

        with patch("bamf.api.routers.auth.settings") as mock_settings:
            mock_settings.auth.sso.oidc = []
            mock_settings.auth.sso.saml = []
            result = _get_claims_rules("nonexistent")

        assert result == []

    def test_local_provider_returns_empty(self):
        """Local provider has no claims_to_roles rules."""
        from bamf.api.routers.auth import _get_claims_rules

        mock_oidc = MagicMock()
        mock_oidc.name = "auth0"
        mock_oidc.claims_to_roles = [{"claim": "groups", "value": "dev", "roles": ["developer"]}]

        with patch("bamf.api.routers.auth.settings") as mock_settings:
            mock_settings.auth.sso.oidc = [mock_oidc]
            mock_settings.auth.sso.saml = []
            result = _get_claims_rules("local")

        assert result == []


# ── Tests: CA Certificate Edge Cases ─────────────────────────────────


class TestGetCACertificateEdge:
    @pytest.mark.asyncio
    async def test_ca_not_initialized(self, auth_client):
        """Returns 503 when CA is not yet initialized."""
        with patch("bamf.auth.ca.get_ca", side_effect=RuntimeError("CA not initialized")):
            resp = await auth_client.get("/api/v1/auth/ca/public")

        assert resp.status_code == 503
        assert "CA not initialized" in resp.json()["detail"]


# ── Tests: Token Exchange Cookie ─────────────────────────────────────


class TestTokenExchangeCookie:
    """Tests for session cookie behavior in POST /auth/token."""

    @pytest.mark.asyncio
    async def test_sets_cookie_when_tunnel_domain_configured(self, auth_client):
        """Session cookie is set on parent domain when tunnel_domain is configured."""
        verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
        h = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(h).rstrip(b"=").decode()

        auth_code = AuthCode(
            email="alice@example.com",
            roles=["developer"],
            provider_name="local",
            code_challenge=challenge,
            code_challenge_method="S256",
        )

        mock_session = Session(
            email="alice@example.com",
            display_name="Alice",
            roles=["developer"],
            provider_name="local",
            created_at=_NOW,
            expires_at=_NOW,
            last_active_at=_NOW,
            token="session-token-for-cookie",
        )

        with (
            patch(
                "bamf.api.routers.auth.consume_auth_code",
                new_callable=AsyncMock,
                return_value=auth_code,
            ),
            patch(
                "bamf.api.routers.auth.create_session",
                new_callable=AsyncMock,
                return_value=mock_session,
            ),
            patch("bamf.api.routers.auth.settings") as mock_settings,
        ):
            mock_settings.tunnel_domain = "tunnel.bamf.local"
            mock_settings.auth.session_ttl_hours = 12
            resp = await auth_client.post(
                "/api/v1/auth/token",
                data={
                    "grant_type": "authorization_code",
                    "code": "test-code",
                    "code_verifier": verifier,
                },
            )

        assert resp.status_code == 200
        # Check cookie was set
        cookie_header = resp.headers.get("set-cookie", "")
        assert "bamf_session" in cookie_header
        assert ".bamf.local" in cookie_header

    @pytest.mark.asyncio
    async def test_invalid_grant_type(self, auth_client):
        """Invalid grant_type returns 400."""
        resp = await auth_client.post(
            "/api/v1/auth/token",
            data={
                "grant_type": "client_credentials",
                "code": "any",
                "code_verifier": "any",
            },
        )
        assert resp.status_code == 400
        assert "authorization_code" in resp.json()["detail"]


# ── Tests: Local Login Submit (form-based, redirect flow) ────────────


class TestLocalLoginSubmit:
    """Tests for POST /auth/local/login (form-based local login + redirect)."""

    @pytest.fixture
    def login_app(self):
        app = FastAPI()
        app.include_router(router, prefix="/api/v1")

        async def override_db():
            yield AsyncMock()

        app.dependency_overrides[get_db] = override_db
        return app

    @pytest.fixture
    async def login_client(self, login_app):
        async with AsyncClient(
            transport=ASGITransport(app=login_app),
            base_url="http://test",
            follow_redirects=False,
        ) as client:
            yield client

    @pytest.mark.asyncio
    async def test_successful_local_login(self, login_client):
        """Valid form login redirects to client with bamf_code."""
        from bamf.auth.auth_state import AuthState
        from bamf.auth.sso import AuthenticatedIdentity

        auth_state = AuthState(
            provider_name="local",
            client_redirect_uri="http://localhost:9999/callback",
            client_state="orig-state",
            code_challenge="test-challenge",
            code_challenge_method="S256",
            idp_state="local-state",
        )

        mock_identity = AuthenticatedIdentity(
            provider_name="local",
            subject="user@example.com",
            email="user@example.com",
            display_name="User",
            groups=[],
        )

        mock_connector = AsyncMock()
        mock_connector.name = "local"
        mock_connector.handle_callback.return_value = mock_identity

        login_result = LoginResult(
            email="user@example.com",
            display_name="User",
            roles=["developer"],
            provider_name="local",
            kubernetes_groups=[],
        )

        with (
            patch(
                "bamf.api.routers.auth.consume_auth_state",
                new_callable=AsyncMock,
                return_value=auth_state,
            ),
            patch("bamf.api.routers.auth.get_connector", return_value=mock_connector),
            patch(
                "bamf.api.routers.auth.process_login",
                new_callable=AsyncMock,
                return_value=login_result,
            ),
            patch("bamf.api.routers.auth.generate_code", return_value="local-bamf-code"),
            patch("bamf.api.routers.auth.store_auth_code", new_callable=AsyncMock),
            patch("bamf.api.routers.auth.log_audit_event", new_callable=AsyncMock),
            patch("bamf.api.routers.auth.settings") as mock_settings,
        ):
            mock_settings.auth.require_external_sso_for_roles = []
            mock_settings.auth.sso.oidc = []
            mock_settings.auth.sso.saml = []
            resp = await login_client.post(
                "/api/v1/auth/local/login",
                data={
                    "state": "local-state",
                    "email": "user@example.com",
                    "password": "correct-password",
                },
            )

        assert resp.status_code == 302
        location = resp.headers["location"]
        assert "localhost:9999/callback" in location
        assert "code=local-bamf-code" in location
        assert "state=orig-state" in location

    @pytest.mark.asyncio
    async def test_expired_auth_state(self, login_client):
        """Expired auth state returns 400."""
        with patch(
            "bamf.api.routers.auth.consume_auth_state",
            new_callable=AsyncMock,
            return_value=None,
        ):
            resp = await login_client.post(
                "/api/v1/auth/local/login",
                data={
                    "state": "expired-state",
                    "email": "user@example.com",
                    "password": "password",
                },
            )

        assert resp.status_code == 400
        assert "Invalid or expired" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_wrong_provider_in_state(self, login_client):
        """Auth state for non-local provider returns 400."""
        from bamf.auth.auth_state import AuthState

        auth_state = AuthState(
            provider_name="auth0",
            client_redirect_uri="http://localhost/callback",
            client_state="state",
            code_challenge="challenge",
            code_challenge_method="S256",
            idp_state="local-state",
        )

        with patch(
            "bamf.api.routers.auth.consume_auth_state",
            new_callable=AsyncMock,
            return_value=auth_state,
        ):
            resp = await login_client.post(
                "/api/v1/auth/local/login",
                data={
                    "state": "local-state",
                    "email": "user@example.com",
                    "password": "password",
                },
            )

        assert resp.status_code == 400
        assert "not for local provider" in resp.json()["detail"]

    @pytest.mark.asyncio
    async def test_invalid_credentials(self, login_client):
        """Invalid credentials via form login returns 401."""
        from bamf.auth.auth_state import AuthState

        auth_state = AuthState(
            provider_name="local",
            client_redirect_uri="http://localhost/callback",
            client_state="state",
            code_challenge="challenge",
            code_challenge_method="S256",
            idp_state="local-state",
        )

        mock_connector = AsyncMock()
        mock_connector.name = "local"
        mock_connector.handle_callback.side_effect = ValueError("Invalid credentials")

        with (
            patch(
                "bamf.api.routers.auth.consume_auth_state",
                new_callable=AsyncMock,
                return_value=auth_state,
            ),
            patch("bamf.api.routers.auth.get_connector", return_value=mock_connector),
            patch("bamf.api.routers.auth.log_audit_event", new_callable=AsyncMock),
            patch("bamf.api.routers.auth.settings") as mock_settings,
        ):
            mock_settings.auth.sso.oidc = []
            mock_settings.auth.sso.saml = []
            resp = await login_client.post(
                "/api/v1/auth/local/login",
                data={
                    "state": "local-state",
                    "email": "user@example.com",
                    "password": "wrong-password",
                },
            )

        assert resp.status_code == 401
        assert "Invalid credentials" in resp.json()["detail"]
