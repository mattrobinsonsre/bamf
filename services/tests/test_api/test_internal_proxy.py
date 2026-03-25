"""Tests for internal proxy API endpoints.

Tests the /api/v1/internal/proxy/* endpoints (authorize, audit, recording)
including the verify_internal_token auth dependency.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from bamf.api.routers.internal_proxy import router


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture
def internal_app():
    """Create a minimal FastAPI app with only the internal proxy router."""
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")
    return app


@pytest.fixture
async def internal_client(internal_app):
    """Async test client for the internal proxy endpoints."""
    async with AsyncClient(
        transport=ASGITransport(app=internal_app),
        base_url="http://test",
    ) as client:
        yield client


INTERNAL_TOKEN = "test-internal-secret"
AUTH_HEADER = {"Authorization": f"Bearer {INTERNAL_TOKEN}"}


@pytest.fixture(autouse=True)
def _patch_settings():
    """Patch settings to provide a test internal token."""
    with patch("bamf.api.routers.internal_proxy.settings") as mock_settings:
        mock_settings.proxy_internal_token = INTERNAL_TOKEN
        mock_settings.api_prefix = "/api/v1"
        yield mock_settings


# ── Auth Dependency Tests ─────────────────────────────────────────────────


class TestVerifyInternalToken:
    """Tests for the verify_internal_token dependency."""

    @pytest.mark.asyncio
    async def test_missing_auth_header(self, internal_client):
        """Request without Authorization header returns 401."""
        resp = await internal_client.post(
            "/api/v1/internal/proxy/audit",
            json={"resource_name": "test"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_wrong_token(self, internal_client):
        """Request with wrong token returns 403."""
        resp = await internal_client.post(
            "/api/v1/internal/proxy/audit",
            json={"resource_name": "test"},
            headers={"Authorization": "Bearer wrong-token"},
        )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_not_bearer(self, internal_client):
        """Non-Bearer auth scheme returns 401."""
        resp = await internal_client.post(
            "/api/v1/internal/proxy/audit",
            json={"resource_name": "test"},
            headers={"Authorization": f"Basic {INTERNAL_TOKEN}"},
        )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_token_not_configured(self, internal_client, _patch_settings):
        """If internal token is empty on server side, returns 503."""
        _patch_settings.proxy_internal_token = ""
        resp = await internal_client.post(
            "/api/v1/internal/proxy/audit",
            json={"resource_name": "test"},
            headers=AUTH_HEADER,
        )
        assert resp.status_code == 503


# ── Authorize Endpoint Tests ──────────────────────────────────────────────


@dataclass
class FakeSession:
    """Minimal session stub for testing."""

    email: str = "alice@example.com"
    display_name: str | None = "Alice"
    roles: list[str] = field(default_factory=lambda: ["developer"])
    kubernetes_groups: list[str] = field(default_factory=list)
    provider_name: str = "auth0"


@dataclass
class FakeResource:
    """Minimal resource stub for testing."""

    name: str = "grafana"
    resource_type: str = "http"
    agent_id: str = "agent-123"
    hostname: str = "grafana.internal"
    port: int = 3000
    tunnel_hostname: str = "grafana"
    webhooks: list[dict] = field(default_factory=list)
    labels: dict = field(default_factory=dict)


class TestAuthorizeEndpoint:
    """Tests for POST /internal/proxy/authorize."""

    @pytest.mark.asyncio
    async def test_resource_not_found(self, internal_client):
        """Unknown tunnel hostname returns resource_not_found."""
        with (
            patch(
                "bamf.api.routers.internal_proxy.get_resource_by_tunnel_hostname",
                new_callable=AsyncMock,
                return_value=None,
            ),
            patch(
                "bamf.api.routers.internal_proxy.get_redis_client",
                return_value=MagicMock(),
            ),
        ):
            resp = await internal_client.post(
                "/api/v1/internal/proxy/authorize",
                json={"tunnel_hostname": "nonexistent", "session_token": "tok-123"},
                headers=AUTH_HEADER,
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["allowed"] is False
        assert data["reason"] == "resource_not_found"

    @pytest.mark.asyncio
    async def test_no_session_token(self, internal_client):
        """Missing session token returns no_session."""
        resource = FakeResource()
        with (
            patch(
                "bamf.api.routers.internal_proxy.get_resource_by_tunnel_hostname",
                new_callable=AsyncMock,
                return_value=resource,
            ),
            patch(
                "bamf.api.routers.internal_proxy.get_redis_client",
                return_value=MagicMock(),
            ),
        ):
            resp = await internal_client.post(
                "/api/v1/internal/proxy/authorize",
                json={"tunnel_hostname": "grafana"},
                headers=AUTH_HEADER,
            )

        data = resp.json()
        assert data["allowed"] is False
        assert data["reason"] == "no_session"

    @pytest.mark.asyncio
    async def test_invalid_session(self, internal_client):
        """Invalid session token returns no_session."""
        resource = FakeResource()
        with (
            patch(
                "bamf.api.routers.internal_proxy.get_resource_by_tunnel_hostname",
                new_callable=AsyncMock,
                return_value=resource,
            ),
            patch(
                "bamf.api.routers.internal_proxy.get_session",
                new_callable=AsyncMock,
                return_value=None,
            ),
            patch(
                "bamf.api.routers.internal_proxy.get_redis_client",
                return_value=MagicMock(),
            ),
        ):
            resp = await internal_client.post(
                "/api/v1/internal/proxy/authorize",
                json={"tunnel_hostname": "grafana", "session_token": "expired-tok"},
                headers=AUTH_HEADER,
            )

        data = resp.json()
        assert data["allowed"] is False
        assert data["reason"] == "no_session"

    @pytest.mark.asyncio
    async def test_access_denied(self, internal_client):
        """RBAC denial returns access_denied with session info."""
        resource = FakeResource()
        session = FakeSession()
        mock_db = AsyncMock()

        with (
            patch(
                "bamf.api.routers.internal_proxy.get_resource_by_tunnel_hostname",
                new_callable=AsyncMock,
                return_value=resource,
            ),
            patch(
                "bamf.api.routers.internal_proxy.get_session",
                new_callable=AsyncMock,
                return_value=session,
            ),
            patch(
                "bamf.api.routers.internal_proxy.get_redis_client",
                return_value=MagicMock(),
            ),
            patch(
                "bamf.api.routers.internal_proxy.async_session_factory_read",
                return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock()),
            ),
            patch(
                "bamf.api.routers.internal_proxy.check_access",
                new_callable=AsyncMock,
                return_value=False,
            ),
        ):
            resp = await internal_client.post(
                "/api/v1/internal/proxy/authorize",
                json={"tunnel_hostname": "grafana", "session_token": "tok-abc"},
                headers=AUTH_HEADER,
            )

        data = resp.json()
        assert data["allowed"] is False
        assert data["reason"] == "access_denied"
        assert data["session"]["email"] == "alice@example.com"
        assert data["resource"]["name"] == "grafana"

    @pytest.mark.asyncio
    async def test_allowed_full_flow(self, internal_client):
        """Full successful authorize returns all fields."""
        resource = FakeResource()
        session = FakeSession()
        mock_db = AsyncMock()
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(
            side_effect=lambda key: {
                "agent:agent-123:status": "online",
                "agent:agent-123:relay_bridge": "bridge-0",
                "agent:agent-123:name": "dc-agent-01",
            }.get(key)
        )

        with (
            patch(
                "bamf.api.routers.internal_proxy.get_resource_by_tunnel_hostname",
                new_callable=AsyncMock,
                return_value=resource,
            ),
            patch(
                "bamf.api.routers.internal_proxy.get_session",
                new_callable=AsyncMock,
                return_value=session,
            ),
            patch(
                "bamf.api.routers.internal_proxy.get_redis_client",
                return_value=mock_redis,
            ),
            patch(
                "bamf.api.routers.internal_proxy.async_session_factory_read",
                return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock()),
            ),
            patch(
                "bamf.api.routers.internal_proxy.check_access",
                new_callable=AsyncMock,
                return_value=True,
            ),
            patch(
                "bamf.api.routers.internal_proxy.build_bridge_relay_host",
                return_value="bamf-bridge-0.headless:8080",
            ),
        ):
            resp = await internal_client.post(
                "/api/v1/internal/proxy/authorize",
                json={
                    "tunnel_hostname": "grafana",
                    "session_token": "tok-abc",
                    "method": "GET",
                    "path": "/dashboards",
                    "source_ip": "10.0.0.1",
                },
                headers=AUTH_HEADER,
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["allowed"] is True
        assert data["session"]["email"] == "alice@example.com"
        assert data["resource"]["name"] == "grafana"
        assert data["relay"]["bridge_id"] == "bridge-0"
        assert data["relay"]["agent_name"] == "dc-agent-01"

    @pytest.mark.asyncio
    async def test_webhook_bypass_auth(self, internal_client):
        """Webhook match skips session auth entirely."""
        resource = FakeResource(
            webhooks=[{"path": "/webhook", "methods": ["POST"]}]
        )
        mock_redis = AsyncMock()
        mock_redis.get = AsyncMock(
            side_effect=lambda key: {
                "agent:agent-123:status": "online",
                "agent:agent-123:relay_bridge": "bridge-0",
                "agent:agent-123:name": "dc-agent-01",
            }.get(key)
        )

        with (
            patch(
                "bamf.api.routers.internal_proxy.get_resource_by_tunnel_hostname",
                new_callable=AsyncMock,
                return_value=resource,
            ),
            patch(
                "bamf.api.routers.internal_proxy.get_redis_client",
                return_value=mock_redis,
            ),
            patch(
                "bamf.api.routers.internal_proxy.build_bridge_relay_host",
                return_value="bamf-bridge-0.headless:8080",
            ),
        ):
            resp = await internal_client.post(
                "/api/v1/internal/proxy/authorize",
                json={
                    "tunnel_hostname": "grafana",
                    "method": "POST",
                    "path": "/webhook",
                    "source_ip": "10.0.0.1",
                    # No session_token — webhook bypasses auth
                },
                headers=AUTH_HEADER,
            )

        data = resp.json()
        assert data["allowed"] is True
        assert data["session"] is None
        assert data["webhook_match"] is not None
        assert data["relay"] is not None

    @pytest.mark.asyncio
    async def test_resource_by_name(self, internal_client):
        """Can resolve resource by name instead of tunnel_hostname."""
        resource = FakeResource()
        with (
            patch(
                "bamf.api.routers.internal_proxy.get_resource_by_tunnel_hostname",
                new_callable=AsyncMock,
                return_value=None,
            ),
            patch(
                "bamf.api.routers.internal_proxy.get_resource",
                new_callable=AsyncMock,
                return_value=resource,
            ),
            patch(
                "bamf.api.routers.internal_proxy.get_redis_client",
                return_value=MagicMock(),
            ),
        ):
            resp = await internal_client.post(
                "/api/v1/internal/proxy/authorize",
                json={"resource_name": "grafana"},
                headers=AUTH_HEADER,
            )

        data = resp.json()
        # Should find resource by name, then fail on no_session
        assert data["reason"] == "no_session"
        assert data["resource"]["name"] == "grafana"


# ── Audit Endpoint Tests ──────────────────────────────────────────────────


class TestAuditEndpoint:
    """Tests for POST /internal/proxy/audit."""

    @pytest.mark.asyncio
    async def test_accepted(self, internal_client):
        """Audit endpoint returns 202 and logs event."""
        mock_db = AsyncMock()
        with (
            patch(
                "bamf.api.routers.internal_proxy.async_session_factory",
                return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock()),
            ),
            patch(
                "bamf.api.routers.internal_proxy.log_audit_event",
                new_callable=AsyncMock,
            ) as mock_log,
        ):
            resp = await internal_client.post(
                "/api/v1/internal/proxy/audit",
                json={
                    "user_email": "alice@example.com",
                    "resource_name": "grafana",
                    "method": "GET",
                    "path": "/dashboards",
                    "status_code": 200,
                    "source_ip": "10.0.0.1",
                    "action": "access_granted",
                },
                headers=AUTH_HEADER,
            )

        assert resp.status_code == 202
        assert resp.json() == {"status": "accepted"}
        mock_log.assert_called_once()

    @pytest.mark.asyncio
    async def test_swallows_db_errors(self, internal_client):
        """Audit endpoint returns 202 even if DB write fails."""
        with patch(
            "bamf.api.routers.internal_proxy.async_session_factory",
            side_effect=Exception("db down"),
        ):
            resp = await internal_client.post(
                "/api/v1/internal/proxy/audit",
                json={"resource_name": "grafana"},
                headers=AUTH_HEADER,
            )

        assert resp.status_code == 202


# ── Recording Endpoint Tests ──────────────────────────────────────────────


class TestRecordingEndpoint:
    """Tests for POST /internal/proxy/recording."""

    @pytest.mark.asyncio
    async def test_accepted(self, internal_client):
        """Recording endpoint returns 202 and stores recording."""
        mock_db = AsyncMock()
        with patch(
            "bamf.api.routers.internal_proxy.async_session_factory",
            return_value=AsyncMock(__aenter__=AsyncMock(return_value=mock_db), __aexit__=AsyncMock()),
        ):
            resp = await internal_client.post(
                "/api/v1/internal/proxy/recording",
                json={
                    "user_email": "alice@example.com",
                    "resource_name": "grafana",
                    "recording_type": "http",
                    "data": '{"request": {}, "response": {}}',
                },
                headers=AUTH_HEADER,
            )

        assert resp.status_code == 202
        assert resp.json() == {"status": "accepted"}
        mock_db.add.assert_called_once()
        mock_db.commit.assert_called_once()

    @pytest.mark.asyncio
    async def test_swallows_db_errors(self, internal_client):
        """Recording endpoint returns 202 even if DB write fails."""
        with patch(
            "bamf.api.routers.internal_proxy.async_session_factory",
            side_effect=Exception("db down"),
        ):
            resp = await internal_client.post(
                "/api/v1/internal/proxy/recording",
                json={
                    "user_email": "alice@example.com",
                    "resource_name": "grafana",
                    "data": "{}",
                },
                headers=AUTH_HEADER,
            )

        assert resp.status_code == 202
