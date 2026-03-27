"""Tests for the proxy application factory in bamf.proxy.app.

Tests create_application() and its routes/middleware using
httpx.AsyncClient with ASGITransport to test the FastAPI app directly.
The lifespan is overridden to avoid startup/shutdown side effects.
"""

from __future__ import annotations

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

# ── Fixtures ────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _patch_settings():
    """Patch proxy settings for all tests to avoid env var dependencies."""
    mock_settings = MagicMock()
    mock_settings.api_url = "http://test-api:8000"
    mock_settings.internal_token = "test-token"
    mock_settings.bridge_internal_port = 8080
    mock_settings.tunnel_domain = "tunnel.bamf.local"
    mock_settings.json_logs = False
    mock_settings.callback_base_url = "https://bamf.local"
    mock_settings.bridge_headless_service = ""
    mock_settings.namespace = ""
    mock_settings.log_level = "INFO"
    mock_settings.app_name = "bamf-proxy"
    with (
        patch("bamf.proxy.config.settings", mock_settings),
        patch("bamf.proxy.app.settings", mock_settings),
        patch("bamf.proxy.kube.settings", mock_settings),
        patch("bamf.proxy.kube.BRIDGE_INTERNAL_PORT", 8080),
        patch("bamf.proxy.handler.settings", mock_settings),
        patch("bamf.proxy.handler.BRIDGE_INTERNAL_PORT", 8080),
    ):
        yield


def _create_test_app() -> FastAPI:
    """Create the proxy app with a no-op lifespan to skip startup/shutdown."""
    from bamf.proxy.app import create_application

    app = create_application()

    # Replace the lifespan with a no-op to avoid structlog reconfiguration
    # and api_client.close_client() calls during testing.
    @asynccontextmanager
    async def noop_lifespan(app: FastAPI) -> AsyncGenerator[None]:
        yield

    app.router.lifespan_context = noop_lifespan
    return app


@pytest.fixture
async def proxy_client() -> AsyncGenerator[AsyncClient]:
    """Create an async test client for the proxy app."""
    app = _create_test_app()
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://testserver",
    ) as client:
        yield client


# ── App creation tests ──────────────────────────────────────────────────


class TestCreateApplication:
    """Tests for create_application() basic properties."""

    def test_app_title(self):
        """Application has the correct title."""
        app = _create_test_app()
        assert app.title == "BAMF Proxy"

    def test_app_version(self):
        """Application has a version string."""
        app = _create_test_app()
        assert app.version == "0.1.0"

    def test_app_has_docs_url(self):
        """Application exposes docs at /proxy/docs."""
        app = _create_test_app()
        assert app.docs_url == "/proxy/docs"

    def test_app_has_openapi_url(self):
        """Application exposes openapi schema at /proxy/openapi.json."""
        app = _create_test_app()
        assert app.openapi_url == "/proxy/openapi.json"


# ── Health endpoint tests ───────────────────────────────────────────────


class TestHealthEndpoint:
    """Tests for /health endpoint."""

    @pytest.mark.asyncio
    async def test_health_returns_ok(self, proxy_client: AsyncClient):
        """/health returns status ok with service name."""
        response = await proxy_client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["service"] == "proxy"


class TestReadyEndpoint:
    """Tests for /ready endpoint."""

    @pytest.mark.asyncio
    async def test_ready_returns_ok(self, proxy_client: AsyncClient):
        """/ready returns status ok with service name."""
        response = await proxy_client.get("/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        assert data["service"] == "proxy"


# ── Kube router mount tests ────────────────────────────────────────────


class TestKubeRouterMount:
    """Tests for kube router being mounted at /api/v1."""

    @pytest.mark.asyncio
    async def test_kube_route_exists(self, proxy_client: AsyncClient):
        """Kube proxy route responds at /api/v1/kube/{resource}/{path}.

        Since the kube route requires a Bearer token and calls authorize(),
        we expect a 401 when no token is provided -- this confirms the route
        is mounted and reachable.
        """
        response = await proxy_client.get("/api/v1/kube/test-cluster/api/v1/pods")
        # 401 confirms the route was matched (not 404)
        assert response.status_code == 401
        data = response.json()
        assert data["detail"] == "Authentication required"

    @pytest.mark.asyncio
    async def test_kube_route_methods(self, proxy_client: AsyncClient):
        """Kube proxy route accepts multiple HTTP methods."""
        for method in ["GET", "POST", "PUT", "PATCH", "DELETE"]:
            response = await proxy_client.request(
                method, "/api/v1/kube/test-cluster/api/v1/pods"
            )
            # 401 confirms the route matched for this method
            assert response.status_code == 401, f"Method {method} returned {response.status_code}"


# ── Request ID middleware tests ─────────────────────────────────────────


class TestRequestIdMiddleware:
    """Tests for the request ID middleware."""

    @pytest.mark.asyncio
    async def test_request_id_added_to_response(self, proxy_client: AsyncClient):
        """Response includes X-Request-ID header when none was provided."""
        response = await proxy_client.get("/health")
        assert response.status_code == 200
        request_id = response.headers.get("x-request-id")
        assert request_id is not None
        assert len(request_id) > 0

    @pytest.mark.asyncio
    async def test_request_id_is_uuid_format(self, proxy_client: AsyncClient):
        """Auto-generated request ID is a valid UUID."""
        import uuid

        response = await proxy_client.get("/health")
        request_id = response.headers.get("x-request-id")
        # Should not raise ValueError for valid UUID
        parsed = uuid.UUID(request_id)
        assert str(parsed) == request_id

    @pytest.mark.asyncio
    async def test_custom_request_id_preserved(self, proxy_client: AsyncClient):
        """Custom X-Request-ID from client is preserved in response."""
        custom_id = "my-custom-request-id-12345"
        response = await proxy_client.get(
            "/health",
            headers={"X-Request-ID": custom_id},
        )
        assert response.status_code == 200
        assert response.headers.get("x-request-id") == custom_id

    @pytest.mark.asyncio
    async def test_custom_request_id_preserved_on_kube_route(self, proxy_client: AsyncClient):
        """Custom X-Request-ID is preserved even on error responses (kube 401)."""
        custom_id = "kube-req-id-abc"
        response = await proxy_client.get(
            "/api/v1/kube/test-cluster/api/v1/pods",
            headers={"X-Request-ID": custom_id},
        )
        assert response.status_code == 401
        assert response.headers.get("x-request-id") == custom_id

    @pytest.mark.asyncio
    async def test_each_request_gets_unique_id(self, proxy_client: AsyncClient):
        """Consecutive requests without X-Request-ID get different IDs."""
        resp1 = await proxy_client.get("/health")
        resp2 = await proxy_client.get("/health")
        id1 = resp1.headers.get("x-request-id")
        id2 = resp2.headers.get("x-request-id")
        assert id1 != id2


# ── HTTP proxy middleware tests ─────────────────────────────────────────


class TestProxyMiddleware:
    """Tests for the HTTP proxy middleware intercepting tunnel domain requests."""

    @pytest.mark.asyncio
    async def test_non_tunnel_domain_passes_through(self, proxy_client: AsyncClient):
        """Requests to non-tunnel-domain hosts pass through to normal routes."""
        # /health is a normal route; testserver host is not a tunnel domain
        response = await proxy_client.get("/health")
        assert response.status_code == 200
        assert response.json()["service"] == "proxy"

    @pytest.mark.asyncio
    async def test_tunnel_domain_request_intercepted(self, proxy_client: AsyncClient):
        """Requests to *.tunnel.bamf.local are intercepted by the proxy middleware."""
        # This request hits the proxy middleware which calls api_client.authorize()
        # We need to mock authorize to avoid actual API calls
        with patch("bamf.proxy.handler.api_client.authorize", new_callable=AsyncMock) as mock_auth:
            mock_auth.return_value = MagicMock(
                allowed=False,
                reason="no_session",
                webhook_match=None,
            )
            response = await proxy_client.get(
                "/some-path",
                headers={"host": "grafana.tunnel.bamf.local"},
            )

        # The proxy middleware returns a redirect or 401 for no_session
        # (not a 404, which would mean it fell through to normal routing)
        assert response.status_code in (302, 401)
        mock_auth.assert_called_once()

    @pytest.mark.asyncio
    async def test_tunnel_domain_resource_not_found(self, proxy_client: AsyncClient):
        """Requests to unknown tunnel hostname return 404."""
        with patch("bamf.proxy.handler.api_client.authorize", new_callable=AsyncMock) as mock_auth:
            mock_auth.return_value = MagicMock(
                allowed=False,
                reason="resource_not_found",
                webhook_match=None,
            )
            response = await proxy_client.get(
                "/dashboard",
                headers={"host": "nonexistent.tunnel.bamf.local"},
            )

        assert response.status_code == 404


# ── OpenAPI endpoint tests ──────────────────────────────────────────────


class TestOpenAPIEndpoints:
    """Tests for OpenAPI documentation endpoints."""

    @pytest.mark.asyncio
    async def test_openapi_json(self, proxy_client: AsyncClient):
        """OpenAPI schema is available at /proxy/openapi.json."""
        response = await proxy_client.get("/proxy/openapi.json")
        assert response.status_code == 200
        data = response.json()
        assert data["info"]["title"] == "BAMF Proxy"

    @pytest.mark.asyncio
    async def test_docs_page(self, proxy_client: AsyncClient):
        """Swagger UI docs page is available at /proxy/docs."""
        response = await proxy_client.get("/proxy/docs")
        assert response.status_code == 200
        # Swagger UI returns HTML
        assert "text/html" in response.headers.get("content-type", "")
