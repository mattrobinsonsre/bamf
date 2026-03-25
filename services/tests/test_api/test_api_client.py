"""Tests for proxy api_client module.

These tests mock httpx responses to verify the proxy's HTTP client
correctly parses API responses into dataclasses.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest


# We patch the settings import before importing api_client so
# the module-level `settings` picks up our test values.
@pytest.fixture(autouse=True)
def _patch_settings():
    """Patch proxy settings for all tests."""
    mock_settings = MagicMock()
    mock_settings.api_url = "http://test-api:8000"
    mock_settings.internal_token = "test-token"
    with patch("bamf.proxy.config.settings", mock_settings):
        with patch("bamf.proxy.api_client.settings", mock_settings):
            yield


@pytest.fixture(autouse=True)
def _reset_client():
    """Reset the shared httpx client between tests."""
    import bamf.proxy.api_client as mod

    mod._client = None
    yield
    mod._client = None


class TestAuthorize:
    """Tests for the authorize() function."""

    @pytest.mark.asyncio
    async def test_allowed_with_full_response(self):
        """Successful authorize returns all fields populated."""
        from bamf.proxy.api_client import authorize

        response_data = {
            "allowed": True,
            "reason": None,
            "login_redirect": None,
            "session": {
                "email": "alice@example.com",
                "display_name": "Alice",
                "roles": ["developer", "ssh-access"],
                "kubernetes_groups": ["view"],
                "provider_name": "auth0",
            },
            "resource": {
                "name": "grafana",
                "resource_type": "http",
                "agent_id": "agent-123",
                "hostname": "grafana.internal",
                "port": 3000,
                "tunnel_hostname": "grafana",
                "webhooks": [],
                "labels": {"env": "prod"},
            },
            "relay": {
                "bridge_id": "bridge-0",
                "bridge_relay_host": "bamf-bridge-0.bamf-bridge-headless:8080",
                "agent_name": "dc-agent-01",
                "connected": True,
            },
            "webhook_match": None,
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = response_data

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_resp

        with patch("bamf.proxy.api_client._get_client", return_value=mock_client):
            result = await authorize(
                session_token="tok-abc",
                tunnel_hostname="grafana",
                method="GET",
                path="/dashboards",
                source_ip="10.0.0.1",
            )

        assert result.allowed is True
        assert result.reason is None
        assert result.session is not None
        assert result.session.email == "alice@example.com"
        assert result.session.roles == ["developer", "ssh-access"]
        assert result.session.kubernetes_groups == ["view"]
        assert result.resource is not None
        assert result.resource.name == "grafana"
        assert result.resource.port == 3000
        assert result.resource.labels == {"env": "prod"}
        assert result.relay is not None
        assert result.relay.bridge_id == "bridge-0"
        assert result.relay.agent_name == "dc-agent-01"
        assert result.webhook_match is None

    @pytest.mark.asyncio
    async def test_denied_no_session(self):
        """Denied authorize with reason no_session."""
        from bamf.proxy.api_client import authorize

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "allowed": False,
            "reason": "no_session",
            "resource": {"name": "grafana", "resource_type": "http"},
        }

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_resp

        with patch("bamf.proxy.api_client._get_client", return_value=mock_client):
            result = await authorize(tunnel_hostname="grafana")

        assert result.allowed is False
        assert result.reason == "no_session"
        assert result.session is None
        assert result.resource is not None
        assert result.resource.name == "grafana"

    @pytest.mark.asyncio
    async def test_connection_error_returns_api_unavailable(self):
        """Network error returns allowed=False with reason api_unavailable."""
        from bamf.proxy.api_client import authorize

        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.ConnectError("connection refused")

        with patch("bamf.proxy.api_client._get_client", return_value=mock_client):
            result = await authorize(session_token="tok-abc", tunnel_hostname="grafana")

        assert result.allowed is False
        assert result.reason == "api_unavailable"

    @pytest.mark.asyncio
    async def test_timeout_returns_api_unavailable(self):
        """Timeout returns allowed=False with reason api_unavailable."""
        from bamf.proxy.api_client import authorize

        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.ReadTimeout("read timeout")

        with patch("bamf.proxy.api_client._get_client", return_value=mock_client):
            result = await authorize(session_token="tok-abc", tunnel_hostname="grafana")

        assert result.allowed is False
        assert result.reason == "api_unavailable"

    @pytest.mark.asyncio
    async def test_api_error_status(self):
        """Non-200 status returns allowed=False with reason api_error."""
        from bamf.proxy.api_client import authorize

        mock_resp = MagicMock()
        mock_resp.status_code = 500

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_resp

        with patch("bamf.proxy.api_client._get_client", return_value=mock_client):
            result = await authorize(session_token="tok-abc", tunnel_hostname="grafana")

        assert result.allowed is False
        assert result.reason == "api_error"

    @pytest.mark.asyncio
    async def test_webhook_match_no_session(self):
        """Webhook match returns with no session but resource and relay."""
        from bamf.proxy.api_client import authorize

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "allowed": True,
            "session": None,
            "resource": {"name": "grafana", "resource_type": "http"},
            "relay": {
                "bridge_id": "bridge-0",
                "bridge_relay_host": "host:8080",
                "agent_name": "agent-1",
            },
            "webhook_match": {"path": "/webhook", "methods": ["POST"]},
        }

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_resp

        with patch("bamf.proxy.api_client._get_client", return_value=mock_client):
            result = await authorize(tunnel_hostname="grafana", method="POST", path="/webhook")

        assert result.allowed is True
        assert result.session is None
        assert result.webhook_match is not None
        assert result.webhook_match["path"] == "/webhook"

    @pytest.mark.asyncio
    async def test_missing_optional_fields(self):
        """Response with minimal fields still parses correctly."""
        from bamf.proxy.api_client import authorize

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"allowed": False, "reason": "resource_not_found"}

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_resp

        with patch("bamf.proxy.api_client._get_client", return_value=mock_client):
            result = await authorize(tunnel_hostname="nonexistent")

        assert result.allowed is False
        assert result.reason == "resource_not_found"
        assert result.session is None
        assert result.resource is None
        assert result.relay is None


class TestLogAudit:
    """Tests for the log_audit() function."""

    @pytest.mark.asyncio
    async def test_fire_and_forget(self):
        """log_audit sends POST and doesn't raise on success."""
        from bamf.proxy.api_client import log_audit

        mock_resp = MagicMock()
        mock_resp.status_code = 202

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_resp

        with patch("bamf.proxy.api_client._get_client", return_value=mock_client):
            await log_audit(
                user_email="alice@example.com",
                resource_name="grafana",
                method="GET",
                path="/dashboards",
                status_code=200,
            )

        mock_client.post.assert_called_once()
        args = mock_client.post.call_args
        assert args[0][0] == "/api/v1/internal/proxy/audit"

    @pytest.mark.asyncio
    async def test_swallows_errors(self):
        """log_audit doesn't raise on network errors."""
        from bamf.proxy.api_client import log_audit

        mock_client = AsyncMock()
        mock_client.post.side_effect = httpx.ConnectError("down")

        with patch("bamf.proxy.api_client._get_client", return_value=mock_client):
            # Should not raise
            await log_audit(resource_name="grafana")


class TestStoreRecording:
    """Tests for the store_recording() function."""

    @pytest.mark.asyncio
    async def test_fire_and_forget(self):
        """store_recording sends POST and doesn't raise on success."""
        from bamf.proxy.api_client import store_recording

        mock_resp = MagicMock()
        mock_resp.status_code = 202

        mock_client = AsyncMock()
        mock_client.post.return_value = mock_resp

        with patch("bamf.proxy.api_client._get_client", return_value=mock_client):
            await store_recording(
                user_email="alice@example.com",
                resource_name="grafana",
                data='{"request": {}, "response": {}}',
            )

        mock_client.post.assert_called_once()
        args = mock_client.post.call_args
        assert args[0][0] == "/api/v1/internal/proxy/recording"

    @pytest.mark.asyncio
    async def test_swallows_errors(self):
        """store_recording doesn't raise on network errors."""
        from bamf.proxy.api_client import store_recording

        mock_client = AsyncMock()
        mock_client.post.side_effect = Exception("boom")

        with patch("bamf.proxy.api_client._get_client", return_value=mock_client):
            # Should not raise
            await store_recording(
                user_email="alice@example.com",
                resource_name="grafana",
                data="{}",
            )


class TestCloseClient:
    """Tests for close_client()."""

    @pytest.mark.asyncio
    async def test_close_client_resets_global(self):
        """close_client sets _client back to None."""
        from bamf.proxy.api_client import _client, close_client

        import bamf.proxy.api_client as mod

        # Simulate an initialized client
        mock_client = AsyncMock()
        mod._client = mock_client

        await close_client()

        assert mod._client is None
        mock_client.aclose.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_client_noop_when_none(self):
        """close_client is safe to call when no client exists."""
        from bamf.proxy.api_client import close_client

        import bamf.proxy.api_client as mod

        mod._client = None
        # Should not raise
        await close_client()
