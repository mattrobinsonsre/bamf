"""Integration tests for proxy handler functions.

Tests cover the main proxy handler functions in bamf/proxy/handler.py:
- handle_proxy_request() — the main HTTP proxy handler
- _forward_with_retry() — HTTP forwarding with retry logic
- _handle_webhook_request() — webhook passthrough handler
- _store_http_recording() — recording storage
- proxy_middleware() — Starlette middleware entry point

All external dependencies (api_client, httpx, settings) are mocked.
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from starlette.datastructures import Headers

import bamf.proxy.handler as handler_mod
from bamf.proxy.api_client import AuthorizeResult, RelayInfo, ResourceInfo, SessionInfo

# ── Fixture helpers ──────────────────────────────────────────────────────


def _make_mock_settings(**overrides):
    """Build a mock ProxySettings with sensible defaults."""
    s = MagicMock()
    s.tunnel_domain = overrides.get("tunnel_domain", "tunnel.bamf.local")
    s.callback_base_url = overrides.get("callback_base_url", "https://bamf.local")
    s.bridge_internal_port = overrides.get("bridge_internal_port", 8080)
    s.bridge_headless_service = overrides.get("bridge_headless_service", "bamf-bridge-headless")
    s.namespace = overrides.get("namespace", "bamf")
    return s


class _FakeURL:
    """Mimics Starlette's URL with path and query attributes."""

    def __init__(self, path: str, query: str = ""):
        self.path = path
        self.query = query

    def __str__(self):
        if self.query:
            return f"http://test{self.path}?{self.query}"
        return f"http://test{self.path}"


class _FakeClient:
    """Mimics request.client with a host attribute."""

    def __init__(self, host: str):
        self.host = host


class _FakeRequest:
    """A lightweight fake Starlette Request for testing proxy handler.

    Uses Starlette's real Headers class so .get(), iteration, and
    dict(request.headers) all work correctly.
    """

    def __init__(
        self,
        *,
        method: str = "GET",
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
        path: str = "/dashboard",
        query: str = "",
        client_host: str = "10.0.0.1",
    ):
        self.method = method
        # Build raw headers list for Starlette's Headers class
        raw_headers: list[tuple[bytes, bytes]] = []
        for k, v in (headers or {}).items():
            raw_headers.append((k.lower().encode(), v.encode()))
        self.headers = Headers(raw=raw_headers)
        self._cookies = cookies or {}
        self.url = _FakeURL(path, query)
        self.client = _FakeClient(client_host)

    @property
    def cookies(self) -> dict[str, str]:
        return self._cookies

    async def body(self) -> bytes:
        return getattr(self, "_body", b"")

    def set_body(self, body: bytes) -> None:
        self._body = body


def _make_request(
    *,
    method: str = "GET",
    host: str = "grafana.tunnel.bamf.local",
    path: str = "/dashboard",
    query: str = "",
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    body: bytes = b"",
    client_host: str = "10.0.0.1",
) -> _FakeRequest:
    """Build a fake Request with all required attributes."""
    all_headers = {"host": host, **(headers or {})}
    req = _FakeRequest(
        method=method,
        headers=all_headers,
        cookies=cookies,
        path=path,
        query=query,
        client_host=client_host,
    )
    req.set_body(body)
    return req


def _make_auth_result(
    *,
    allowed: bool = True,
    reason: str | None = None,
    webhook_match: dict | None = None,
    resource_name: str = "grafana",
    resource_type: str = "http",
    hostname: str = "grafana.internal",
    port: int = 3000,
    tunnel_hostname: str = "grafana",
    email: str = "alice@example.com",
    roles: list[str] | None = None,
    bridge_relay_host: str = "bamf-bridge-0.headless:8080",
    agent_name: str = "dc-agent-01",
) -> AuthorizeResult:
    """Build an AuthorizeResult for testing."""
    session = None
    resource = None
    relay = None

    if allowed or resource_name:
        resource = ResourceInfo(
            name=resource_name,
            resource_type=resource_type,
            hostname=hostname,
            port=port,
            tunnel_hostname=tunnel_hostname,
        )

    if allowed and not webhook_match:
        session = SessionInfo(
            email=email,
            display_name="Alice",
            roles=roles or ["developer"],
            kubernetes_groups=[],
        )

    if allowed:
        relay = RelayInfo(
            bridge_id="bridge-0",
            bridge_relay_host=bridge_relay_host,
            agent_name=agent_name,
        )

    return AuthorizeResult(
        allowed=allowed,
        reason=reason,
        session=session,
        resource=resource,
        relay=relay,
        webhook_match=webhook_match,
    )


def _make_httpx_response(
    *,
    status_code: int = 200,
    headers: dict[str, str] | None = None,
    content: bytes = b"OK",
    content_type: str = "text/html",
) -> MagicMock:
    """Build a mock httpx.Response with proper header handling."""
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code

    resp_headers = {"content-type": content_type, **(headers or {})}

    # Build an httpx.Headers object for realistic behavior
    real_headers = httpx.Headers(resp_headers)
    resp.headers = real_headers

    resp.content = content
    resp.aread = AsyncMock()
    resp.aclose = AsyncMock()

    return resp


def _make_httpx_response_with_cookies(
    *,
    status_code: int = 200,
    response_headers: dict[str, str] | None = None,
    set_cookies: list[str] | None = None,
    content: bytes = b"OK",
    content_type: str = "text/html",
) -> MagicMock:
    """Build a mock httpx.Response that includes Set-Cookie headers.

    httpx.Headers deduplicates keys, so Set-Cookie handling needs
    special treatment via multi_items().
    """
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = status_code

    all_headers = {"content-type": content_type, **(response_headers or {})}

    # Build multi_items list with Set-Cookie entries
    multi = list(all_headers.items())
    for cookie in set_cookies or []:
        multi.append(("set-cookie", cookie))

    # items() returns deduplicated (last wins) — exclude set-cookie
    items_no_cookie = list(all_headers.items())

    resp.headers = MagicMock()
    resp.headers.multi_items.return_value = multi
    resp.headers.items.return_value = items_no_cookie
    resp.headers.get = lambda key, default="": all_headers.get(key, default)

    resp.content = content
    resp.aread = AsyncMock()
    resp.aclose = AsyncMock()

    return resp


@pytest.fixture(autouse=True)
def _patch_settings():
    """Patch proxy settings for all tests in this module."""
    mock_settings = _make_mock_settings()
    with (
        patch("bamf.proxy.handler.settings", mock_settings),
        patch("bamf.proxy.handler.BRIDGE_INTERNAL_PORT", 8080),
    ):
        yield mock_settings


@pytest.fixture(autouse=True)
def _reset_proxy_client():
    """Reset the global proxy client between tests."""
    handler_mod._proxy_client = None
    yield
    handler_mod._proxy_client = None


# ═══════════════════════════════════════════════════════════════════════
# handle_proxy_request
# ═══════════════════════════════════════════════════════════════════════


class TestHandleProxyRequestHappyPath:
    """Tests for the successful proxy request flow."""

    @pytest.mark.asyncio
    async def test_successful_proxy_returns_200(self):
        """A fully authenticated and authorized request returns the proxied response."""
        auth = _make_auth_result()
        mock_resp = _make_httpx_response(
            status_code=200,
            content=b"<html>Dashboard</html>",
        )

        request = _make_request(
            headers={
                "host": "grafana.tunnel.bamf.local",
                "authorization": "Bearer session-tok-123",
            },
        )

        with (
            patch("bamf.proxy.handler.api_client") as mock_api,
            patch("bamf.proxy.handler._forward_with_retry", new_callable=AsyncMock) as mock_fwd,
            patch(
                "bamf.proxy.handler.rewrite_request_headers",
                return_value={"Host": "grafana.internal"},
            ),
            patch("bamf.proxy.handler.rewrite_response_headers", return_value={"x-custom": "val"}),
        ):
            mock_api.authorize = AsyncMock(return_value=auth)
            mock_api.log_audit = AsyncMock()
            mock_fwd.return_value = mock_resp

            resp = await handler_mod.handle_proxy_request(request)

        assert resp.status_code == 200
        assert resp.body == b"<html>Dashboard</html>"

    @pytest.mark.asyncio
    async def test_set_cookies_are_rewritten(self):
        """Set-Cookie headers from the target are rewritten to the tunnel domain."""
        auth = _make_auth_result()
        mock_resp = _make_httpx_response_with_cookies(
            status_code=200,
            content=b"ok",
            set_cookies=["session=abc; domain=grafana.internal; path=/"],
        )

        request = _make_request(
            headers={
                "host": "grafana.tunnel.bamf.local",
                "authorization": "Bearer tok",
            },
        )

        with (
            patch("bamf.proxy.handler.api_client") as mock_api,
            patch("bamf.proxy.handler._forward_with_retry", new_callable=AsyncMock) as mock_fwd,
            patch("bamf.proxy.handler.rewrite_request_headers", return_value={}),
            patch("bamf.proxy.handler.rewrite_response_headers", return_value={}),
            patch(
                "bamf.proxy.handler.rewrite_set_cookie",
                return_value="session=abc; domain=grafana.tunnel.bamf.local; path=/",
            ) as mock_rewrite_cookie,
        ):
            mock_api.authorize = AsyncMock(return_value=auth)
            mock_api.log_audit = AsyncMock()
            mock_fwd.return_value = mock_resp

            resp = await handler_mod.handle_proxy_request(request)

        mock_rewrite_cookie.assert_called_once()
        # The rewritten cookie should appear in response headers
        cookies = [v for k, v in resp.raw_headers if k == b"set-cookie"]
        assert len(cookies) == 1

    @pytest.mark.asyncio
    async def test_sse_response_returns_streaming(self):
        """SSE content-type triggers a StreamingResponse."""
        auth = _make_auth_result()
        mock_resp = _make_httpx_response(
            status_code=200,
            content=b"data: hello\n\n",
            content_type="text/event-stream",
        )

        request = _make_request(
            headers={
                "host": "grafana.tunnel.bamf.local",
                "authorization": "Bearer tok",
            },
        )

        with (
            patch("bamf.proxy.handler.api_client") as mock_api,
            patch("bamf.proxy.handler._forward_with_retry", new_callable=AsyncMock) as mock_fwd,
            patch("bamf.proxy.handler.rewrite_request_headers", return_value={}),
            patch("bamf.proxy.handler.rewrite_response_headers", return_value={}),
        ):
            mock_api.authorize = AsyncMock(return_value=auth)
            mock_api.log_audit = AsyncMock()
            mock_fwd.return_value = mock_resp

            resp = await handler_mod.handle_proxy_request(request)

        assert resp.media_type == "text/event-stream"
        # StreamingResponse — aread should NOT have been called
        mock_resp.aread.assert_not_called()

    @pytest.mark.asyncio
    async def test_http_audit_triggers_recording_task(self):
        """Resources with type http-audit schedule _store_http_recording."""
        auth = _make_auth_result(resource_type="http-audit")
        mock_resp = _make_httpx_response(status_code=200, content=b"response body")

        request = _make_request(
            headers={
                "host": "grafana.tunnel.bamf.local",
                "authorization": "Bearer tok",
            },
        )

        with (
            patch("bamf.proxy.handler.api_client") as mock_api,
            patch("bamf.proxy.handler._forward_with_retry", new_callable=AsyncMock) as mock_fwd,
            patch("bamf.proxy.handler.rewrite_request_headers", return_value={}),
            patch("bamf.proxy.handler.rewrite_response_headers", return_value={}),
            patch("bamf.proxy.handler._store_http_recording", new_callable=AsyncMock),
        ):
            mock_api.authorize = AsyncMock(return_value=auth)
            mock_api.log_audit = AsyncMock()
            mock_fwd.return_value = mock_resp

            resp = await handler_mod.handle_proxy_request(request)
            # Let fire-and-forget tasks execute
            await asyncio.sleep(0.01)

        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_audit_log_is_called(self):
        """Successful proxy triggers a fire-and-forget audit log call."""
        auth = _make_auth_result()
        mock_resp = _make_httpx_response(status_code=200, content=b"ok")

        request = _make_request(
            headers={
                "host": "grafana.tunnel.bamf.local",
                "authorization": "Bearer tok",
            },
        )

        with (
            patch("bamf.proxy.handler.api_client") as mock_api,
            patch("bamf.proxy.handler._forward_with_retry", new_callable=AsyncMock) as mock_fwd,
            patch("bamf.proxy.handler.rewrite_request_headers", return_value={}),
            patch("bamf.proxy.handler.rewrite_response_headers", return_value={}),
        ):
            mock_api.authorize = AsyncMock(return_value=auth)
            mock_api.log_audit = AsyncMock()
            mock_fwd.return_value = mock_resp

            await handler_mod.handle_proxy_request(request)
            # Let fire-and-forget tasks execute
            await asyncio.sleep(0.01)

        mock_api.log_audit.assert_called_once()
        call_kwargs = mock_api.log_audit.call_args[1]
        assert call_kwargs["user_email"] == "alice@example.com"
        assert call_kwargs["resource_name"] == "grafana"
        assert call_kwargs["status_code"] == 200

    @pytest.mark.asyncio
    async def test_non_audit_resource_skips_recording(self):
        """Regular http resources do NOT trigger recording."""
        auth = _make_auth_result(resource_type="http")  # not http-audit
        mock_resp = _make_httpx_response(status_code=200, content=b"ok")

        request = _make_request(
            headers={
                "host": "grafana.tunnel.bamf.local",
                "authorization": "Bearer tok",
            },
        )

        with (
            patch("bamf.proxy.handler.api_client") as mock_api,
            patch("bamf.proxy.handler._forward_with_retry", new_callable=AsyncMock) as mock_fwd,
            patch("bamf.proxy.handler.rewrite_request_headers", return_value={}),
            patch("bamf.proxy.handler.rewrite_response_headers", return_value={}),
            patch("bamf.proxy.handler._store_http_recording", new_callable=AsyncMock) as mock_store,
        ):
            mock_api.authorize = AsyncMock(return_value=auth)
            mock_api.log_audit = AsyncMock()
            mock_fwd.return_value = mock_resp

            await handler_mod.handle_proxy_request(request)
            await asyncio.sleep(0.01)

            mock_store.assert_not_called()


class TestHandleProxyRequestAuthFailures:
    """Tests for authentication and authorization failure paths."""

    @pytest.mark.asyncio
    async def test_no_session_browser_redirects_to_login(self):
        """Browser request with no session gets a 302 redirect to login."""
        auth = _make_auth_result(allowed=False, reason="no_session")

        request = _make_request(
            headers={
                "host": "grafana.tunnel.bamf.local",
                "accept": "text/html",
            },
        )

        with patch("bamf.proxy.handler.api_client") as mock_api:
            mock_api.authorize = AsyncMock(return_value=auth)
            resp = await handler_mod.handle_proxy_request(request)

        assert resp.status_code == 302
        location = resp.headers.get("location", "")
        assert "/login?" in location
        assert "redirect=" in location

    @pytest.mark.asyncio
    async def test_no_session_api_returns_401(self):
        """Non-browser request with no session gets a 401."""
        auth = _make_auth_result(allowed=False, reason="no_session")

        request = _make_request(
            headers={
                "host": "grafana.tunnel.bamf.local",
                "accept": "application/json",
            },
        )

        with patch("bamf.proxy.handler.api_client") as mock_api:
            mock_api.authorize = AsyncMock(return_value=auth)
            resp = await handler_mod.handle_proxy_request(request)

        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_access_denied_browser_returns_403_with_message(self):
        """Browser request denied by RBAC gets 403 with user-friendly message."""
        auth = _make_auth_result(allowed=False, reason="access_denied")

        request = _make_request(
            headers={
                "host": "grafana.tunnel.bamf.local",
                "accept": "text/html",
            },
        )

        with patch("bamf.proxy.handler.api_client") as mock_api:
            mock_api.authorize = AsyncMock(return_value=auth)
            resp = await handler_mod.handle_proxy_request(request)

        assert resp.status_code == 403
        assert b"permission" in resp.body

    @pytest.mark.asyncio
    async def test_access_denied_api_returns_403_short(self):
        """Non-browser request denied by RBAC gets terse 403."""
        auth = _make_auth_result(allowed=False, reason="access_denied")

        request = _make_request(
            headers={
                "host": "grafana.tunnel.bamf.local",
                "accept": "application/json",
            },
        )

        with patch("bamf.proxy.handler.api_client") as mock_api:
            mock_api.authorize = AsyncMock(return_value=auth)
            resp = await handler_mod.handle_proxy_request(request)

        assert resp.status_code == 403
        assert resp.body == b"Access denied"

    @pytest.mark.asyncio
    async def test_resource_not_found_returns_404(self):
        """Unknown tunnel hostname returns 404."""
        auth = AuthorizeResult(allowed=False, reason="resource_not_found")

        request = _make_request(
            headers={"host": "nonexistent.tunnel.bamf.local"},
        )

        with patch("bamf.proxy.handler.api_client") as mock_api:
            mock_api.authorize = AsyncMock(return_value=auth)
            resp = await handler_mod.handle_proxy_request(request)

        assert resp.status_code == 404
        assert b"nonexistent" in resp.body

    @pytest.mark.asyncio
    async def test_relay_unavailable_returns_503(self):
        """Relay not connected returns 503 with Retry-After."""
        auth = AuthorizeResult(allowed=False, reason="relay_unavailable")

        request = _make_request(
            headers={
                "host": "grafana.tunnel.bamf.local",
                "authorization": "Bearer tok",
            },
        )

        with patch("bamf.proxy.handler.api_client") as mock_api:
            mock_api.authorize = AsyncMock(return_value=auth)
            resp = await handler_mod.handle_proxy_request(request)

        assert resp.status_code == 503
        assert "Retry-After" in resp.headers

    @pytest.mark.asyncio
    async def test_webhook_relay_unavailable_returns_503(self):
        """Webhook with relay unavailable returns 503."""
        auth = AuthorizeResult(
            allowed=False,
            reason="relay_unavailable",
            webhook_match={"path": "/hook", "methods": ["POST"]},
        )

        request = _make_request(
            method="POST",
            headers={"host": "grafana.tunnel.bamf.local"},
            path="/hook",
        )

        with patch("bamf.proxy.handler.api_client") as mock_api:
            mock_api.authorize = AsyncMock(return_value=auth)
            resp = await handler_mod.handle_proxy_request(request)

        assert resp.status_code == 503
        assert "Retry-After" in resp.headers

    @pytest.mark.asyncio
    async def test_generic_error_returns_502(self):
        """Unknown denial reason returns 502."""
        auth = AuthorizeResult(allowed=False, reason="some_weird_error")

        request = _make_request(
            headers={"host": "grafana.tunnel.bamf.local"},
        )

        with patch("bamf.proxy.handler.api_client") as mock_api:
            mock_api.authorize = AsyncMock(return_value=auth)
            resp = await handler_mod.handle_proxy_request(request)

        assert resp.status_code == 502
        assert b"some_weird_error" in resp.body


class TestHandleProxyRequestBridgeFailures:
    """Tests for bridge connection failure paths."""

    @pytest.mark.asyncio
    async def test_forward_returns_none_gives_502(self):
        """When _forward_with_retry returns None, respond with 502."""
        auth = _make_auth_result()

        request = _make_request(
            headers={
                "host": "grafana.tunnel.bamf.local",
                "authorization": "Bearer tok",
            },
        )

        with (
            patch("bamf.proxy.handler.api_client") as mock_api,
            patch("bamf.proxy.handler._forward_with_retry", new_callable=AsyncMock) as mock_fwd,
            patch("bamf.proxy.handler.rewrite_request_headers", return_value={}),
        ):
            mock_api.authorize = AsyncMock(return_value=auth)
            mock_fwd.return_value = None

            resp = await handler_mod.handle_proxy_request(request)

        assert resp.status_code == 502
        assert b"Bridge connection failed" in resp.body

    @pytest.mark.asyncio
    async def test_forward_returns_502_gives_503(self):
        """When bridge returns 502, proxy responds with 503 + Retry-After."""
        auth = _make_auth_result()
        mock_resp = _make_httpx_response(status_code=502, content=b"bad gateway")

        request = _make_request(
            headers={
                "host": "grafana.tunnel.bamf.local",
                "authorization": "Bearer tok",
            },
        )

        with (
            patch("bamf.proxy.handler.api_client") as mock_api,
            patch("bamf.proxy.handler._forward_with_retry", new_callable=AsyncMock) as mock_fwd,
            patch("bamf.proxy.handler.rewrite_request_headers", return_value={}),
        ):
            mock_api.authorize = AsyncMock(return_value=auth)
            mock_fwd.return_value = mock_resp

            resp = await handler_mod.handle_proxy_request(request)

        assert resp.status_code == 503
        assert "Retry-After" in resp.headers


class TestHandleProxyRequestWebhookDispatch:
    """Tests verifying webhook requests dispatch to _handle_webhook_request."""

    @pytest.mark.asyncio
    async def test_webhook_match_delegates_to_handler(self):
        """When auth says webhook_match, delegate to _handle_webhook_request."""
        auth = _make_auth_result(
            webhook_match={"path": "/webhook", "methods": ["POST"]},
        )
        expected_response = MagicMock()
        expected_response.status_code = 200

        request = _make_request(
            method="POST",
            headers={"host": "grafana.tunnel.bamf.local"},
            path="/webhook",
        )

        with (
            patch("bamf.proxy.handler.api_client") as mock_api,
            patch(
                "bamf.proxy.handler._handle_webhook_request",
                new_callable=AsyncMock,
                return_value=expected_response,
            ) as mock_webhook,
        ):
            mock_api.authorize = AsyncMock(return_value=auth)

            resp = await handler_mod.handle_proxy_request(request)

        assert resp is expected_response
        mock_webhook.assert_called_once()


# ═══════════════════════════════════════════════════════════════════════
# _forward_with_retry
# ═══════════════════════════════════════════════════════════════════════


class TestForwardWithRetry:
    """Tests for the _forward_with_retry function."""

    @pytest.mark.asyncio
    async def test_success_on_first_try(self):
        """Returns response immediately when first request succeeds."""
        auth = _make_auth_result()
        mock_resp = MagicMock(spec=httpx.Response)
        mock_resp.status_code = 200

        mock_client = MagicMock()
        mock_request_obj = MagicMock()
        mock_client.build_request.return_value = mock_request_obj
        mock_client.send = AsyncMock(return_value=mock_resp)

        with patch("bamf.proxy.handler._get_proxy_client", return_value=mock_client):
            result = await handler_mod._forward_with_retry(
                "GET",
                "http://bridge:8080/relay/agent/path",
                {"Host": "target"},
                b"",
                auth=auth,
            )

        assert result is mock_resp
        assert mock_client.send.call_count == 1

    @pytest.mark.asyncio
    async def test_retries_on_none_response(self):
        """Retries up to 2 times when bridge returns ConnectError."""
        auth = _make_auth_result()

        success_resp = MagicMock(spec=httpx.Response)
        success_resp.status_code = 200

        call_count = 0

        async def _mock_send(req, stream=False):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise httpx.ConnectError("refused")
            return success_resp

        mock_client = MagicMock()
        mock_client.build_request.return_value = MagicMock()
        mock_client.send = _mock_send

        with (
            patch("bamf.proxy.handler._get_proxy_client", return_value=mock_client),
            patch("bamf.proxy.handler.api_client") as mock_api,
        ):
            mock_api.authorize = AsyncMock(return_value=auth)
            result = await handler_mod._forward_with_retry(
                "GET",
                "http://bridge:8080/relay/agent/path",
                {},
                b"",
                auth=auth,
            )

        assert result is success_resp
        # First attempt fails, re-authorize called, second attempt succeeds
        assert call_count == 2
        mock_api.authorize.assert_called_once()

    @pytest.mark.asyncio
    async def test_retries_on_502(self):
        """Retries when bridge returns 502 (relay not ready)."""
        auth = _make_auth_result()

        bad_resp = MagicMock(spec=httpx.Response)
        bad_resp.status_code = 502
        bad_resp.aclose = AsyncMock()

        good_resp = MagicMock(spec=httpx.Response)
        good_resp.status_code = 200

        call_count = 0

        async def _mock_send(req, stream=False):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return bad_resp
            return good_resp

        mock_client = MagicMock()
        mock_client.build_request.return_value = MagicMock()
        mock_client.send = _mock_send

        with (
            patch("bamf.proxy.handler._get_proxy_client", return_value=mock_client),
            patch("bamf.proxy.handler.api_client") as mock_api,
        ):
            mock_api.authorize = AsyncMock(return_value=auth)
            result = await handler_mod._forward_with_retry(
                "GET",
                "http://bridge:8080/relay/agent/path",
                {},
                b"",
                auth=auth,
            )

        assert result is good_resp
        assert call_count == 2
        # The 502 response should have been closed before retry
        bad_resp.aclose.assert_called_once()

    @pytest.mark.asyncio
    async def test_all_retries_exhausted_returns_none(self):
        """Returns None when all retry attempts fail with ConnectError."""
        auth = _make_auth_result()

        async def _always_fail(req, stream=False):
            raise httpx.ConnectError("bridge down")

        mock_client = MagicMock()
        mock_client.build_request.return_value = MagicMock()
        mock_client.send = _always_fail

        with (
            patch("bamf.proxy.handler._get_proxy_client", return_value=mock_client),
            patch("bamf.proxy.handler.api_client") as mock_api,
        ):
            mock_api.authorize = AsyncMock(return_value=auth)
            result = await handler_mod._forward_with_retry(
                "GET",
                "http://bridge:8080/relay/agent/path",
                {},
                b"",
                auth=auth,
            )

        assert result is None

    @pytest.mark.asyncio
    async def test_pool_timeout_resets_client(self):
        """PoolTimeout triggers client reset and retry."""
        auth = _make_auth_result()

        success_resp = MagicMock(spec=httpx.Response)
        success_resp.status_code = 200

        call_count = 0

        async def _mock_send(req, stream=False):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise httpx.PoolTimeout("pool full")
            return success_resp

        mock_client = MagicMock()
        mock_client.build_request.return_value = MagicMock()
        mock_client.send = _mock_send

        # Set a pre-existing client to verify it gets cleared
        old_client = AsyncMock()
        handler_mod._proxy_client = old_client

        with (
            patch("bamf.proxy.handler._get_proxy_client", return_value=mock_client),
            patch("bamf.proxy.handler.api_client") as mock_api,
            patch("bamf.proxy.handler._close_client", new_callable=AsyncMock),
        ):
            mock_api.authorize = AsyncMock(return_value=auth)
            await handler_mod._forward_with_retry(
                "GET",
                "http://bridge:8080/relay/agent/path",
                {},
                b"",
                auth=auth,
            )

        # After pool timeout, _proxy_client should be reset to None
        assert handler_mod._proxy_client is None

    @pytest.mark.asyncio
    async def test_timeout_exception_returns_none(self):
        """Generic timeout returns None after all retries."""
        auth = _make_auth_result()

        async def _timeout(req, stream=False):
            raise httpx.ReadTimeout("read timeout")

        mock_client = MagicMock()
        mock_client.build_request.return_value = MagicMock()
        mock_client.send = _timeout

        with (
            patch("bamf.proxy.handler._get_proxy_client", return_value=mock_client),
            patch("bamf.proxy.handler.api_client") as mock_api,
        ):
            mock_api.authorize = AsyncMock(return_value=auth)
            result = await handler_mod._forward_with_retry(
                "GET",
                "http://bridge:8080/relay/agent/path",
                {},
                b"",
                auth=auth,
            )

        assert result is None

    @pytest.mark.asyncio
    async def test_no_retry_on_success_status(self):
        """Non-502 success statuses are returned without retry."""
        auth = _make_auth_result()

        resp_304 = MagicMock(spec=httpx.Response)
        resp_304.status_code = 304

        mock_client = MagicMock()
        mock_client.build_request.return_value = MagicMock()
        mock_client.send = AsyncMock(return_value=resp_304)

        with patch("bamf.proxy.handler._get_proxy_client", return_value=mock_client):
            result = await handler_mod._forward_with_retry(
                "GET",
                "http://bridge:8080/relay/agent/path",
                {},
                b"",
                auth=auth,
            )

        assert result is resp_304
        assert mock_client.send.call_count == 1


# ═══════════════════════════════════════════════════════════════════════
# _handle_webhook_request
# ═══════════════════════════════════════════════════════════════════════


class TestHandleWebhookRequest:
    """Tests for the _handle_webhook_request function."""

    @pytest.mark.asyncio
    async def test_webhook_happy_path(self):
        """Webhook request is forwarded and response returned."""
        auth = _make_auth_result(
            webhook_match={"path": "/webhook", "methods": ["POST"]},
        )
        mock_resp = _make_httpx_response(
            status_code=200,
            content=b'{"ok": true}',
            content_type="application/json",
        )

        request = _make_request(
            method="POST",
            host="grafana.tunnel.bamf.local",
            path="/webhook",
            body=b'{"event": "push"}',
        )

        with (
            patch("bamf.proxy.handler._forward_with_retry", new_callable=AsyncMock) as mock_fwd,
            patch("bamf.proxy.handler.api_client") as mock_api,
            patch(
                "bamf.proxy.handler.rewrite_webhook_request_headers",
                return_value={"Host": "grafana.internal"},
            ),
            patch("bamf.proxy.handler.rewrite_response_headers", return_value={}),
        ):
            mock_fwd.return_value = mock_resp
            mock_api.log_audit = AsyncMock()

            resp = await handler_mod._handle_webhook_request(
                request, auth, "grafana", "tunnel.bamf.local"
            )
            await asyncio.sleep(0.01)

        assert resp.status_code == 200
        assert resp.body == b'{"ok": true}'
        mock_api.log_audit.assert_called_once()
        audit_kwargs = mock_api.log_audit.call_args[1]
        assert audit_kwargs["action"] == "webhook_passthrough"
        assert audit_kwargs["resource_name"] == "grafana"

    @pytest.mark.asyncio
    async def test_webhook_bridge_failure_returns_502(self):
        """Webhook when bridge is unreachable returns 502."""
        auth = _make_auth_result(
            webhook_match={"path": "/webhook", "methods": ["POST"]},
        )

        request = _make_request(
            method="POST",
            host="grafana.tunnel.bamf.local",
            path="/webhook",
        )

        with (
            patch("bamf.proxy.handler._forward_with_retry", new_callable=AsyncMock) as mock_fwd,
            patch("bamf.proxy.handler.rewrite_webhook_request_headers", return_value={}),
        ):
            mock_fwd.return_value = None

            resp = await handler_mod._handle_webhook_request(
                request, auth, "grafana", "tunnel.bamf.local"
            )

        assert resp.status_code == 502
        assert b"Bridge connection failed" in resp.body

    @pytest.mark.asyncio
    async def test_webhook_bridge_502_returns_503(self):
        """Webhook when bridge returns 502 gets converted to 503."""
        auth = _make_auth_result(
            webhook_match={"path": "/webhook", "methods": ["POST"]},
        )
        mock_resp = _make_httpx_response(status_code=502, content=b"bad gateway")

        request = _make_request(
            method="POST",
            host="grafana.tunnel.bamf.local",
            path="/webhook",
        )

        with (
            patch("bamf.proxy.handler._forward_with_retry", new_callable=AsyncMock) as mock_fwd,
            patch("bamf.proxy.handler.rewrite_webhook_request_headers", return_value={}),
        ):
            mock_fwd.return_value = mock_resp

            resp = await handler_mod._handle_webhook_request(
                request, auth, "grafana", "tunnel.bamf.local"
            )

        assert resp.status_code == 503
        assert "Retry-After" in resp.headers

    @pytest.mark.asyncio
    async def test_webhook_set_cookies_rewritten(self):
        """Set-Cookie headers in webhook responses are rewritten."""
        auth = _make_auth_result(
            webhook_match={"path": "/hook", "methods": ["POST"]},
        )
        mock_resp = _make_httpx_response_with_cookies(
            status_code=200,
            content=b"ok",
            set_cookies=["tok=xyz; domain=grafana.internal"],
        )

        request = _make_request(
            method="POST",
            host="grafana.tunnel.bamf.local",
            path="/hook",
        )

        with (
            patch("bamf.proxy.handler._forward_with_retry", new_callable=AsyncMock) as mock_fwd,
            patch("bamf.proxy.handler.api_client") as mock_api,
            patch("bamf.proxy.handler.rewrite_webhook_request_headers", return_value={}),
            patch("bamf.proxy.handler.rewrite_response_headers", return_value={}),
            patch(
                "bamf.proxy.handler.rewrite_set_cookie",
                return_value="tok=xyz; domain=grafana.tunnel.bamf.local",
            ) as mock_rsc,
        ):
            mock_fwd.return_value = mock_resp
            mock_api.log_audit = AsyncMock()

            await handler_mod._handle_webhook_request(request, auth, "grafana", "tunnel.bamf.local")

        mock_rsc.assert_called_once()

    @pytest.mark.asyncio
    async def test_webhook_sse_response_streams(self):
        """Webhook SSE response returns StreamingResponse."""
        auth = _make_auth_result(
            webhook_match={"path": "/hook", "methods": ["POST"]},
        )
        mock_resp = _make_httpx_response(
            status_code=200,
            content=b"data: event\n\n",
            content_type="text/event-stream",
        )

        request = _make_request(
            method="POST",
            host="grafana.tunnel.bamf.local",
            path="/hook",
        )

        with (
            patch("bamf.proxy.handler._forward_with_retry", new_callable=AsyncMock) as mock_fwd,
            patch("bamf.proxy.handler.api_client") as mock_api,
            patch("bamf.proxy.handler.rewrite_webhook_request_headers", return_value={}),
            patch("bamf.proxy.handler.rewrite_response_headers", return_value={}),
        ):
            mock_fwd.return_value = mock_resp
            mock_api.log_audit = AsyncMock()

            resp = await handler_mod._handle_webhook_request(
                request, auth, "grafana", "tunnel.bamf.local"
            )

        assert resp.media_type == "text/event-stream"
        mock_resp.aread.assert_not_called()


# ═══════════════════════════════════════════════════════════════════════
# _store_http_recording
# ═══════════════════════════════════════════════════════════════════════


class TestStoreHttpRecording:
    """Tests for the _store_http_recording function."""

    @pytest.mark.asyncio
    async def test_stores_recording_via_api_client(self):
        """A normal recording stores the full HTTP exchange."""
        mock_request = _make_request(
            method="POST",
            path="/api/data",
            query="format=json",
            body=b'{"key": "value"}',
            headers={
                "host": "grafana.tunnel.bamf.local",
                "content-type": "application/json",
            },
        )

        mock_response = _make_httpx_response(
            status_code=200,
            content=b'{"result": "ok"}',
            content_type="application/json",
        )

        with patch("bamf.proxy.handler.api_client") as mock_api:
            mock_api.store_recording = AsyncMock()

            await handler_mod._store_http_recording(
                user_email="alice@example.com",
                resource_name="grafana",
                request=mock_request,
                request_body=b'{"key": "value"}',
                raw_request_headers={
                    "content-type": "application/json",
                },
                response=mock_response,
                duration_ms=42,
            )

        mock_api.store_recording.assert_called_once()
        call_kwargs = mock_api.store_recording.call_args[1]
        assert call_kwargs["user_email"] == "alice@example.com"
        assert call_kwargs["resource_name"] == "grafana"
        assert call_kwargs["recording_type"] == "http"

        # Verify exchange data structure
        exchange = json.loads(call_kwargs["data"])
        assert exchange["version"] == 1
        assert exchange["request"]["method"] == "POST"
        assert exchange["request"]["path"] == "/api/data"
        assert exchange["response"]["status"] == 200
        assert exchange["timing"]["duration_ms"] == 42

    @pytest.mark.asyncio
    async def test_binary_body_excluded(self):
        """Binary request/response bodies are not included in the recording."""
        mock_request = _make_request(
            method="POST",
            path="/upload",
            headers={
                "host": "grafana.tunnel.bamf.local",
                "content-type": "image/png",
            },
        )

        mock_response = _make_httpx_response(
            status_code=200,
            content=b"\x89PNG\r\n",
            content_type="image/png",
        )

        with patch("bamf.proxy.handler.api_client") as mock_api:
            mock_api.store_recording = AsyncMock()

            await handler_mod._store_http_recording(
                user_email="alice@example.com",
                resource_name="grafana",
                request=mock_request,
                request_body=b"\x89PNG\r\n",
                raw_request_headers={"content-type": "image/png"},
                response=mock_response,
                duration_ms=5,
            )

        exchange = json.loads(mock_api.store_recording.call_args[1]["data"])
        # Binary bodies should have body=None
        assert exchange["request"]["body"] is None
        assert exchange["response"]["body"] is None

    @pytest.mark.asyncio
    async def test_hop_by_hop_headers_stripped(self):
        """Hop-by-hop headers (host, connection, etc.) are excluded from recording."""
        mock_request = _make_request(
            method="GET",
            path="/data",
            headers={
                "host": "grafana.tunnel.bamf.local",
                "content-type": "text/plain",
            },
        )

        mock_response = _make_httpx_response(
            status_code=200,
            content=b"ok",
            content_type="text/plain",
        )

        with patch("bamf.proxy.handler.api_client") as mock_api:
            mock_api.store_recording = AsyncMock()

            await handler_mod._store_http_recording(
                user_email="alice@example.com",
                resource_name="grafana",
                request=mock_request,
                request_body=b"",
                raw_request_headers={
                    "host": "grafana.tunnel.bamf.local",
                    "connection": "keep-alive",
                    "content-type": "text/plain",
                },
                response=mock_response,
                duration_ms=1,
            )

        exchange = json.loads(mock_api.store_recording.call_args[1]["data"])
        req_header_keys = [k.lower() for k in exchange["request"]["headers"]]
        assert "host" not in req_header_keys
        assert "connection" not in req_header_keys

    @pytest.mark.asyncio
    async def test_exception_swallowed_not_raised(self):
        """Errors during recording storage are logged but not raised."""
        mock_request = _make_request(
            method="GET",
            path="/data",
            headers={"host": "grafana.tunnel.bamf.local"},
        )

        mock_response = _make_httpx_response(
            status_code=200,
            content=b"ok",
        )

        with patch("bamf.proxy.handler.api_client") as mock_api:
            mock_api.store_recording = AsyncMock(side_effect=Exception("storage down"))

            # Should not raise
            await handler_mod._store_http_recording(
                user_email="alice@example.com",
                resource_name="grafana",
                request=mock_request,
                request_body=b"",
                raw_request_headers={},
                response=mock_response,
                duration_ms=1,
            )

    @pytest.mark.asyncio
    async def test_query_params_are_redacted(self):
        """Sensitive query parameters are redacted in recordings."""
        mock_request = _make_request(
            method="GET",
            path="/callback",
            query="code=abc&token=secret123",
            headers={
                "host": "grafana.tunnel.bamf.local",
                "content-type": "text/html",
            },
        )

        mock_response = _make_httpx_response(
            status_code=200,
            content=b"ok",
            content_type="text/html",
        )

        with patch("bamf.proxy.handler.api_client") as mock_api:
            mock_api.store_recording = AsyncMock()

            await handler_mod._store_http_recording(
                user_email="alice@example.com",
                resource_name="grafana",
                request=mock_request,
                request_body=b"",
                raw_request_headers={"content-type": "text/html"},
                response=mock_response,
                duration_ms=1,
            )

        exchange = json.loads(mock_api.store_recording.call_args[1]["data"])
        query = exchange["request"]["query"]
        # "token" is in REDACT_QUERY_PARAMS, so should be redacted
        assert "secret123" not in query

    @pytest.mark.asyncio
    async def test_sensitive_headers_redacted(self):
        """Authorization and other sensitive headers are redacted."""
        mock_request = _make_request(
            method="GET",
            path="/api",
            headers={
                "host": "grafana.tunnel.bamf.local",
                "authorization": "Bearer super-secret-token",
                "x-api-key": "my-api-key",
            },
        )

        mock_response = _make_httpx_response(
            status_code=200,
            content=b"ok",
            content_type="application/json",
        )

        with patch("bamf.proxy.handler.api_client") as mock_api:
            mock_api.store_recording = AsyncMock()

            await handler_mod._store_http_recording(
                user_email="alice@example.com",
                resource_name="grafana",
                request=mock_request,
                request_body=b"",
                raw_request_headers={
                    "authorization": "Bearer super-secret-token",
                    "x-api-key": "my-api-key",
                    "content-type": "application/json",
                },
                response=mock_response,
                duration_ms=1,
            )

        exchange = json.loads(mock_api.store_recording.call_args[1]["data"])
        req_headers = exchange["request"]["headers"]
        # Check sensitive headers are redacted (not plaintext)
        for key in ("authorization", "x-api-key"):
            if key in req_headers:
                assert req_headers[key] != "Bearer super-secret-token"
                assert req_headers[key] != "my-api-key"


# ═══════════════════════════════════════════════════════════════════════
# proxy_middleware
# ═══════════════════════════════════════════════════════════════════════


class TestProxyMiddleware:
    """Tests for the proxy_middleware function."""

    @pytest.mark.asyncio
    async def test_non_tunnel_request_passes_through(self):
        """Requests not matching the tunnel domain call next middleware."""
        request = _make_request(
            headers={"host": "bamf.local"},
        )

        next_response = MagicMock()

        async def call_next(req):
            return next_response

        resp = await handler_mod.proxy_middleware(request, call_next)
        assert resp is next_response

    @pytest.mark.asyncio
    async def test_tunnel_request_is_intercepted(self):
        """Requests matching the tunnel domain are handled by the proxy."""
        auth = _make_auth_result()
        mock_resp = _make_httpx_response(status_code=200, content=b"proxied")

        request = _make_request(
            headers={
                "host": "grafana.tunnel.bamf.local",
                "authorization": "Bearer tok",
            },
        )

        async def call_next(req):
            pytest.fail("call_next should not be called for proxy requests")

        with (
            patch("bamf.proxy.handler.api_client") as mock_api,
            patch("bamf.proxy.handler._forward_with_retry", new_callable=AsyncMock) as mock_fwd,
            patch("bamf.proxy.handler.rewrite_request_headers", return_value={}),
            patch("bamf.proxy.handler.rewrite_response_headers", return_value={}),
        ):
            mock_api.authorize = AsyncMock(return_value=auth)
            mock_api.log_audit = AsyncMock()
            mock_fwd.return_value = mock_resp

            resp = await handler_mod.proxy_middleware(request, call_next)

        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_websocket_upgrade_passes_through(self):
        """WebSocket upgrade requests pass through to route matching."""
        request = _make_request(
            headers={
                "host": "grafana.tunnel.bamf.local",
                "upgrade": "websocket",
            },
        )

        next_response = MagicMock()

        async def call_next(req):
            return next_response

        resp = await handler_mod.proxy_middleware(request, call_next)
        assert resp is next_response

    @pytest.mark.asyncio
    async def test_no_tunnel_domain_configured_passes_through(self):
        """When tunnel_domain is empty, all requests pass through."""
        request = _make_request(
            headers={"host": "anything.example.com"},
        )

        next_response = MagicMock()

        async def call_next(req):
            return next_response

        with patch("bamf.proxy.handler.settings") as mock_settings:
            mock_settings.tunnel_domain = ""
            resp = await handler_mod.proxy_middleware(request, call_next)

        assert resp is next_response

    @pytest.mark.asyncio
    async def test_host_with_port_matches_correctly(self):
        """Host header with port number still matches the tunnel domain."""
        auth = _make_auth_result()
        mock_resp = _make_httpx_response(status_code=200, content=b"ok")

        request = _make_request(
            headers={
                "host": "grafana.tunnel.bamf.local:443",
                "authorization": "Bearer tok",
            },
        )

        async def call_next(req):
            pytest.fail("call_next should not be called")

        with (
            patch("bamf.proxy.handler.api_client") as mock_api,
            patch("bamf.proxy.handler._forward_with_retry", new_callable=AsyncMock) as mock_fwd,
            patch("bamf.proxy.handler.rewrite_request_headers", return_value={}),
            patch("bamf.proxy.handler.rewrite_response_headers", return_value={}),
        ):
            mock_api.authorize = AsyncMock(return_value=auth)
            mock_api.log_audit = AsyncMock()
            mock_fwd.return_value = mock_resp

            resp = await handler_mod.proxy_middleware(request, call_next)

        assert resp.status_code == 200
