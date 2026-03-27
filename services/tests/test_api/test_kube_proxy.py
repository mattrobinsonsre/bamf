"""Tests for the kube_proxy() HTTP handler in bamf.proxy.kube.

Heavy mocking approach: mock api_client.authorize(), _get_kube_client(),
and _forward() to isolate the handler logic from network dependencies.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest

from bamf.proxy.api_client import (
    AuthorizeResult,
    RelayInfo,
    ResourceInfo,
    SessionInfo,
)

# ── Fixtures ────────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _patch_settings():
    """Patch proxy settings for all tests."""
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
        patch("bamf.proxy.kube.settings", mock_settings),
        patch("bamf.proxy.kube.BRIDGE_INTERNAL_PORT", 8080),
    ):
        yield


@pytest.fixture(autouse=True)
def _reset_kube_client():
    """Reset the shared kube httpx client between tests."""
    import bamf.proxy.kube as kube_mod

    kube_mod._kube_client = None
    yield
    kube_mod._kube_client = None


def _make_auth_result(
    *,
    allowed: bool = True,
    reason: str | None = None,
    resource_type: str = "kubernetes",
    k8s_groups: list[str] | None = None,
    email: str = "alice@example.com",
    hostname: str | None = "kubernetes.default.svc",
    port: int | None = 6443,
    bridge_relay_host: str = "bamf-bridge-0.headless:8080",
    agent_name: str = "dc-agent-01",
) -> AuthorizeResult:
    """Build a mock AuthorizeResult for testing."""
    if not allowed:
        return AuthorizeResult(allowed=False, reason=reason)

    session = SessionInfo(
        email=email,
        display_name="Alice",
        roles=["sre"],
        kubernetes_groups=k8s_groups if k8s_groups is not None else ["system:masters"],
        provider_name="auth0",
    )
    resource = ResourceInfo(
        name="prod-cluster",
        resource_type=resource_type,
        agent_id="agent-uuid",
        hostname=hostname,
        port=port,
        tunnel_hostname=None,
    )
    relay = RelayInfo(
        bridge_id="bridge-0",
        bridge_relay_host=bridge_relay_host,
        agent_name=agent_name,
        connected=True,
    )
    return AuthorizeResult(
        allowed=True,
        session=session,
        resource=resource,
        relay=relay,
    )


def _make_httpx_response(
    status_code: int = 200,
    content: bytes = b'{"items": []}',
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """Build a real httpx.Response object for testing."""
    resp_headers = headers or {"content-type": "application/json"}
    return httpx.Response(
        status_code=status_code,
        content=content,
        headers=resp_headers,
    )


def _make_request_scope(
    method: str = "GET",
    path: str = "/api/v1/kube/prod-cluster/api/v1/pods",
    headers: dict[str, str] | None = None,
    query_string: str = "",
) -> dict:
    """Build an ASGI scope dict for a Starlette Request."""
    default_headers = {
        "host": "bamf.example.com",
        "authorization": "Bearer test-session-token",
        "accept": "application/json",
        "user-agent": "kubectl/1.28",
    }
    if headers:
        default_headers.update(headers)

    raw_headers = [(k.lower().encode(), v.encode()) for k, v in default_headers.items()]

    return {
        "type": "http",
        "method": method,
        "path": path,
        "query_string": query_string.encode(),
        "headers": raw_headers,
        "server": ("bamf.example.com", 443),
        "client": ("10.0.0.1", 12345),
    }


# ── Tests ───────────────────────────────────────────────────────────────


class TestKubeProxyHappyPath:
    """Tests for successful kube_proxy() execution."""

    @pytest.mark.asyncio
    async def test_happy_path_returns_k8s_response(self):
        """Valid Bearer token + authorized + forward succeeds = K8s response returned."""
        from starlette.requests import Request

        from bamf.proxy.kube import kube_proxy

        auth_result = _make_auth_result()
        k8s_body = b'{"kind": "PodList", "items": []}'
        forward_resp = _make_httpx_response(status_code=200, content=k8s_body)

        scope = _make_request_scope()
        request = Request(scope=scope)
        # Provide an async body
        request._body = b""

        with (
            patch("bamf.proxy.kube.api_client.authorize", new_callable=AsyncMock) as mock_auth,
            patch("bamf.proxy.kube._get_kube_client"),
            patch("bamf.proxy.kube._forward", new_callable=AsyncMock) as mock_forward,
        ):
            mock_auth.return_value = auth_result
            mock_forward.return_value = forward_resp

            response = await kube_proxy(
                resource_name="prod-cluster",
                path="api/v1/pods",
                request=request,
            )

        assert response.status_code == 200
        assert b"PodList" in response.body

        # Verify authorize was called with correct parameters
        mock_auth.assert_called_once()
        call_kwargs = mock_auth.call_args.kwargs
        assert call_kwargs["session_token"] == "test-session-token"
        assert call_kwargs["resource_name"] == "prod-cluster"
        assert call_kwargs["method"] == "GET"
        assert call_kwargs["path"] == "/api/v1/pods"

    @pytest.mark.asyncio
    async def test_correct_impersonation_headers_set(self):
        """X-Forwarded-Email and X-Forwarded-K8s-Groups headers are set on forwarded request."""
        from starlette.requests import Request

        from bamf.proxy.kube import kube_proxy

        auth_result = _make_auth_result(
            email="bob@example.com",
            k8s_groups=["developers", "view"],
        )
        forward_resp = _make_httpx_response(status_code=200, content=b'{"ok": true}')

        scope = _make_request_scope(
            headers={"authorization": "Bearer bob-token"},
        )
        request = Request(scope=scope)
        request._body = b""

        with (
            patch("bamf.proxy.kube.api_client.authorize", new_callable=AsyncMock) as mock_auth,
            patch("bamf.proxy.kube._get_kube_client"),
            patch("bamf.proxy.kube._forward", new_callable=AsyncMock) as mock_forward,
        ):
            mock_auth.return_value = auth_result
            mock_forward.return_value = forward_resp

            await kube_proxy(
                resource_name="prod-cluster",
                path="api/v1/pods",
                request=request,
            )

        # Inspect the headers passed to _forward
        # _forward(client, method, url, headers, body) — headers at index 3
        mock_forward.assert_called()
        forward_call_args = mock_forward.call_args
        headers = forward_call_args[0][3]  # positional arg index 3 = headers dict

        assert headers["X-Forwarded-Email"] == "bob@example.com"
        assert headers["X-Forwarded-K8s-Groups"] == "developers,view"
        assert "X-Bamf-Target" in headers
        assert headers["X-Bamf-Target"] == "https://kubernetes.default.svc:6443"

    @pytest.mark.asyncio
    async def test_hop_by_hop_headers_stripped(self):
        """Hop-by-hop headers (host, connection, etc.) are removed before forwarding."""
        from starlette.requests import Request

        from bamf.proxy.kube import kube_proxy

        auth_result = _make_auth_result()
        forward_resp = _make_httpx_response(status_code=200, content=b"{}")

        scope = _make_request_scope(
            headers={
                "authorization": "Bearer tok",
                "connection": "keep-alive",
                "transfer-encoding": "chunked",
                "upgrade": "h2c",
            },
        )
        request = Request(scope=scope)
        request._body = b""

        with (
            patch("bamf.proxy.kube.api_client.authorize", new_callable=AsyncMock) as mock_auth,
            patch("bamf.proxy.kube._get_kube_client"),
            patch("bamf.proxy.kube._forward", new_callable=AsyncMock) as mock_forward,
        ):
            mock_auth.return_value = auth_result
            mock_forward.return_value = forward_resp

            await kube_proxy(
                resource_name="prod-cluster",
                path="api/v1/pods",
                request=request,
            )

        headers = mock_forward.call_args[0][3]  # index 3 = headers dict
        # These hop-by-hop headers should be stripped
        assert "host" not in headers
        assert "connection" not in headers
        assert "transfer-encoding" not in headers
        assert "upgrade" not in headers


class TestKubeProxyMissingToken:
    """Tests for missing/invalid Bearer token."""

    @pytest.mark.asyncio
    async def test_missing_bearer_token_returns_401(self):
        """Request without Authorization header returns 401."""
        from fastapi import HTTPException
        from starlette.requests import Request

        from bamf.proxy.kube import kube_proxy

        scope = _make_request_scope(
            headers={
                "host": "bamf.example.com",
                "accept": "application/json",
            },
        )
        # Override to remove authorization header entirely
        scope["headers"] = [
            (k, v) for k, v in scope["headers"] if k != b"authorization"
        ]
        request = Request(scope=scope)

        with pytest.raises(HTTPException) as exc_info:
            await kube_proxy(
                resource_name="prod-cluster",
                path="api/v1/pods",
                request=request,
            )

        assert exc_info.value.status_code == 401
        assert "Authentication required" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_non_bearer_auth_returns_401(self):
        """Request with Basic auth (not Bearer) returns 401."""
        from fastapi import HTTPException
        from starlette.requests import Request

        from bamf.proxy.kube import kube_proxy

        scope = _make_request_scope(
            headers={"authorization": "Basic dXNlcjpwYXNz"},
        )
        request = Request(scope=scope)

        with pytest.raises(HTTPException) as exc_info:
            await kube_proxy(
                resource_name="prod-cluster",
                path="api/v1/pods",
                request=request,
            )

        assert exc_info.value.status_code == 401


class TestKubeProxyAuthorizeFailures:
    """Tests for various authorize() rejection reasons."""

    @pytest.mark.asyncio
    async def test_authorize_no_session_returns_401(self):
        """Authorize returns no_session -> 401."""
        from fastapi import HTTPException
        from starlette.requests import Request

        from bamf.proxy.kube import kube_proxy

        auth_result = _make_auth_result(allowed=False, reason="no_session")

        scope = _make_request_scope()
        request = Request(scope=scope)

        with (
            patch("bamf.proxy.kube.api_client.authorize", new_callable=AsyncMock) as mock_auth,
        ):
            mock_auth.return_value = auth_result

            with pytest.raises(HTTPException) as exc_info:
                await kube_proxy(
                    resource_name="prod-cluster",
                    path="api/v1/pods",
                    request=request,
                )

        assert exc_info.value.status_code == 401
        assert "Authentication required" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_authorize_access_denied_returns_403(self):
        """Authorize returns access_denied -> 403."""
        from fastapi import HTTPException
        from starlette.requests import Request

        from bamf.proxy.kube import kube_proxy

        auth_result = _make_auth_result(allowed=False, reason="access_denied")

        scope = _make_request_scope()
        request = Request(scope=scope)

        with patch("bamf.proxy.kube.api_client.authorize", new_callable=AsyncMock) as mock_auth:
            mock_auth.return_value = auth_result

            with pytest.raises(HTTPException) as exc_info:
                await kube_proxy(
                    resource_name="prod-cluster",
                    path="api/v1/pods",
                    request=request,
                )

        assert exc_info.value.status_code == 403
        assert "Access denied" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_authorize_resource_not_found_returns_404(self):
        """Authorize returns resource_not_found -> 404."""
        from fastapi import HTTPException
        from starlette.requests import Request

        from bamf.proxy.kube import kube_proxy

        auth_result = _make_auth_result(allowed=False, reason="resource_not_found")

        scope = _make_request_scope()
        request = Request(scope=scope)

        with patch("bamf.proxy.kube.api_client.authorize", new_callable=AsyncMock) as mock_auth:
            mock_auth.return_value = auth_result

            with pytest.raises(HTTPException) as exc_info:
                await kube_proxy(
                    resource_name="nonexistent",
                    path="api/v1/pods",
                    request=request,
                )

        assert exc_info.value.status_code == 404
        assert "not found" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_authorize_relay_unavailable_returns_503(self):
        """Authorize returns relay_unavailable -> 503."""
        from fastapi import HTTPException
        from starlette.requests import Request

        from bamf.proxy.kube import kube_proxy

        auth_result = _make_auth_result(allowed=False, reason="relay_unavailable")

        scope = _make_request_scope()
        request = Request(scope=scope)

        with patch("bamf.proxy.kube.api_client.authorize", new_callable=AsyncMock) as mock_auth:
            mock_auth.return_value = auth_result

            with pytest.raises(HTTPException) as exc_info:
                await kube_proxy(
                    resource_name="prod-cluster",
                    path="api/v1/pods",
                    request=request,
                )

        assert exc_info.value.status_code == 503

    @pytest.mark.asyncio
    async def test_authorize_unknown_reason_returns_502(self):
        """Authorize returns unrecognized reason -> 502."""
        from fastapi import HTTPException
        from starlette.requests import Request

        from bamf.proxy.kube import kube_proxy

        auth_result = _make_auth_result(allowed=False, reason="something_unexpected")

        scope = _make_request_scope()
        request = Request(scope=scope)

        with patch("bamf.proxy.kube.api_client.authorize", new_callable=AsyncMock) as mock_auth:
            mock_auth.return_value = auth_result

            with pytest.raises(HTTPException) as exc_info:
                await kube_proxy(
                    resource_name="prod-cluster",
                    path="api/v1/pods",
                    request=request,
                )

        assert exc_info.value.status_code == 502


class TestKubeProxyResourceTypeValidation:
    """Tests for resource type checking."""

    @pytest.mark.asyncio
    async def test_non_kubernetes_resource_type_returns_400(self):
        """Resource type is not 'kubernetes' -> 400."""
        from fastapi import HTTPException
        from starlette.requests import Request

        from bamf.proxy.kube import kube_proxy

        auth_result = _make_auth_result(resource_type="ssh")

        scope = _make_request_scope()
        request = Request(scope=scope)
        request._body = b""

        with patch("bamf.proxy.kube.api_client.authorize", new_callable=AsyncMock) as mock_auth:
            mock_auth.return_value = auth_result

            with pytest.raises(HTTPException) as exc_info:
                await kube_proxy(
                    resource_name="prod-cluster",
                    path="api/v1/pods",
                    request=request,
                )

        assert exc_info.value.status_code == 400
        assert "not a Kubernetes resource" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_no_kubernetes_groups_returns_403(self):
        """Session has no kubernetes_groups -> 403."""
        from fastapi import HTTPException
        from starlette.requests import Request

        from bamf.proxy.kube import kube_proxy

        auth_result = _make_auth_result(k8s_groups=[])

        scope = _make_request_scope()
        request = Request(scope=scope)
        request._body = b""

        with patch("bamf.proxy.kube.api_client.authorize", new_callable=AsyncMock) as mock_auth:
            mock_auth.return_value = auth_result

            with pytest.raises(HTTPException) as exc_info:
                await kube_proxy(
                    resource_name="prod-cluster",
                    path="api/v1/pods",
                    request=request,
                )

        assert exc_info.value.status_code == 403
        assert "No Kubernetes groups" in exc_info.value.detail


class TestKubeProxyForwardFailures:
    """Tests for _forward() returning errors."""

    @pytest.mark.asyncio
    async def test_forward_returns_502_triggers_retry(self):
        """Forward returning 502 triggers retry via re-authorize."""
        from starlette.requests import Request

        from bamf.proxy.kube import kube_proxy

        auth_result = _make_auth_result()
        # First forward returns 502, second returns 200 after retry
        resp_502 = _make_httpx_response(status_code=502, content=b"Bad Gateway")
        resp_200 = _make_httpx_response(status_code=200, content=b'{"ok": true}')

        scope = _make_request_scope()
        request = Request(scope=scope)
        request._body = b""

        with (
            patch("bamf.proxy.kube.api_client.authorize", new_callable=AsyncMock) as mock_auth,
            patch("bamf.proxy.kube._get_kube_client"),
            patch("bamf.proxy.kube._forward", new_callable=AsyncMock) as mock_forward,
        ):
            mock_auth.return_value = auth_result
            # First call returns 502, second returns 200
            mock_forward.side_effect = [resp_502, resp_200]

            response = await kube_proxy(
                resource_name="prod-cluster",
                path="api/v1/pods",
                request=request,
            )

        assert response.status_code == 200
        # authorize called: once initially + once on retry
        assert mock_auth.call_count == 2
        # forward called twice: initial + retry
        assert mock_forward.call_count == 2

    @pytest.mark.asyncio
    async def test_forward_returns_502_all_retries_exhausted(self):
        """Forward returning 502 on all attempts -> 503."""
        from fastapi import HTTPException
        from starlette.requests import Request

        from bamf.proxy.kube import kube_proxy

        auth_result = _make_auth_result()
        resp_502 = _make_httpx_response(status_code=502, content=b"Bad Gateway")

        scope = _make_request_scope()
        request = Request(scope=scope)
        request._body = b""

        with (
            patch("bamf.proxy.kube.api_client.authorize", new_callable=AsyncMock) as mock_auth,
            patch("bamf.proxy.kube._get_kube_client"),
            patch("bamf.proxy.kube._forward", new_callable=AsyncMock) as mock_forward,
        ):
            mock_auth.return_value = auth_result
            mock_forward.return_value = resp_502

            with pytest.raises(HTTPException) as exc_info:
                await kube_proxy(
                    resource_name="prod-cluster",
                    path="api/v1/pods",
                    request=request,
                )

        assert exc_info.value.status_code == 503
        assert "Relay connection not available" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_forward_connection_error_returns_502(self):
        """Forward raises connection error (returns None) -> 502."""
        from fastapi import HTTPException
        from starlette.requests import Request

        from bamf.proxy.kube import kube_proxy

        auth_result = _make_auth_result()

        scope = _make_request_scope()
        request = Request(scope=scope)
        request._body = b""

        with (
            patch("bamf.proxy.kube.api_client.authorize", new_callable=AsyncMock) as mock_auth,
            patch("bamf.proxy.kube._get_kube_client"),
            patch("bamf.proxy.kube._forward", new_callable=AsyncMock) as mock_forward,
        ):
            mock_auth.return_value = auth_result
            # _forward returns None on connection error
            mock_forward.return_value = None

            with pytest.raises(HTTPException) as exc_info:
                await kube_proxy(
                    resource_name="prod-cluster",
                    path="api/v1/pods",
                    request=request,
                )

        assert exc_info.value.status_code == 502
        assert "Bridge connection failed" in exc_info.value.detail


class TestKubeProxyResponseHeaders:
    """Tests for response header handling."""

    @pytest.mark.asyncio
    async def test_response_strips_hop_by_hop_headers(self):
        """Response hop-by-hop headers (transfer-encoding, connection, etc.) are stripped."""
        from starlette.requests import Request

        from bamf.proxy.kube import kube_proxy

        auth_result = _make_auth_result()
        forward_resp = _make_httpx_response(
            status_code=200,
            content=b'{"items": []}',
            headers={
                "content-type": "application/json",
                "transfer-encoding": "chunked",
                "connection": "keep-alive",
                "content-length": "14",
                "x-custom-header": "preserved",
            },
        )

        scope = _make_request_scope()
        request = Request(scope=scope)
        request._body = b""

        with (
            patch("bamf.proxy.kube.api_client.authorize", new_callable=AsyncMock) as mock_auth,
            patch("bamf.proxy.kube._get_kube_client"),
            patch("bamf.proxy.kube._forward", new_callable=AsyncMock) as mock_forward,
        ):
            mock_auth.return_value = auth_result
            mock_forward.return_value = forward_resp

            response = await kube_proxy(
                resource_name="prod-cluster",
                path="api/v1/pods",
                request=request,
            )

        # Hop-by-hop headers should be stripped from the upstream response.
        # Note: Starlette's Response auto-sets its own content-length from the
        # body, so content-length will reappear — but with the correct value
        # (matching the actual body), not the upstream's original value.
        assert "transfer-encoding" not in response.headers
        assert "connection" not in response.headers
        # content-length is re-added by Starlette based on actual body size
        assert response.headers.get("content-length") == str(len(b'{"items": []}'))
        # Custom headers should be preserved
        assert response.headers.get("x-custom-header") == "preserved"

    @pytest.mark.asyncio
    async def test_default_target_host_and_port(self):
        """When resource has no hostname/port, defaults to kubernetes.default.svc:6443."""
        from starlette.requests import Request

        from bamf.proxy.kube import kube_proxy

        auth_result = _make_auth_result(hostname=None, port=None)
        forward_resp = _make_httpx_response(status_code=200, content=b"{}")

        scope = _make_request_scope()
        request = Request(scope=scope)
        request._body = b""

        with (
            patch("bamf.proxy.kube.api_client.authorize", new_callable=AsyncMock) as mock_auth,
            patch("bamf.proxy.kube._get_kube_client"),
            patch("bamf.proxy.kube._forward", new_callable=AsyncMock) as mock_forward,
        ):
            mock_auth.return_value = auth_result
            mock_forward.return_value = forward_resp

            await kube_proxy(
                resource_name="prod-cluster",
                path="api/v1/pods",
                request=request,
            )

        headers = mock_forward.call_args[0][3]  # index 3 = headers dict
        assert headers["X-Bamf-Target"] == "https://kubernetes.default.svc:6443"
