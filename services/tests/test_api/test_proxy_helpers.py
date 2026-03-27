"""Tests for pure helper functions in the proxy handler and kube modules.

Covers session/token extraction, browser request detection, auth error
response construction, bridge relay URL building, binary content-type
detection, and body capture logic. All functions under test are pure
(or nearly pure) and do not require database, Redis, or network access.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from bamf.proxy.handler import (
    BRIDGE_INTERNAL_PORT,
    HTTP_RECORDING_BODY_MAX,
    SESSION_COOKIE_NAME,
    _auth_error_response,
    _build_bridge_relay_url,
    _capture_body,
    _extract_session_token,
    _extract_ws_session_token,
    _is_binary_content_type,
    _is_browser_request,
)
from bamf.proxy.kube import (
    _build_bridge_relay_url as kube_build_bridge_relay_url,
)
from bamf.proxy.kube import (
    _extract_bearer_token as kube_extract_bearer_token,
)
from bamf.proxy.kube import (
    _extract_ws_bearer_token as kube_extract_ws_bearer_token,
)

# ── Mock factories ──────────────────────────────────────────────────────


def _make_request(
    headers: dict | None = None,
    cookies: dict | None = None,
    host: str = "grafana.tunnel.bamf.local",
    path: str = "/dashboard",
    query: str = "",
) -> MagicMock:
    """Build a mock Starlette/FastAPI Request."""
    req = MagicMock()
    req.headers = headers or {}
    req.cookies = cookies or {}
    req.url.path = path
    req.url.query = query
    # Needed by _auth_error_response
    req.headers = {**(headers or {})}
    if "host" not in req.headers:
        req.headers["host"] = host
    return req


def _make_websocket(
    headers: dict | None = None,
    cookies: dict | None = None,
    query_params: dict | None = None,
) -> MagicMock:
    """Build a mock Starlette WebSocket."""
    ws = MagicMock()
    ws.headers = headers or {}
    ws.cookies = cookies or {}
    ws.query_params = query_params or {}
    return ws


# ═══════════════════════════════════════════════════════════════════════
# handler.py helpers
# ═══════════════════════════════════════════════════════════════════════


class TestExtractSessionToken:
    """Tests for handler._extract_session_token."""

    def test_bearer_token_extracted(self):
        req = _make_request(headers={"authorization": "Bearer abc123"})
        assert _extract_session_token(req) == "abc123"

    def test_cookie_fallback(self):
        req = _make_request(cookies={SESSION_COOKIE_NAME: "from-cookie"})
        assert _extract_session_token(req) == "from-cookie"

    def test_bearer_takes_precedence_over_cookie(self):
        req = _make_request(
            headers={"authorization": "Bearer from-header"},
            cookies={SESSION_COOKIE_NAME: "from-cookie"},
        )
        assert _extract_session_token(req) == "from-header"

    def test_returns_none_when_absent(self):
        req = _make_request()
        assert _extract_session_token(req) is None

    def test_non_bearer_scheme_ignored(self):
        req = _make_request(headers={"authorization": "Basic dXNlcjpwYXNz"})
        assert _extract_session_token(req) is None

    def test_empty_bearer_returns_empty_string(self):
        req = _make_request(headers={"authorization": "Bearer "})
        assert _extract_session_token(req) == ""

    def test_bearer_case_sensitive(self):
        # "bearer" (lowercase) does not match — prefix check is case-sensitive
        req = _make_request(headers={"authorization": "bearer lowercase"})
        assert _extract_session_token(req) is None

    def test_bearer_with_long_token(self):
        token = "x" * 512
        req = _make_request(headers={"authorization": f"Bearer {token}"})
        assert _extract_session_token(req) == token

    def test_wrong_cookie_name_ignored(self):
        req = _make_request(cookies={"some_other_cookie": "val"})
        assert _extract_session_token(req) is None


class TestExtractWsSessionToken:
    """Tests for handler._extract_ws_session_token."""

    def test_query_param(self):
        ws = _make_websocket(query_params={"token": "ws-query"})
        assert _extract_ws_session_token(ws) == "ws-query"

    def test_bearer_header(self):
        ws = _make_websocket(headers={"authorization": "Bearer ws-bearer"})
        assert _extract_ws_session_token(ws) == "ws-bearer"

    def test_cookie_fallback(self):
        ws = _make_websocket(cookies={SESSION_COOKIE_NAME: "ws-cookie"})
        assert _extract_ws_session_token(ws) == "ws-cookie"

    def test_query_param_takes_precedence_over_header(self):
        ws = _make_websocket(
            headers={"authorization": "Bearer header-val"},
            query_params={"token": "query-val"},
        )
        assert _extract_ws_session_token(ws) == "query-val"

    def test_query_param_takes_precedence_over_cookie(self):
        ws = _make_websocket(
            cookies={SESSION_COOKIE_NAME: "cookie-val"},
            query_params={"token": "query-val"},
        )
        assert _extract_ws_session_token(ws) == "query-val"

    def test_bearer_takes_precedence_over_cookie(self):
        ws = _make_websocket(
            headers={"authorization": "Bearer bearer-val"},
            cookies={SESSION_COOKIE_NAME: "cookie-val"},
        )
        assert _extract_ws_session_token(ws) == "bearer-val"

    def test_returns_none_when_absent(self):
        ws = _make_websocket()
        assert _extract_ws_session_token(ws) is None

    def test_non_bearer_scheme_ignored_falls_to_cookie(self):
        ws = _make_websocket(
            headers={"authorization": "Basic abc"},
            cookies={SESSION_COOKIE_NAME: "cookie-val"},
        )
        assert _extract_ws_session_token(ws) == "cookie-val"


class TestIsBrowserRequest:
    """Tests for handler._is_browser_request."""

    def test_html_accept(self):
        req = _make_request(headers={"accept": "text/html"})
        assert _is_browser_request(req) is True

    def test_html_in_mixed_accept(self):
        req = _make_request(
            headers={"accept": "text/html,application/xhtml+xml,application/xml;q=0.9"}
        )
        assert _is_browser_request(req) is True

    def test_json_accept(self):
        req = _make_request(headers={"accept": "application/json"})
        assert _is_browser_request(req) is False

    def test_wildcard_accept(self):
        req = _make_request(headers={"accept": "*/*"})
        assert _is_browser_request(req) is False

    def test_no_accept_header(self):
        req = _make_request()
        assert _is_browser_request(req) is False

    def test_empty_accept_header(self):
        req = _make_request(headers={"accept": ""})
        assert _is_browser_request(req) is False

    def test_text_plain_not_browser(self):
        req = _make_request(headers={"accept": "text/plain"})
        assert _is_browser_request(req) is False


class TestAuthErrorResponse:
    """Tests for handler._auth_error_response."""

    def test_browser_request_gets_redirect(self):
        req = _make_request(
            headers={
                "accept": "text/html",
                "host": "grafana.tunnel.bamf.local",
            },
            path="/dashboard",
            query="",
        )
        resp = _auth_error_response(req)
        assert resp.status_code == 302
        location = resp.headers.get("location", "")
        assert "/login?" in location
        assert "redirect=" in location
        # The redirect target should encode the original URL
        assert "grafana.tunnel.bamf.local" in location

    def test_browser_request_preserves_query_string(self):
        req = _make_request(
            headers={
                "accept": "text/html",
                "host": "grafana.tunnel.bamf.local",
            },
            path="/page",
            query="tab=settings",
        )
        resp = _auth_error_response(req)
        assert resp.status_code == 302
        location = resp.headers.get("location", "")
        # Query string should appear in the redirect URL (URL-encoded)
        assert "tab" in location

    def test_api_request_gets_401(self):
        req = _make_request(
            headers={
                "accept": "application/json",
                "host": "grafana.tunnel.bamf.local",
            },
        )
        resp = _auth_error_response(req)
        assert resp.status_code == 401
        assert resp.headers.get("www-authenticate") == "Bearer"

    def test_no_accept_header_gets_401(self):
        req = _make_request(headers={"host": "grafana.tunnel.bamf.local"})
        resp = _auth_error_response(req)
        assert resp.status_code == 401


class TestBuildBridgeRelayUrl:
    """Tests for handler._build_bridge_relay_url."""

    def test_basic_url(self):
        url = _build_bridge_relay_url("bridge-0.headless.svc", "my-agent", "/api/data")
        assert url == f"http://bridge-0.headless.svc:{BRIDGE_INTERNAL_PORT}/relay/my-agent/api/data"

    def test_with_query_string(self):
        url = _build_bridge_relay_url("bridge-1", "agent-x", "/path", "foo=bar&baz=1")
        assert url.endswith("?foo=bar&baz=1")
        assert "/relay/agent-x/path" in url

    def test_without_query_string(self):
        url = _build_bridge_relay_url("bridge-1", "agent-x", "/path")
        assert "?" not in url

    def test_none_query_string(self):
        url = _build_bridge_relay_url("bridge-1", "agent-x", "/path", None)
        assert "?" not in url

    def test_empty_query_string(self):
        # Empty string is falsy, should not append ?
        url = _build_bridge_relay_url("bridge-1", "agent-x", "/path", "")
        assert "?" not in url

    def test_root_path(self):
        url = _build_bridge_relay_url("bridge-0", "agent-1", "/")
        assert url.endswith("/relay/agent-1/")

    def test_empty_path(self):
        url = _build_bridge_relay_url("bridge-0", "agent-1", "")
        assert url.endswith("/relay/agent-1")

    def test_url_uses_http_scheme(self):
        url = _build_bridge_relay_url("bridge-0", "agent-1", "/x")
        assert url.startswith("http://")

    def test_url_includes_bridge_internal_port(self):
        url = _build_bridge_relay_url("myhost", "agent", "/p")
        assert f":{BRIDGE_INTERNAL_PORT}/" in url


class TestIsBinaryContentType:
    """Tests for handler._is_binary_content_type."""

    @pytest.mark.parametrize(
        "ct",
        [
            "image/png",
            "image/jpeg",
            "image/gif",
            "image/webp",
            "audio/mpeg",
            "audio/ogg",
            "video/mp4",
            "video/webm",
            "font/woff2",
            "font/ttf",
            "application/octet-stream",
            "application/zip",
            "application/gzip",
            "application/pdf",
            "application/wasm",
        ],
    )
    def test_binary_types(self, ct: str):
        assert _is_binary_content_type(ct) is True

    @pytest.mark.parametrize(
        "ct",
        [
            "text/html",
            "text/plain",
            "text/css",
            "text/javascript",
            "application/json",
            "application/xml",
            "application/javascript",
            "application/x-www-form-urlencoded",
        ],
    )
    def test_text_types(self, ct: str):
        assert _is_binary_content_type(ct) is False

    def test_charset_suffix_ignored(self):
        assert _is_binary_content_type("image/png; charset=utf-8") is True
        assert _is_binary_content_type("text/html; charset=utf-8") is False

    def test_case_insensitive(self):
        assert _is_binary_content_type("IMAGE/PNG") is True
        assert _is_binary_content_type("Application/Octet-Stream") is True

    def test_empty_string(self):
        assert _is_binary_content_type("") is False


class TestCaptureBody:
    """Tests for handler._capture_body."""

    def test_text_body(self):
        result = _capture_body(b'{"key": "value"}', "application/json")
        assert result["body"] == '{"key": "value"}'
        assert result["body_truncated"] is False

    def test_empty_body(self):
        result = _capture_body(b"", "text/plain")
        assert result["body"] == ""
        assert result["body_truncated"] is False

    def test_binary_body_excluded(self):
        result = _capture_body(b"\x89PNG\r\n\x1a\n", "image/png")
        assert result["body"] is None
        assert result["body_size"] == 8
        assert result["body_truncated"] is False

    def test_large_body_truncated(self):
        big = b"a" * (HTTP_RECORDING_BODY_MAX + 500)
        result = _capture_body(big, "text/plain")
        assert result["body_truncated"] is True
        assert len(result["body"]) == HTTP_RECORDING_BODY_MAX

    def test_exact_limit_not_truncated(self):
        body = b"z" * HTTP_RECORDING_BODY_MAX
        result = _capture_body(body, "text/plain")
        assert result["body_truncated"] is False
        assert len(result["body"]) == HTTP_RECORDING_BODY_MAX

    def test_one_byte_over_limit_truncated(self):
        body = b"w" * (HTTP_RECORDING_BODY_MAX + 1)
        result = _capture_body(body, "text/plain")
        assert result["body_truncated"] is True

    def test_binary_body_records_size(self):
        data = b"\x00" * 1024
        result = _capture_body(data, "application/octet-stream")
        assert result["body"] is None
        assert result["body_size"] == 1024

    def test_utf8_replacement_on_invalid_bytes(self):
        # Invalid UTF-8 bytes should be replaced, not crash
        result = _capture_body(b"\x80\x81\x82", "text/plain")
        assert result["body_truncated"] is False
        # Each invalid byte becomes the replacement character
        assert "\ufffd" in result["body"]

    def test_html_body(self):
        html = b"<html><body>Hello</body></html>"
        result = _capture_body(html, "text/html")
        assert result["body"] == "<html><body>Hello</body></html>"
        assert result["body_truncated"] is False


# ═══════════════════════════════════════════════════════════════════════
# kube.py helpers
# ═══════════════════════════════════════════════════════════════════════


class TestKubeExtractBearerToken:
    """Tests for kube._extract_bearer_token."""

    def test_valid_bearer(self):
        req = _make_request(headers={"authorization": "Bearer kube-token"})
        assert kube_extract_bearer_token(req) == "kube-token"

    def test_no_auth_header(self):
        req = _make_request()
        assert kube_extract_bearer_token(req) is None

    def test_non_bearer_scheme(self):
        req = _make_request(headers={"authorization": "Basic abc"})
        assert kube_extract_bearer_token(req) is None

    def test_bearer_case_sensitive(self):
        req = _make_request(headers={"authorization": "bearer lowercase"})
        assert kube_extract_bearer_token(req) is None

    def test_empty_bearer_value(self):
        req = _make_request(headers={"authorization": "Bearer "})
        assert kube_extract_bearer_token(req) == ""

    def test_does_not_check_cookies(self):
        """kube._extract_bearer_token only checks Authorization header, never cookies."""
        req = _make_request(
            cookies={SESSION_COOKIE_NAME: "cookie-val"},
        )
        assert kube_extract_bearer_token(req) is None


class TestKubeExtractWsBearerToken:
    """Tests for kube._extract_ws_bearer_token."""

    def test_bearer_header(self):
        ws = _make_websocket(headers={"authorization": "Bearer ws-kube"})
        assert kube_extract_ws_bearer_token(ws) == "ws-kube"

    def test_query_param_fallback(self):
        ws = _make_websocket(query_params={"token": "query-kube"})
        assert kube_extract_ws_bearer_token(ws) == "query-kube"

    def test_header_takes_precedence_over_query(self):
        ws = _make_websocket(
            headers={"authorization": "Bearer header-val"},
            query_params={"token": "query-val"},
        )
        assert kube_extract_ws_bearer_token(ws) == "header-val"

    def test_no_token(self):
        ws = _make_websocket()
        assert kube_extract_ws_bearer_token(ws) is None

    def test_non_bearer_falls_through_to_query(self):
        ws = _make_websocket(
            headers={"authorization": "Basic abc"},
            query_params={"token": "from-query"},
        )
        assert kube_extract_ws_bearer_token(ws) == "from-query"

    def test_non_bearer_no_query_returns_none(self):
        ws = _make_websocket(headers={"authorization": "Basic abc"})
        assert kube_extract_ws_bearer_token(ws) is None


class TestKubeBuildBridgeRelayUrl:
    """Tests for kube._build_bridge_relay_url."""

    def test_basic_url(self):
        from bamf.proxy.kube import BRIDGE_INTERNAL_PORT as KUBE_PORT

        url = kube_build_bridge_relay_url("bridge-0.svc", "my-agent", "/api/v1/pods")
        expected = f"http://bridge-0.svc:{KUBE_PORT}/relay/my-agent/api/v1/pods"
        assert url == expected

    def test_with_query_string(self):
        url = kube_build_bridge_relay_url("bridge-1", "agent-2", "/path", "watch=true&limit=10")
        assert url.endswith("?watch=true&limit=10")

    def test_without_query_string(self):
        url = kube_build_bridge_relay_url("bridge-1", "agent-2", "/path")
        assert "?" not in url

    def test_none_query_string(self):
        url = kube_build_bridge_relay_url("bridge-1", "agent-2", "/path", None)
        assert "?" not in url

    def test_empty_query_string(self):
        url = kube_build_bridge_relay_url("bridge-1", "agent-2", "/path", "")
        assert "?" not in url

    def test_empty_path(self):
        url = kube_build_bridge_relay_url("bridge-0", "agent-1", "")
        assert url.endswith("/relay/agent-1")

    def test_nested_k8s_path(self):
        url = kube_build_bridge_relay_url(
            "bridge-0", "agent-1", "/api/v1/namespaces/default/pods/mypod/exec"
        )
        assert "/relay/agent-1/api/v1/namespaces/default/pods/mypod/exec" in url


# ═══════════════════════════════════════════════════════════════════════
# Cross-module consistency checks
# ═══════════════════════════════════════════════════════════════════════


class TestCrossModuleConsistency:
    """Verify that handler and kube URL builders use the same port."""

    def test_same_bridge_internal_port(self):
        from bamf.proxy.kube import BRIDGE_INTERNAL_PORT as KUBE_PORT

        assert BRIDGE_INTERNAL_PORT == KUBE_PORT

    def test_handler_and_kube_url_format_matches(self):
        """Both modules should produce identically structured relay URLs."""
        handler_url = _build_bridge_relay_url("bridge-0", "agent-1", "/foo", "bar=1")
        kube_url = kube_build_bridge_relay_url("bridge-0", "agent-1", "/foo", "bar=1")
        assert handler_url == kube_url
