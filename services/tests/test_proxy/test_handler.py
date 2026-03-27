"""Tests for HTTP proxy handler pure functions.

Tests session token extraction, browser request detection,
auth error responses, bridge relay URL construction, binary content
type detection, and body capture logic.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from bamf.proxy.handler import (
    HTTP_RECORDING_BODY_MAX,
    SESSION_COOKIE_NAME,
    _build_bridge_relay_url,
    _capture_body,
    _extract_session_token,
    _extract_ws_session_token,
    _is_binary_content_type,
    _is_browser_request,
)

# ── Helpers ──────────────────────────────────────────────────────────────


def _make_request(
    headers: dict | None = None,
    cookies: dict | None = None,
) -> MagicMock:
    req = MagicMock()
    req.headers = headers or {}
    req.cookies = cookies or {}
    return req


def _make_websocket(
    headers: dict | None = None,
    cookies: dict | None = None,
    query_params: dict | None = None,
) -> MagicMock:
    ws = MagicMock()
    ws.headers = headers or {}
    ws.cookies = cookies or {}
    ws.query_params = query_params or {}
    return ws


# ── Tests: _extract_session_token ────────────────────────────────────────


class TestExtractSessionToken:
    def test_bearer_token(self):
        req = _make_request(headers={"authorization": "Bearer my-token"})
        assert _extract_session_token(req) == "my-token"

    def test_cookie(self):
        req = _make_request(cookies={SESSION_COOKIE_NAME: "cookie-token"})
        assert _extract_session_token(req) == "cookie-token"

    def test_bearer_takes_precedence_over_cookie(self):
        req = _make_request(
            headers={"authorization": "Bearer bearer-token"},
            cookies={SESSION_COOKIE_NAME: "cookie-token"},
        )
        assert _extract_session_token(req) == "bearer-token"

    def test_no_token(self):
        req = _make_request()
        assert _extract_session_token(req) is None

    def test_non_bearer_auth(self):
        req = _make_request(headers={"authorization": "Basic abc123"})
        assert _extract_session_token(req) is None


# ── Tests: _extract_ws_session_token ─────────────────────────────────────


class TestExtractWsSessionToken:
    def test_query_param(self):
        ws = _make_websocket(query_params={"token": "ws-token"})
        assert _extract_ws_session_token(ws) == "ws-token"

    def test_bearer_header(self):
        ws = _make_websocket(headers={"authorization": "Bearer ws-bearer"})
        assert _extract_ws_session_token(ws) == "ws-bearer"

    def test_cookie_fallback(self):
        ws = _make_websocket(cookies={SESSION_COOKIE_NAME: "ws-cookie"})
        assert _extract_ws_session_token(ws) == "ws-cookie"

    def test_query_param_takes_precedence(self):
        ws = _make_websocket(
            headers={"authorization": "Bearer bearer-val"},
            query_params={"token": "query-val"},
        )
        assert _extract_ws_session_token(ws) == "query-val"

    def test_no_token(self):
        ws = _make_websocket()
        assert _extract_ws_session_token(ws) is None


# ── Tests: _is_browser_request ───────────────────────────────────────────


class TestIsBrowserRequest:
    def test_browser_accept(self):
        req = _make_request(headers={"accept": "text/html,application/xhtml+xml"})
        assert _is_browser_request(req) is True

    def test_api_accept(self):
        req = _make_request(headers={"accept": "application/json"})
        assert _is_browser_request(req) is False

    def test_no_accept(self):
        req = _make_request()
        assert _is_browser_request(req) is False


# ── Tests: _build_bridge_relay_url ───────────────────────────────────────


class TestBuildBridgeRelayUrl:
    def test_basic(self):
        url = _build_bridge_relay_url("bridge-0.svc", "agent-1", "/api/pods")
        assert "/relay/agent-1/api/pods" in url
        assert url.startswith("http://bridge-0.svc:")

    def test_with_query(self):
        url = _build_bridge_relay_url("bridge-0", "agent-1", "/path", "key=val")
        assert url.endswith("?key=val")

    def test_without_query(self):
        url = _build_bridge_relay_url("bridge-0", "agent-1", "/path")
        assert "?" not in url


# ── Tests: _is_binary_content_type ───────────────────────────────────────


class TestIsBinaryContentType:
    @pytest.mark.parametrize(
        "ct",
        [
            "image/png",
            "image/jpeg",
            "audio/mpeg",
            "video/mp4",
            "font/woff2",
            "application/octet-stream",
            "application/zip",
            "application/gzip",
            "application/pdf",
            "application/wasm",
        ],
    )
    def test_binary_types(self, ct):
        assert _is_binary_content_type(ct) is True

    @pytest.mark.parametrize(
        "ct",
        [
            "text/html",
            "application/json",
            "text/plain",
            "application/xml",
            "text/css",
        ],
    )
    def test_text_types(self, ct):
        assert _is_binary_content_type(ct) is False

    def test_with_charset(self):
        assert _is_binary_content_type("image/png; charset=utf-8") is True
        assert _is_binary_content_type("text/html; charset=utf-8") is False


# ── Tests: _capture_body ────────────────────────────────────────────────


class TestCaptureBody:
    def test_text_body(self):
        result = _capture_body(b'{"key": "value"}', "application/json")
        assert result["body"] == '{"key": "value"}'
        assert result["body_truncated"] is False

    def test_empty_body(self):
        result = _capture_body(b"", "text/plain")
        assert result["body"] == ""
        assert result["body_truncated"] is False

    def test_binary_body_skipped(self):
        result = _capture_body(b"\x89PNG\r\n", "image/png")
        assert result["body"] is None
        assert "body_size" in result

    def test_large_body_truncated(self):
        big_body = b"x" * (HTTP_RECORDING_BODY_MAX + 100)
        result = _capture_body(big_body, "text/plain")
        assert result["body_truncated"] is True
        assert len(result["body"]) == HTTP_RECORDING_BODY_MAX

    def test_exact_limit(self):
        body = b"y" * HTTP_RECORDING_BODY_MAX
        result = _capture_body(body, "text/plain")
        assert result["body_truncated"] is False
        assert len(result["body"]) == HTTP_RECORDING_BODY_MAX
