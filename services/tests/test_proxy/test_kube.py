"""Tests for Kubernetes proxy pure functions.

Tests bearer token extraction from HTTP and WebSocket requests,
and bridge relay URL construction.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from bamf.proxy.kube import (
    _build_bridge_relay_url,
    _extract_bearer_token,
    _extract_ws_bearer_token,
)

# ── Helpers ──────────────────────────────────────────────────────────────


def _make_request(headers: dict | None = None) -> MagicMock:
    req = MagicMock()
    req.headers = headers or {}
    return req


def _make_websocket(
    headers: dict | None = None,
    query_params: dict | None = None,
) -> MagicMock:
    ws = MagicMock()
    ws.headers = headers or {}
    ws.query_params = query_params or {}
    return ws


# ── Tests: _extract_bearer_token ─────────────────────────────────────────


class TestExtractBearerToken:
    def test_valid_bearer(self):
        req = _make_request(headers={"authorization": "Bearer my-token"})
        assert _extract_bearer_token(req) == "my-token"

    def test_no_auth_header(self):
        req = _make_request()
        assert _extract_bearer_token(req) is None

    def test_non_bearer_scheme(self):
        req = _make_request(headers={"authorization": "Basic abc"})
        assert _extract_bearer_token(req) is None

    def test_bearer_prefix_case_sensitive(self):
        req = _make_request(headers={"authorization": "bearer lowercase"})
        assert _extract_bearer_token(req) is None

    def test_empty_bearer(self):
        req = _make_request(headers={"authorization": "Bearer "})
        assert _extract_bearer_token(req) == ""


# ── Tests: _extract_ws_bearer_token ──────────────────────────────────────


class TestExtractWsBearerToken:
    def test_header(self):
        ws = _make_websocket(headers={"authorization": "Bearer ws-token"})
        assert _extract_ws_bearer_token(ws) == "ws-token"

    def test_query_param(self):
        ws = _make_websocket(query_params={"token": "query-token"})
        assert _extract_ws_bearer_token(ws) == "query-token"

    def test_header_takes_precedence(self):
        ws = _make_websocket(
            headers={"authorization": "Bearer header-val"},
            query_params={"token": "query-val"},
        )
        assert _extract_ws_bearer_token(ws) == "header-val"

    def test_no_token(self):
        ws = _make_websocket()
        assert _extract_ws_bearer_token(ws) is None


# ── Tests: _build_bridge_relay_url ───────────────────────────────────────


class TestBuildBridgeRelayUrl:
    def test_basic_url(self):
        url = _build_bridge_relay_url("bridge-0.svc", "my-agent", "/api/v1/pods")
        assert "/relay/my-agent/api/v1/pods" in url
        assert url.startswith("http://bridge-0.svc:")

    def test_with_query_string(self):
        url = _build_bridge_relay_url("bridge-1", "agent-2", "/path", "watch=true")
        assert url.endswith("?watch=true")

    def test_without_query_string(self):
        url = _build_bridge_relay_url("bridge-1", "agent-2", "/path")
        assert "?" not in url

    def test_empty_path(self):
        url = _build_bridge_relay_url("bridge-0", "agent-1", "")
        assert "/relay/agent-1" in url
