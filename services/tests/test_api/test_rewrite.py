"""Tests for the HTTP proxy header rewriting module."""

from bamf.api.proxy.rewrite import (
    rewrite_request_headers,
    rewrite_response_headers,
    rewrite_set_cookie,
)


class TestRewriteRequestHeaders:
    """Test rewrite_request_headers() for proxy header transformation."""

    def _base_kwargs(self) -> dict:
        return {
            "tunnel_hostname": "grafana",
            "tunnel_domain": "tunnel.bamf.local",
            "target_host": "grafana.internal",
            "target_port": 3000,
            "target_protocol": "http",
            "user_email": "alice@example.com",
            "user_roles": ["developer"],
            "client_ip": "10.0.0.1",
        }

    def test_hop_by_hop_stripped(self):
        """Standard hop-by-hop headers are removed."""
        headers = {
            "accept-encoding": "gzip, deflate, br",
            "connection": "keep-alive",
            "keep-alive": "timeout=5",
            "transfer-encoding": "chunked",
            "te": "trailers",
            "trailer": "Expires",
            "proxy-authorization": "Basic abc",
            "proxy-authenticate": "Basic",
            "accept": "text/html",
        }
        result = rewrite_request_headers(headers=headers, **self._base_kwargs())
        assert "connection" not in result
        assert "keep-alive" not in result
        assert "transfer-encoding" not in result
        assert "te" not in result
        assert "trailer" not in result
        assert "proxy-authorization" not in result
        assert "proxy-authenticate" not in result
        assert "accept" in result

    def test_accept_encoding_forced_identity(self):
        """Accept-Encoding is replaced with 'identity' to prevent target compression."""
        headers = {"accept-encoding": "gzip, deflate, br"}
        result = rewrite_request_headers(headers=headers, **self._base_kwargs())
        assert result["Accept-Encoding"] == "identity"

    def test_upgrade_header_preserved(self):
        """Upgrade header is NOT stripped — needed for WebSocket proxying."""
        headers = {
            "upgrade": "websocket",
            "connection": "Upgrade",
            "sec-websocket-key": "dGhlIHNhbXBsZSBub25jZQ==",
            "sec-websocket-version": "13",
        }
        result = rewrite_request_headers(headers=headers, **self._base_kwargs())
        assert result["upgrade"] == "websocket"
        # Connection should be preserved for upgrade requests
        assert result["connection"] == "Upgrade"
        assert result["sec-websocket-key"] == "dGhlIHNhbXBsZSBub25jZQ=="

    def test_connection_stripped_without_upgrade(self):
        """Connection header is stripped when there is no Upgrade header."""
        headers = {
            "connection": "keep-alive",
            "accept": "text/html",
        }
        result = rewrite_request_headers(headers=headers, **self._base_kwargs())
        assert "connection" not in result

    def test_host_rewritten_to_target(self):
        """Host header is rewritten to the target's internal hostname:port."""
        headers = {"host": "grafana.tunnel.bamf.local"}
        result = rewrite_request_headers(headers=headers, **self._base_kwargs())
        assert result["Host"] == "grafana.internal:3000"

    def test_bamf_target_header_set(self):
        """X-Bamf-Target header is set with the target origin."""
        headers = {}
        result = rewrite_request_headers(headers=headers, **self._base_kwargs())
        assert result["X-Bamf-Target"] == "http://grafana.internal:3000"

    def test_forwarded_headers_set(self):
        """X-Forwarded-* headers are injected."""
        headers = {}
        result = rewrite_request_headers(headers=headers, **self._base_kwargs())
        assert result["X-Forwarded-Host"] == "grafana.tunnel.bamf.local"
        assert result["X-Forwarded-Proto"] == "https"
        assert result["X-Forwarded-User"] == "alice@example.com"
        assert result["X-Forwarded-Email"] == "alice@example.com"
        assert result["X-Forwarded-For"] == "10.0.0.1"
        assert result["X-Forwarded-Roles"] == "developer"

    def test_authorization_stripped(self):
        """Authorization header (BAMF Bearer) is stripped from proxied requests."""
        headers = {"authorization": "Bearer bamf-session-token"}
        result = rewrite_request_headers(headers=headers, **self._base_kwargs())
        assert "authorization" not in result

    def test_bamf_cookie_stripped(self):
        """bamf_session cookie is removed but other cookies pass through."""
        headers = {"cookie": "bamf_session=abc123; other_cookie=xyz"}
        result = rewrite_request_headers(headers=headers, **self._base_kwargs())
        assert "bamf_session" not in result.get("cookie", "")
        assert "other_cookie=xyz" in result["cookie"]

    def test_kubernetes_groups_injected(self):
        """X-Forwarded-Groups header is injected when kubernetes_groups is provided."""
        headers = {}
        result = rewrite_request_headers(
            headers=headers,
            **self._base_kwargs(),
            kubernetes_groups=["system:masters", "developers"],
        )
        assert result["X-Forwarded-Groups"] == "system:masters,developers"

    def test_kubernetes_groups_empty_not_injected(self):
        """X-Forwarded-Groups header is NOT injected when kubernetes_groups is empty."""
        headers = {}
        result = rewrite_request_headers(
            headers=headers,
            **self._base_kwargs(),
            kubernetes_groups=[],
        )
        assert "X-Forwarded-Groups" not in result

    def test_kubernetes_groups_none_not_injected(self):
        """X-Forwarded-Groups header is NOT injected when kubernetes_groups is None."""
        headers = {}
        result = rewrite_request_headers(
            headers=headers,
            **self._base_kwargs(),
            kubernetes_groups=None,
        )
        assert "X-Forwarded-Groups" not in result

    def test_kubernetes_groups_single(self):
        """X-Forwarded-Groups works with a single group."""
        headers = {}
        result = rewrite_request_headers(
            headers=headers,
            **self._base_kwargs(),
            kubernetes_groups=["view"],
        )
        assert result["X-Forwarded-Groups"] == "view"

    def test_content_length_preserved(self):
        """Content-Length passes through on requests (needed for POST bodies)."""
        headers = {"content-length": "42", "content-type": "application/json"}
        result = rewrite_request_headers(headers=headers, **self._base_kwargs())
        assert result["content-length"] == "42"

    def test_content_encoding_preserved(self):
        """Content-Encoding passes through on requests."""
        headers = {"content-encoding": "gzip", "content-type": "application/json"}
        result = rewrite_request_headers(headers=headers, **self._base_kwargs())
        assert result["content-encoding"] == "gzip"


class TestRewriteResponseHeaders:
    """Test rewrite_response_headers() for proxy response transformation."""

    def _base_kwargs(self) -> dict:
        return {
            "tunnel_hostname": "grafana",
            "tunnel_domain": "tunnel.bamf.local",
            "target_host": "grafana.internal",
            "target_port": 3000,
            "target_protocol": "http",
        }

    def test_location_rewritten(self):
        """Location redirect from target hostname is rewritten to tunnel hostname."""
        headers = {"location": "http://grafana.internal:3000/dashboard"}
        result = rewrite_response_headers(headers=headers, **self._base_kwargs())
        assert result["location"] == "https://grafana.tunnel.bamf.local/dashboard"

    def test_set_cookie_domain_rewritten(self):
        """Set-Cookie domain is rewritten to tunnel hostname."""
        headers = {"set-cookie": "session=abc; domain=grafana.internal; path=/"}
        result = rewrite_response_headers(headers=headers, **self._base_kwargs())
        assert "domain=grafana.tunnel.bamf.local" in result["set-cookie"]

    def test_cors_origin_rewritten(self):
        """Access-Control-Allow-Origin is rewritten to tunnel origin."""
        headers = {"access-control-allow-origin": "http://grafana.internal:3000"}
        result = rewrite_response_headers(headers=headers, **self._base_kwargs())
        assert result["access-control-allow-origin"] == "https://grafana.tunnel.bamf.local"

    def test_hop_by_hop_stripped(self):
        """Hop-by-hop headers are stripped from responses."""
        headers = {
            "connection": "keep-alive",
            "transfer-encoding": "chunked",
            "content-type": "text/html",
        }
        result = rewrite_response_headers(headers=headers, **self._base_kwargs())
        assert "connection" not in result
        assert "transfer-encoding" not in result
        assert "content-type" in result

    def test_upgrade_preserved_for_101(self):
        """Upgrade and Connection headers preserved when is_upgrade=True."""
        headers = {
            "upgrade": "websocket",
            "connection": "Upgrade",
            "sec-websocket-accept": "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
        }
        result = rewrite_response_headers(headers=headers, **self._base_kwargs(), is_upgrade=True)
        assert result["upgrade"] == "websocket"
        assert result["connection"] == "Upgrade"
        assert result["sec-websocket-accept"] == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="

    def test_upgrade_stripped_when_not_upgrade_response(self):
        """Upgrade header stripped in normal (non-101) responses."""
        headers = {
            "upgrade": "websocket",
            "content-type": "text/html",
        }
        result = rewrite_response_headers(headers=headers, **self._base_kwargs())
        assert "upgrade" not in result
        assert "content-type" in result

    def test_connection_stripped_when_not_upgrade(self):
        """Connection header stripped when is_upgrade is False (default)."""
        headers = {"connection": "keep-alive", "content-type": "text/html"}
        result = rewrite_response_headers(headers=headers, **self._base_kwargs())
        assert "connection" not in result

    def test_content_length_stripped_response(self):
        """Content-Length is stripped from responses (Starlette re-adds from body)."""
        headers = {"content-length": "1234", "content-type": "text/html"}
        result = rewrite_response_headers(headers=headers, **self._base_kwargs())
        assert "content-length" not in result

    def test_content_encoding_stripped_response(self):
        """Content-Encoding is stripped from responses (Starlette re-adds from body)."""
        headers = {"content-encoding": "gzip", "content-type": "text/html"}
        result = rewrite_response_headers(headers=headers, **self._base_kwargs())
        assert "content-encoding" not in result

    def test_csp_rewritten(self):
        """CSP absolute URLs are replaced with tunnel origin."""
        headers = {
            "content-security-policy": "default-src 'self' http://grafana.internal:3000; img-src *"
        }
        result = rewrite_response_headers(headers=headers, **self._base_kwargs())
        assert (
            result["content-security-policy"]
            == "default-src 'self' https://grafana.tunnel.bamf.local; img-src *"
        )

    def test_csp_rewritten_without_port(self):
        """CSP URLs without port are rewritten."""
        headers = {"content-security-policy": "connect-src http://grafana.internal/api"}
        result = rewrite_response_headers(headers=headers, **self._base_kwargs())
        assert (
            result["content-security-policy"] == "connect-src https://grafana.tunnel.bamf.local/api"
        )

    def test_csp_no_match_passthrough(self):
        """CSP without target URLs passes through unchanged."""
        headers = {"content-security-policy": "default-src 'self'; script-src 'unsafe-inline'"}
        result = rewrite_response_headers(headers=headers, **self._base_kwargs())
        assert result["content-security-policy"] == "default-src 'self'; script-src 'unsafe-inline'"


class TestRewriteSetCookie:
    """Test rewrite_set_cookie() for individual Set-Cookie header rewriting."""

    def test_domain_rewritten(self):
        """domain= attribute is rewritten to tunnel hostname."""
        result = rewrite_set_cookie(
            "session=abc; domain=grafana.internal; path=/",
            target_host="grafana.internal",
            tunnel_hostname="grafana",
            tunnel_domain="tunnel.bamf.local",
        )
        assert "domain=grafana.tunnel.bamf.local" in result
        assert "domain=grafana.internal" not in result

    def test_no_domain_passthrough(self):
        """Cookie without domain attribute passes through unchanged."""
        original = "session=abc; path=/; HttpOnly"
        result = rewrite_set_cookie(
            original,
            target_host="grafana.internal",
            tunnel_hostname="grafana",
            tunnel_domain="tunnel.bamf.local",
        )
        assert result == original
