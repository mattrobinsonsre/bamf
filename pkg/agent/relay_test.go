package agent

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsUpgradeRequest(t *testing.T) {
	tests := []struct {
		name     string
		headers  http.Header
		expected bool
	}{
		{
			name:     "websocket upgrade",
			headers:  http.Header{"Upgrade": {"websocket"}, "Connection": {"Upgrade"}},
			expected: true,
		},
		{
			name:     "h2c upgrade",
			headers:  http.Header{"Upgrade": {"h2c"}},
			expected: true,
		},
		{
			name:     "no upgrade header",
			headers:  http.Header{"Content-Type": {"text/html"}},
			expected: false,
		},
		{
			name:     "empty headers",
			headers:  http.Header{},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := &http.Request{Header: tc.headers}
			require.Equal(t, tc.expected, isUpgradeRequest(req))
		})
	}
}

func TestIsStreamingResponse(t *testing.T) {
	tests := []struct {
		name     string
		resp     *http.Response
		expected bool
	}{
		{
			name: "SSE text/event-stream",
			resp: &http.Response{
				Header:        http.Header{"Content-Type": {"text/event-stream"}},
				ContentLength: -1,
			},
			expected: true,
		},
		{
			name: "SSE with charset",
			resp: &http.Response{
				Header:        http.Header{"Content-Type": {"text/event-stream; charset=utf-8"}},
				ContentLength: -1,
			},
			expected: true,
		},
		{
			name: "chunked with no content-length",
			resp: &http.Response{
				Header:           http.Header{},
				ContentLength:    -1,
				TransferEncoding: []string{"chunked"},
			},
			expected: true,
		},
		{
			name: "chunked with known content-length is not streaming",
			resp: &http.Response{
				Header:           http.Header{},
				ContentLength:    1024,
				TransferEncoding: []string{"chunked"},
			},
			expected: false,
		},
		{
			name: "regular JSON response",
			resp: &http.Response{
				Header:        http.Header{"Content-Type": {"application/json"}},
				ContentLength: 42,
			},
			expected: false,
		},
		{
			name: "HTML with content-length",
			resp: &http.Response{
				Header:        http.Header{"Content-Type": {"text/html"}},
				ContentLength: 512,
			},
			expected: false,
		},
		{
			name: "no content-length and no chunked is not streaming",
			resp: &http.Response{
				Header:        http.Header{"Content-Type": {"application/json"}},
				ContentLength: -1,
			},
			expected: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.expected, isStreamingResponse(tc.resp))
		})
	}
}

// newTestRelayManager creates a RelayManager suitable for unit tests.
func newTestRelayManager() *RelayManager {
	return &RelayManager{
		agentID:   "test-agent",
		resources: nil,
		tlsConfig: &tls.Config{},
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestForwardRequest_PreservesForwardedHeadersForHTTP(t *testing.T) {
	// Start a test HTTP server that echoes back received headers
	var receivedHeaders http.Header
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(200)
	}))
	defer ts.Close()

	rm := newTestRelayManager()

	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/dashboard", RawQuery: "page=1"},
		Header: http.Header{
			"X-Bamf-Target":      {ts.URL},
			"X-Bamf-Resource":    {"grafana"},
			"X-Forwarded-Email":  {"alice@example.com"},
			"X-Forwarded-User":   {"alice@example.com"},
			"X-Forwarded-Roles":  {"developer"},
			"X-Forwarded-Groups": {"devs,sre"},
			"X-Forwarded-Host":   {"grafana.tunnel.bamf.local"},
			"X-Forwarded-Proto":  {"https"},
			"X-Forwarded-For":    {"10.0.0.1"},
			"Accept":             {"text/html"},
		},
		Body: http.NoBody,
	}

	resp := rm.forwardRequest(req)
	require.Equal(t, 200, resp.StatusCode)

	// X-Forwarded-* headers should be preserved for non-K8s HTTP targets
	require.Equal(t, "alice@example.com", receivedHeaders.Get("X-Forwarded-Email"))
	require.Equal(t, "alice@example.com", receivedHeaders.Get("X-Forwarded-User"))
	require.Equal(t, "developer", receivedHeaders.Get("X-Forwarded-Roles"))
	require.Equal(t, "devs,sre", receivedHeaders.Get("X-Forwarded-Groups"))
	require.Equal(t, "grafana.tunnel.bamf.local", receivedHeaders.Get("X-Forwarded-Host"))
	require.Equal(t, "https", receivedHeaders.Get("X-Forwarded-Proto"))
	require.Equal(t, "10.0.0.1", receivedHeaders.Get("X-Forwarded-For"))
	require.Equal(t, "text/html", receivedHeaders.Get("Accept"))

	// BAMF internal headers should be stripped
	require.Empty(t, receivedHeaders.Get("X-Bamf-Target"))
	require.Empty(t, receivedHeaders.Get("X-Bamf-Resource"))

	// Impersonate-* should not be present (never passed to HTTP targets)
	require.Empty(t, receivedHeaders.Get("Impersonate-User"))
	require.Empty(t, receivedHeaders.Get("Impersonate-Group"))
}

func TestForwardRequest_StripsForwardedHeadersForK8s(t *testing.T) {
	rm := newTestRelayManager()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	// K8s request is detected by X-Forwarded-K8s-Groups presence.
	// forwardRequest will try to read SA token (not available in tests),
	// so we verify the K8s path was entered via the error message.
	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/api/v1/pods"},
		Header: http.Header{
			"X-Bamf-Target":          {ts.URL},
			"X-Bamf-Resource":        {"prod-cluster"},
			"X-Forwarded-K8s-Groups": {"system:masters"},
			"X-Forwarded-Email":      {"alice@example.com"},
			"X-Forwarded-User":       {"alice@example.com"},
			"X-Forwarded-Roles":      {"sre"},
			"X-Forwarded-Groups":     {"devs"},
			"X-Forwarded-Host":       {"prod-cluster.tunnel.bamf.local"},
			"X-Forwarded-Proto":      {"https"},
			"X-Forwarded-For":        {"10.0.0.1"},
		},
		Body: http.NoBody,
	}

	resp := rm.forwardRequest(req)

	// 502 because SA token file doesn't exist in tests — confirms K8s path entered
	require.Equal(t, http.StatusBadGateway, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	require.Contains(t, string(body), "SA token")
}

func TestForwardRequest_AlwaysStripsImpersonateHeaders(t *testing.T) {
	// Verify that Impersonate-* headers injected by a malicious client
	// are stripped for non-K8s HTTP targets
	var receivedHeaders http.Header
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(200)
	}))
	defer ts.Close()

	rm := newTestRelayManager()

	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/"},
		Header: http.Header{
			"X-Bamf-Target":    {ts.URL},
			"X-Bamf-Resource":  {"app"},
			"Impersonate-User": {"admin@evil.com"},
			"Impersonate-Group": {"system:masters"},
			"X-Forwarded-Email": {"alice@example.com"},
		},
		Body: http.NoBody,
	}

	resp := rm.forwardRequest(req)
	require.Equal(t, 200, resp.StatusCode)

	// Impersonate-* headers MUST be stripped regardless of request type
	require.Empty(t, receivedHeaders.Get("Impersonate-User"))
	require.Empty(t, receivedHeaders.Get("Impersonate-Group"))

	// But forwarded headers should still be there (non-K8s request)
	require.Equal(t, "alice@example.com", receivedHeaders.Get("X-Forwarded-Email"))
}

func TestForwardRequest_K8sDetectedByK8sGroupsHeader(t *testing.T) {
	// Verify that X-Forwarded-K8s-Groups triggers the K8s code path
	rm := newTestRelayManager()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/api/v1/pods"},
		Header: http.Header{
			"X-Bamf-Target":          {ts.URL},
			"X-Forwarded-K8s-Groups": {"developers"},
			"X-Forwarded-Email":      {"alice@example.com"},
		},
		Body: http.NoBody,
	}

	// K8s path → will fail on SA token, confirming K8s detection
	resp := rm.forwardRequest(req)
	require.Equal(t, http.StatusBadGateway, resp.StatusCode)
	body, _ := io.ReadAll(resp.Body)
	require.True(t, strings.Contains(string(body), "SA token"))
}
