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
	"time"

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
			name: "chunked with no content-length is not streaming",
			resp: &http.Response{
				Header:           http.Header{},
				ContentLength:    -1,
				TransferEncoding: []string{"chunked"},
			},
			expected: false, // Only SSE triggers detach; chunked JSON is finite
		},
		{
			name: "chunked SSE is streaming",
			resp: &http.Response{
				Header:           http.Header{"Content-Type": {"text/event-stream"}},
				ContentLength:    -1,
				TransferEncoding: []string{"chunked"},
			},
			expected: true,
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
		agentID: "test-agent",
		// The httptest servers these tests target listen on 127.0.0.1. The agent
		// only forwards to hosts in its resource config (isAllowedTarget, the SSRF
		// guard), so the loopback host must be a served resource here.
		resources: []ResourceConfig{{Name: "test", Hostname: "127.0.0.1"}},
		tlsConfig: &tls.Config{},
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func TestIsAllowedTarget(t *testing.T) {
	rm := &RelayManager{
		resources: []ResourceConfig{
			{Name: "web", Hostname: "grafana.internal.corp"},
			{Name: "k8s", Hostname: "kubernetes.default.svc"},
			{Name: "lo", Hostname: "127.0.0.1"},
		},
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	tests := []struct {
		name string
		host string
		want bool
	}{
		{"served host", "grafana.internal.corp", true},
		{"served k8s api", "kubernetes.default.svc", true},
		{"served loopback", "127.0.0.1", true},
		{"case-insensitive", "GRAFANA.Internal.Corp", true},
		{"unserved host", "evil.example.com", false},
		{"cloud metadata (SSRF pivot)", "169.254.169.254", false},
		{"empty", "", false},
		{"substring is not a match", "grafana.internal.corp.evil.com", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, rm.isAllowedTarget(tt.host))
		})
	}
}

// A target host the agent does not serve must be rejected with 403, even though
// the X-Bamf-Target header is well-formed — the agent must not be an SSRF pivot.
func TestForwardRequest_RejectsUnservedTarget(t *testing.T) {
	reached := false
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached = true
		w.WriteHeader(200)
	}))
	defer ts.Close()

	rm := &RelayManager{
		agentID:   "test-agent",
		resources: []ResourceConfig{{Name: "only", Hostname: "something-else.internal"}},
		tlsConfig: &tls.Config{},
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	req := &http.Request{
		Method: "GET",
		URL:    &url.URL{Path: "/"},
		Header: http.Header{"X-Bamf-Target": {ts.URL}}, // 127.0.0.1 — not served
		Body:   http.NoBody,
	}
	resp := rm.forwardRequest(req)
	require.Equal(t, http.StatusForbidden, resp.StatusCode)
	require.False(t, reached, "request must not reach an unserved target")
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
			"X-Bamf-Target":     {ts.URL},
			"X-Bamf-Resource":   {"app"},
			"Impersonate-User":  {"admin@evil.com"},
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

func TestRelayManager_RTT(t *testing.T) {
	rm := NewRelayManager("agent-1", nil, nil, slog.Default())

	// No dial has happened yet — no sample.
	_, ok := rm.RTT()
	require.False(t, ok)

	// The first sample seeds the EWMA exactly.
	rm.recordRTT(100 * time.Millisecond)
	rtt, ok := rm.RTT()
	require.True(t, ok)
	require.Equal(t, 100*time.Millisecond, rtt)

	// Subsequent samples move toward the new value (alpha=0.3):
	// 0.3*200ms + 0.7*100ms = 130ms.
	rm.recordRTT(200 * time.Millisecond)
	rtt, ok = rm.RTT()
	require.True(t, ok)
	require.Equal(t, 130*time.Millisecond, rtt)
}
