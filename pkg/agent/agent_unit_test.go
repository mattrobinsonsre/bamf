package agent

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ── Tests: generateInstanceID ────────────────────────────────────────

func TestGenerateInstanceID_Format(t *testing.T) {
	id := generateInstanceID()
	// UUID v4 hex format: 8-4-4-4-12
	matched, err := regexp.MatchString(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`, id)
	require.NoError(t, err)
	require.True(t, matched, "ID %q does not match UUID v4 format", id)
}

func TestGenerateInstanceID_Unique(t *testing.T) {
	ids := make(map[string]bool, 100)
	for range 100 {
		id := generateInstanceID()
		require.False(t, ids[id], "duplicate ID generated: %s", id)
		ids[id] = true
	}
}

// ── Tests: calculateBackoff ──────────────────────────────────────────

func TestCalculateBackoff(t *testing.T) {
	tests := []struct {
		name       string
		base       time.Duration
		max        time.Duration
		jitter     float64
		wantExact  bool
		wantResult time.Duration
	}{
		{
			name:       "zero jitter returns base",
			base:       1 * time.Second,
			max:        5 * time.Minute,
			jitter:     0.0,
			wantExact:  true,
			wantResult: 1 * time.Second,
		},
		{
			name:       "result capped at max",
			base:       10 * time.Minute,
			max:        5 * time.Minute,
			jitter:     0.5,
			wantExact:  true,
			wantResult: 5 * time.Minute,
		},
		{
			name:       "base plus jitter within max",
			base:       1 * time.Second,
			max:        5 * time.Minute,
			jitter:     0.2,
			wantExact:  true,
			wantResult: 1200 * time.Millisecond, // 1s + 0.2*1s
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Agent{
				cfg: &Config{
					ReconnectBaseDelay:   tt.base,
					ReconnectMaxDelay:    tt.max,
					ReconnectJitterRatio: tt.jitter,
				},
			}
			result := a.calculateBackoff()
			if tt.wantExact {
				require.Equal(t, tt.wantResult, result)
			} else {
				require.LessOrEqual(t, result, tt.max)
			}
		})
	}
}

// ── Tests: handleHealth ──────────────────────────────────────────────

func TestHandleHealth(t *testing.T) {
	a := &Agent{logger: slog.New(slog.NewTextHandler(io.Discard, nil))}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	a.handleHealth(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "ok", rec.Body.String())
}

// ── Tests: handleReady ───────────────────────────────────────────────

func TestHandleReady(t *testing.T) {
	tests := []struct {
		name         string
		registered   bool
		sseConnected bool
		wantCode     int
		wantBody     string
	}{
		{
			name:         "not registered",
			registered:   false,
			sseConnected: false,
			wantCode:     http.StatusServiceUnavailable,
			wantBody:     "not ready",
		},
		{
			name:         "registered but no SSE",
			registered:   true,
			sseConnected: false,
			wantCode:     http.StatusServiceUnavailable,
			wantBody:     "not ready",
		},
		{
			name:         "SSE connected but not registered",
			registered:   false,
			sseConnected: true,
			wantCode:     http.StatusServiceUnavailable,
			wantBody:     "not ready",
		},
		{
			name:         "fully ready",
			registered:   true,
			sseConnected: true,
			wantCode:     http.StatusOK,
			wantBody:     "ready",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &Agent{
				logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
				registered: tt.registered,
			}
			a.sseConnected.Store(tt.sseConnected)

			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "/ready", nil)
			a.handleReady(rec, req)

			require.Equal(t, tt.wantCode, rec.Code)
			require.Equal(t, tt.wantBody, rec.Body.String())
		})
	}
}

// ── Tests: handleMetrics ─────────────────────────────────────────────

func TestHandleMetrics_ZeroTunnels(t *testing.T) {
	a := &Agent{
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		tunnels: make(map[string]*TunnelHandler),
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	a.handleMetrics(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	require.Contains(t, rec.Header().Get("Content-Type"), "text/plain")
	body := rec.Body.String()
	require.Contains(t, body, "bamf_agent_active_tunnels 0")
	require.Contains(t, body, "bamf_agent_active_relay 0")
}

func TestHandleMetrics_WithTunnels(t *testing.T) {
	a := &Agent{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		tunnels: map[string]*TunnelHandler{
			"session-1": {},
			"session-2": {},
		},
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	a.handleMetrics(rec, req)

	body := rec.Body.String()
	require.Contains(t, body, "bamf_agent_active_tunnels 2")
	require.Contains(t, body, "# HELP bamf_agent_active_tunnels")
	require.Contains(t, body, "# TYPE bamf_agent_active_tunnels gauge")
}

// ── Tests: ActiveTunnelCount ─────────────────────────────────────────

func TestActiveTunnelCount(t *testing.T) {
	a := &Agent{tunnels: make(map[string]*TunnelHandler)}
	require.Equal(t, 0, a.ActiveTunnelCount())

	a.tunnels["s1"] = &TunnelHandler{}
	a.tunnels["s2"] = &TunnelHandler{}
	require.Equal(t, 2, a.ActiveTunnelCount())
}

// ── Tests: InstanceID ────────────────────────────────────────────────

func TestInstanceID(t *testing.T) {
	a := &Agent{instanceID: "test-instance-123"}
	require.Equal(t, "test-instance-123", a.InstanceID())
}

// ── Tests: HasActiveRelay ────────────────────────────────────────────

func TestHasActiveRelay_NilRelay(t *testing.T) {
	a := &Agent{}
	require.False(t, a.HasActiveRelay())
}

// ── Tests: handleMetrics content format ──────────────────────────────

func TestHandleMetrics_ContainsAllMetrics(t *testing.T) {
	a := &Agent{
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		tunnels: make(map[string]*TunnelHandler),
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	a.handleMetrics(rec, req)

	body := rec.Body.String()
	lines := strings.Split(body, "\n")

	// Should have HELP and TYPE lines for both metrics
	helpCount := 0
	typeCount := 0
	for _, line := range lines {
		if strings.HasPrefix(line, "# HELP") {
			helpCount++
		}
		if strings.HasPrefix(line, "# TYPE") {
			typeCount++
		}
	}
	require.Equal(t, 2, helpCount, "expected 2 HELP lines")
	require.Equal(t, 2, typeCount, "expected 2 TYPE lines")

	// Verify content type header
	require.Equal(t, "text/plain; version=0.0.4; charset=utf-8", rec.Header().Get("Content-Type"))
}

// ── Tests: generateInstanceID version bits ───────────────────────────

func TestGenerateInstanceID_VersionBits(t *testing.T) {
	for range 20 {
		id := generateInstanceID()
		// The version nibble (position 12 of hex, after removing hyphens) must be '4'
		parts := strings.Split(id, "-")
		require.Len(t, parts, 5)
		// Third segment starts with '4' (version 4)
		require.True(t, strings.HasPrefix(parts[2], "4"),
			"version nibble must be 4, got segment %q", parts[2])
		// Fourth segment starts with 8, 9, a, or b (variant bits)
		first := parts[3][0]
		require.True(t, first == '8' || first == '9' || first == 'a' || first == 'b',
			"variant nibble must be 8/9/a/b, got %c in segment %q", first, parts[3])
	}
}

// ── Tests: serveMetrics registers all routes ─────────────────────────

func TestServeMetrics_Routes(t *testing.T) {
	a := &Agent{
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		tunnels: make(map[string]*TunnelHandler),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", a.handleMetrics)
	mux.HandleFunc("/health", a.handleHealth)
	mux.HandleFunc("/ready", a.handleReady)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	endpoints := []struct {
		path string
		want int
	}{
		{"/metrics", http.StatusOK},
		{"/health", http.StatusOK},
		{"/ready", http.StatusServiceUnavailable}, // not registered
	}

	for _, ep := range endpoints {
		t.Run(ep.path, func(t *testing.T) {
			resp, err := http.Get(fmt.Sprintf("%s%s", srv.URL, ep.path))
			require.NoError(t, err)
			defer resp.Body.Close()
			require.Equal(t, ep.want, resp.StatusCode)
		})
	}
}

// ── Tests: HasActiveRelay with relay manager ─────────────────────────

func TestHasActiveRelay_RelayNotConnected(t *testing.T) {
	// Relay exists but has no workers (not connected)
	a := &Agent{
		relay: &RelayManager{
			agentID:   "test-agent",
			resources: nil,
			tlsConfig: &tls.Config{},
			logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		},
	}
	require.False(t, a.HasActiveRelay())
}

// ── Tests: handleEvent dispatch ──────────────────────────────────────

func TestHandleEvent_UnknownType(t *testing.T) {
	a := &Agent{
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg:        &Config{},
		tunnels:    make(map[string]*TunnelHandler),
		shutdownCh: make(chan struct{}),
	}

	// Unknown event type should not panic
	event := SSEEvent{
		Type: "unknown_event_type",
		Data: map[string]interface{}{"foo": "bar"},
	}
	a.handleEvent(context.Background(), event)
}

func TestHandleEvent_HeartbeatNoOp(t *testing.T) {
	a := &Agent{
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg:        &Config{},
		tunnels:    make(map[string]*TunnelHandler),
		shutdownCh: make(chan struct{}),
	}

	// Heartbeat event should be handled silently (no-op)
	event := SSEEvent{
		Type: "heartbeat",
		Data: map[string]interface{}{},
	}
	a.handleEvent(context.Background(), event)
}

func TestHandleEvent_RevokeTriggersShutdown(t *testing.T) {
	a := &Agent{
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg:        &Config{},
		tunnels:    make(map[string]*TunnelHandler),
		shutdownCh: make(chan struct{}),
	}

	event := SSEEvent{
		Type: "revoke",
		Data: map[string]interface{}{"reason": "agent deleted by admin"},
	}
	a.handleEvent(context.Background(), event)

	// shutdownCh should be closed
	select {
	case <-a.shutdownCh:
		// expected
	case <-time.After(time.Second):
		t.Fatal("shutdownCh was not closed after revoke event")
	}
}

func TestHandleEvent_RevokeIdempotent(t *testing.T) {
	a := &Agent{
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg:        &Config{},
		tunnels:    make(map[string]*TunnelHandler),
		shutdownCh: make(chan struct{}),
	}

	event := SSEEvent{
		Type: "revoke",
		Data: map[string]interface{}{"reason": "revoked"},
	}

	// Multiple revoke events should not panic (shutdownOnce)
	a.handleEvent(context.Background(), event)
	a.handleEvent(context.Background(), event)

	select {
	case <-a.shutdownCh:
		// expected
	case <-time.After(time.Second):
		t.Fatal("shutdownCh was not closed")
	}
}

func TestHandleEvent_TunnelRequestMissingCerts(t *testing.T) {
	a := &Agent{
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg:        &Config{Resources: []ResourceConfig{{Name: "web-01", ResourceType: "ssh"}}},
		tunnels:    make(map[string]*TunnelHandler),
		shutdownCh: make(chan struct{}),
	}

	// tunnel_request with missing session_cert should not crash but should
	// log an error and return without creating a tunnel.
	event := SSEEvent{
		Type: "tunnel_request",
		Data: map[string]interface{}{
			"command":       "dial",
			"session_id":    "sess-1",
			"bridge_host":   "bridge.local",
			"bridge_port":   float64(443),
			"resource_name": "web-01",
			// Missing: session_cert, session_key, ca_certificate
		},
	}

	a.handleEvent(context.Background(), event)
	// Give the goroutine a moment to run
	time.Sleep(50 * time.Millisecond)

	require.Equal(t, 0, a.ActiveTunnelCount(), "no tunnel should be created without certs")
}

func TestHandleEvent_TunnelRequestUnknownResource(t *testing.T) {
	a := &Agent{
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg:        &Config{Resources: []ResourceConfig{{Name: "web-01", ResourceType: "ssh"}}},
		tunnels:    make(map[string]*TunnelHandler),
		shutdownCh: make(chan struct{}),
	}

	event := SSEEvent{
		Type: "tunnel_request",
		Data: map[string]interface{}{
			"command":        "dial",
			"session_id":     "sess-1",
			"bridge_host":    "bridge.local",
			"bridge_port":    float64(443),
			"resource_name":  "nonexistent-resource",
			"session_cert":   "CERT",
			"session_key":    "KEY",
			"ca_certificate": "CA",
		},
	}

	a.handleEvent(context.Background(), event)
	time.Sleep(50 * time.Millisecond)

	require.Equal(t, 0, a.ActiveTunnelCount(), "no tunnel should be created for unknown resource")
}

// ── Tests: waitForTunnels ────────────────────────────────────────────

func TestWaitForTunnels_EmptyImmediate(t *testing.T) {
	a := &Agent{
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		tunnels: make(map[string]*TunnelHandler),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	done := make(chan struct{})
	go func() {
		a.waitForTunnels(ctx)
		close(done)
	}()

	select {
	case <-done:
		// expected: returns immediately with no tunnels
	case <-time.After(2 * time.Second):
		t.Fatal("waitForTunnels should return immediately with no active tunnels")
	}
}

func TestWaitForTunnels_ContextCancel(t *testing.T) {
	closeCh := make(chan struct{})
	a := &Agent{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		tunnels: map[string]*TunnelHandler{
			"s1": {closeCh: closeCh},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	done := make(chan struct{})
	go func() {
		a.waitForTunnels(ctx)
		close(done)
	}()

	select {
	case <-done:
		// expected: context expired, tunnels force-closed
	case <-time.After(3 * time.Second):
		t.Fatal("waitForTunnels should return after context cancellation")
	}

	// Tunnels should have been cleaned up
	a.tunnelsMu.RLock()
	remaining := len(a.tunnels)
	a.tunnelsMu.RUnlock()
	require.Equal(t, 0, remaining, "all tunnels should be removed after context cancellation")
}

// ── Tests: handleMetrics with active relay ───────────────────────────

func TestHandleMetrics_WithActiveRelay(t *testing.T) {
	// Create a RelayManager with a worker to simulate an active relay
	rm := &RelayManager{
		agentID:   "test-agent",
		resources: nil,
		tlsConfig: &tls.Config{},
		logger:    slog.New(slog.NewTextHandler(io.Discard, nil)),
		workers:   []*relayWorker{{stopped: make(chan struct{})}},
	}

	a := &Agent{
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		tunnels: make(map[string]*TunnelHandler),
		relay:   rm,
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	a.handleMetrics(rec, req)

	body := rec.Body.String()
	require.Contains(t, body, "bamf_agent_active_relay 1")
}

// ── Tests: handleRelayConnect ────────────────────────────────────────

func TestHandleRelayConnect_MissingBridgeHost(t *testing.T) {
	a := &Agent{
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg:        &Config{},
		tunnels:    make(map[string]*TunnelHandler),
		shutdownCh: make(chan struct{}),
	}

	// Missing bridge_host should log error and return without crashing
	data := map[string]interface{}{
		"bridge_port": float64(443),
	}
	a.handleRelayConnect(data)
	require.Nil(t, a.relay, "relay should not be created with missing bridge_host")
}

func TestHandleRelayConnect_MissingBridgePort(t *testing.T) {
	a := &Agent{
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		cfg:        &Config{},
		tunnels:    make(map[string]*TunnelHandler),
		shutdownCh: make(chan struct{}),
	}

	// Missing bridge_port (defaults to 0) should log error and return
	data := map[string]interface{}{
		"bridge_host": "bridge.local",
	}
	a.handleRelayConnect(data)
	require.Nil(t, a.relay, "relay should not be created with missing bridge_port")
}

// ── Tests: Shutdown ──────────────────────────────────────────────────

func TestShutdown_ClosesShutdownCh(t *testing.T) {
	a := &Agent{
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		tunnels:    make(map[string]*TunnelHandler),
		shutdownCh: make(chan struct{}),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	err := a.Shutdown(ctx)
	require.NoError(t, err)

	select {
	case <-a.shutdownCh:
		// expected
	default:
		t.Fatal("shutdownCh should be closed after Shutdown")
	}
}

func TestShutdown_Idempotent(t *testing.T) {
	a := &Agent{
		logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		tunnels:    make(map[string]*TunnelHandler),
		shutdownCh: make(chan struct{}),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Multiple shutdowns should not panic
	require.NoError(t, a.Shutdown(ctx))
	require.NoError(t, a.Shutdown(ctx))
}

// ── Tests: ActiveTunnelCount concurrent access ──────────────────────

func TestActiveTunnelCount_Concurrent(t *testing.T) {
	a := &Agent{tunnels: make(map[string]*TunnelHandler)}

	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			_ = a.ActiveTunnelCount()
		}(i)
	}
	wg.Wait()
}

// ── Tests: generateInstanceID length ─────────────────────────────────

func TestGenerateInstanceID_Length(t *testing.T) {
	id := generateInstanceID()
	// UUID v4 string: 8-4-4-4-12 = 32 hex chars + 4 hyphens = 36 chars
	require.Len(t, id, 36)
}

// ── Tests: handleRedial with unknown session ─────────────────────────

func TestHandleRedial_SessionNotFound(t *testing.T) {
	a := &Agent{
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
		tunnels: make(map[string]*TunnelHandler),
	}

	// Redial for a session that doesn't exist should not panic
	a.handleRedial("nonexistent-session", "bridge.local", 443,
		[]byte("cert"), []byte("key"), []byte("ca"))
}

func TestHandleRedial_ClosedTunnel(t *testing.T) {
	th := &TunnelHandler{
		closeCh: make(chan struct{}),
		logger:  slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
	// Properly close the tunnel using Close() so IsClosed() returns true
	th.Close()

	a := &Agent{
		logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
		tunnels: map[string]*TunnelHandler{
			"sess-1": th,
		},
	}

	// Redial for a closed tunnel should be a no-op
	a.handleRedial("sess-1", "bridge.local", 443,
		[]byte("cert"), []byte("key"), []byte("ca"))
}
