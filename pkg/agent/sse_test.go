package agent

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mattrobinsonsre/bamf/pkg/apiclient"
	"github.com/stretchr/testify/require"
)

// newTestSSEClient creates an SSEClient pointing at a test server.
func newTestSSEClient(t *testing.T, handler http.HandlerFunc) (*SSEClient, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	client := apiclient.New(apiclient.Config{
		BaseURL:   srv.URL,
		UserAgent: "bamf-agent/test",
	})

	sseClient := NewSSEClient(client, "test-agent-id", slog.Default())
	return sseClient, srv
}

func TestSSEConnect_TunnelRequestEvent(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "text/event-stream", r.Header.Get("Accept"))
		require.Equal(t, "bamf-agent/test", r.Header.Get("User-Agent"))
		require.Contains(t, r.URL.Path, "/api/v1/agents/test-agent-id/events")

		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		flusher, ok := w.(http.Flusher)
		require.True(t, ok)

		// Send a tunnel_request event
		fmt.Fprint(w, "event: tunnel_request\n")
		fmt.Fprint(w, `data: {"command":"dial","session_id":"sess-123","bridge_host":"bridge.local","bridge_port":3022,"resource_name":"web-01","resource_type":"ssh"}`+"\n")
		fmt.Fprint(w, "\n")
		flusher.Flush()
	}

	sseClient, _ := newTestSSEClient(t, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	eventCh, err := sseClient.Connect(ctx)
	require.NoError(t, err)

	event := <-eventCh
	require.Equal(t, "tunnel_request", event.Type)
	require.Equal(t, "dial", event.Data["command"])
	require.Equal(t, "sess-123", event.Data["session_id"])
	require.Equal(t, "bridge.local", event.Data["bridge_host"])
	require.Equal(t, float64(3022), event.Data["bridge_port"])
	require.Equal(t, "web-01", event.Data["resource_name"])
	require.Equal(t, "ssh", event.Data["resource_type"])
}

func TestSSEConnect_HeartbeatEvent(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)

		fmt.Fprint(w, "event: heartbeat\ndata: {}\n\n")
		flusher.Flush()
	}

	sseClient, _ := newTestSSEClient(t, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	eventCh, err := sseClient.Connect(ctx)
	require.NoError(t, err)

	event := <-eventCh
	require.Equal(t, "heartbeat", event.Type)
	require.Empty(t, event.Data)
}

func TestSSEConnect_MultipleEvents(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)

		// First event
		fmt.Fprint(w, "event: heartbeat\ndata: {}\n\n")
		flusher.Flush()

		// Second event
		fmt.Fprint(w, "event: tunnel_request\n")
		fmt.Fprint(w, `data: {"command":"dial","session_id":"s1"}`+"\n\n")
		flusher.Flush()
	}

	sseClient, _ := newTestSSEClient(t, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	eventCh, err := sseClient.Connect(ctx)
	require.NoError(t, err)

	event1 := <-eventCh
	require.Equal(t, "heartbeat", event1.Type)

	event2 := <-eventCh
	require.Equal(t, "tunnel_request", event2.Type)
	require.Equal(t, "s1", event2.Data["session_id"])
}

func TestSSEConnect_CertHeader(t *testing.T) {
	var gotCertHeader string

	handler := func(w http.ResponseWriter, r *http.Request) {
		gotCertHeader = r.Header.Get("X-Bamf-Client-Cert")
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		// Close immediately
	}

	srv := httptest.NewServer(http.HandlerFunc(handler))
	defer srv.Close()

	client := apiclient.New(apiclient.Config{
		BaseURL:   srv.URL,
		UserAgent: "bamf-agent/test",
	})
	client.SetClientCert([]byte("-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"))

	sseClient := NewSSEClient(client, "test-agent-id", slog.Default())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, _ = sseClient.Connect(ctx)

	require.NotEmpty(t, gotCertHeader, "X-Bamf-Client-Cert header should be set")
}

func TestSSEConnect_ErrorStatus(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}

	sseClient, _ := newTestSSEClient(t, handler)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, err := sseClient.Connect(ctx)
	require.Error(t, err)
	require.Contains(t, err.Error(), "unexpected status")
}

func TestSSEConnect_ContextCancellation(t *testing.T) {
	handler := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		flusher.Flush()

		// Block until client disconnects
		<-r.Context().Done()
	}

	sseClient, _ := newTestSSEClient(t, handler)

	ctx, cancel := context.WithCancel(context.Background())

	eventCh, err := sseClient.Connect(ctx)
	require.NoError(t, err)

	// Cancel context — channel should close
	cancel()

	// Drain channel — should close within a reasonable time
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()

	select {
	case _, ok := <-eventCh:
		if ok {
			// Got an event before close, that's fine, drain more
			for range eventCh {
			}
		}
	case <-timer.C:
		t.Fatal("event channel did not close after context cancellation")
	}
}

func TestSSEBackoff(t *testing.T) {
	sseClient := &SSEClient{
		cfg: SSEConfig{
			BaseDelay:   1 * time.Second,
			MaxDelay:    1 * time.Minute,
			JitterRatio: 0, // No jitter for deterministic test
		},
	}

	tests := []struct {
		attempt  int
		expected time.Duration
	}{
		{0, 1 * time.Second},
		{1, 2 * time.Second},
		{2, 4 * time.Second},
		{3, 8 * time.Second},
		{4, 16 * time.Second},
		{5, 32 * time.Second},
		{6, 1 * time.Minute}, // capped at maxDelay
		{10, 1 * time.Minute},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("attempt_%d", tt.attempt), func(t *testing.T) {
			delay := sseClient.backoff(tt.attempt)
			require.Equal(t, tt.expected, delay)
		})
	}
}

func TestSSEBackoffWithJitter(t *testing.T) {
	sseClient := &SSEClient{
		cfg: SSEConfig{
			BaseDelay:   1 * time.Second,
			MaxDelay:    5 * time.Minute,
			JitterRatio: 0.2,
		},
	}

	// With 0.2 jitter, attempt 0 should be between 1s and 1.2s
	delay := sseClient.backoff(0)
	require.GreaterOrEqual(t, delay, 1*time.Second)
	require.Less(t, delay, time.Duration(float64(1*time.Second)*1.21))
}
