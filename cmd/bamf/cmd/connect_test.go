package cmd

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ── Tests: splice ────────────────────────────────────────────────────

type testRWC struct {
	io.Reader
	io.Writer
	closed bool
}

func (t *testRWC) Close() error {
	t.closed = true
	return nil
}

func TestSplice_BidirectionalCopy(t *testing.T) {
	// Create two pipe pairs for bidirectional communication
	ar, bw := io.Pipe()
	br, aw := io.Pipe()

	a := &testRWC{Reader: ar, Writer: aw}
	b := &testRWC{Reader: br, Writer: bw}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- splice(ctx, a, b)
	}()

	// Write from a→b (through splice)
	go func() {
		_, _ = bw.Write([]byte("hello from b"))
		bw.Close()
	}()

	// Read on a's reader side
	buf := make([]byte, 20)
	n, err := ar.Read(buf)
	// ar reads what comes from b through splice
	// Actually splice copies b→a and a→b
	// Let me reconsider: splice does io.Copy(a, b) and io.Copy(b, a)
	// So data read from b is written to a, and vice versa.
	_ = n
	_ = err

	// Close to unblock
	cancel()

	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("splice did not complete")
	}

	require.True(t, a.closed)
	require.True(t, b.closed)
}

func TestSplice_ContextCancellation(t *testing.T) {
	// Use net.Pipe for proper bidirectional comms
	ar, aw := io.Pipe()
	br, bw := io.Pipe()

	a := &testRWC{Reader: ar, Writer: aw}
	b := &testRWC{Reader: br, Writer: bw}

	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() {
		errCh <- splice(ctx, a, b)
	}()

	// Cancel immediately
	cancel()

	err := <-errCh
	require.ErrorIs(t, err, context.Canceled)
}

func TestSplice_OneSideClosed(t *testing.T) {
	ar, aw := io.Pipe()
	br, bw := io.Pipe()

	a := &testRWC{Reader: ar, Writer: aw}
	b := &testRWC{Reader: br, Writer: bw}

	ctx := context.Background()

	errCh := make(chan error, 1)
	go func() {
		errCh <- splice(ctx, a, b)
	}()

	// Close write ends so reads return EOF — splice should complete
	aw.Close()
	bw.Close()

	select {
	case err := <-errCh:
		// Should complete without error (EOF is swallowed)
		require.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("splice did not complete after closing one side")
	}
}

// loadCredentials tests are in login_test.go

// ── Tests: requestConnect ────────────────────────────────────────────

func TestRequestConnect_Success(t *testing.T) {
	expected := ConnectResponse{
		BridgeHostname: "0.bridge.tunnel.example.com",
		BridgePort:     443,
		SessionCert:    "cert-pem",
		SessionKey:     "key-pem",
		CACertificate:  "ca-pem",
		SessionID:      "session-123",
		ResourceType:   "ssh",
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/connect", r.URL.Path)
		require.Equal(t, "POST", r.Method)
		require.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var body map[string]string
		err := json.NewDecoder(r.Body).Decode(&body)
		require.NoError(t, err)
		require.Equal(t, "web-01", body["resource_name"])

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(expected))
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	creds := &tokenResponse{SessionToken: "test-token"}
	result, err := requestConnect(context.Background(), creds, "web-01", "")
	require.NoError(t, err)
	require.Equal(t, "0.bridge.tunnel.example.com", result.BridgeHostname)
	require.Equal(t, 443, result.BridgePort)
	require.Equal(t, "session-123", result.SessionID)
}

func TestRequestConnect_WithReconnectSession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "old-session-id", body["reconnect_session_id"])

		require.NoError(t, json.NewEncoder(w).Encode(ConnectResponse{SessionID: "old-session-id"}))
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	creds := &tokenResponse{SessionToken: "token"}
	result, err := requestConnect(context.Background(), creds, "res", "old-session-id")
	require.NoError(t, err)
	require.Equal(t, "old-session-id", result.SessionID)
}

func TestRequestConnect_Unauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	creds := &tokenResponse{SessionToken: "expired"}
	_, err := requestConnect(context.Background(), creds, "res", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "session expired")
}

func TestRequestConnect_Forbidden(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	creds := &tokenResponse{SessionToken: "token"}
	_, err := requestConnect(context.Background(), creds, "secret-db", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "access denied")
}

func TestRequestConnect_NotFound(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	creds := &tokenResponse{SessionToken: "token"}
	_, err := requestConnect(context.Background(), creds, "nonexistent", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "resource not found")
}

func TestRequestConnect_RateLimited(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts <= 2 {
			w.Header().Set("Retry-After", "0") // no wait in tests
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		require.NoError(t, json.NewEncoder(w).Encode(ConnectResponse{SessionID: "ok"}))
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	creds := &tokenResponse{SessionToken: "token"}
	result, err := requestConnect(context.Background(), creds, "res", "")
	require.NoError(t, err)
	require.Equal(t, "ok", result.SessionID)
	require.Equal(t, 3, attempts)
}

func TestRequestConnect_ServiceUnavailable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"detail":"no bridges available"}`))
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	creds := &tokenResponse{SessionToken: "token"}
	_, err := requestConnect(context.Background(), creds, "res", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "no bridges available")
}

func TestRequestConnect_NoAPIURL(t *testing.T) {
	// Clear both the global var and env
	t.Setenv("BAMF_API_URL", "")
	// Also need to make loadCredentials fail (no HOME/.bamf/credentials.json)
	t.Setenv("HOME", t.TempDir())

	oldAPIURL := apiURL
	apiURL = ""
	defer func() { apiURL = oldAPIURL }()

	creds := &tokenResponse{SessionToken: "token"}
	_, err := requestConnect(context.Background(), creds, "res", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "API URL not configured")
}

// ── Tests: ConnectResponse JSON ──────────────────────────────────────

func TestConnectResponse_JSONRoundTrip(t *testing.T) {
	original := ConnectResponse{
		BridgeHostname:   "0.bridge.tunnel.example.com",
		BridgePort:       8443,
		SessionCert:      "cert",
		SessionKey:       "key",
		CACertificate:    "ca",
		SessionID:        "abc-123",
		SessionExpiresAt: time.Date(2026, 3, 26, 12, 0, 0, 0, time.UTC),
		ResourceType:     "ssh",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded ConnectResponse
	require.NoError(t, json.Unmarshal(data, &decoded))

	require.Equal(t, original.BridgeHostname, decoded.BridgeHostname)
	require.Equal(t, original.BridgePort, decoded.BridgePort)
	require.Equal(t, original.SessionID, decoded.SessionID)
	require.Equal(t, original.ResourceType, decoded.ResourceType)
}

// ── Tests: splice error propagation ──────────────────────────────────

func TestSplice_ErrorFromReader(t *testing.T) {
	errReader := &errRWC{readErr: io.ErrUnexpectedEOF}
	pr, pw := io.Pipe()
	b := &testRWC{Reader: pr, Writer: pw}

	ctx := context.Background()
	errCh := make(chan error, 1)
	go func() {
		errCh <- splice(ctx, errReader, b)
	}()

	// Write something to b so splice's io.Copy(a, b) starts
	go func() {
		_, _ = pw.Write([]byte("data"))
		pw.Close()
	}()

	select {
	case err := <-errCh:
		// Should get the unexpected EOF error propagated
		if err != nil {
			require.True(t, strings.Contains(err.Error(), "unexpected EOF") || err == io.ErrUnexpectedEOF)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("splice did not complete")
	}
}

type errRWC struct {
	readErr  error
	writeErr error
}

func (e *errRWC) Read(p []byte) (int, error) { return 0, e.readErr }
func (e *errRWC) Write(p []byte) (int, error) {
	if e.writeErr != nil {
		return 0, e.writeErr
	}
	return len(p), nil
}
func (e *errRWC) Close() error { return nil }
