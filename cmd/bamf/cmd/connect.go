package cmd

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/mattrobinsonsre/bamf/pkg/tunnel"
)

// ConnectResponse matches the Python API response model
type ConnectResponse struct {
	BridgeHostname   string    `json:"bridge_hostname"`
	BridgePort       int       `json:"bridge_port"`
	SessionCert      string    `json:"session_cert"`
	SessionKey       string    `json:"session_key"`
	CACertificate    string    `json:"ca_certificate"`
	SessionID        string    `json:"session_id"`
	SessionExpiresAt time.Time `json:"session_expires_at"`
	ResourceType     string    `json:"resource_type"`
}

// connectBridge is the shared tunnel setup: load creds, request session, dial bridge,
// and wrap the connection in a reliable stream with automatic reconnection.
// Returns a reconnectingBridge that implements io.ReadWriteCloser and handles
// bridge failures transparently.
func connectBridge(ctx context.Context, resourceName string) (*reconnectingBridge, *ConnectResponse, error) {
	creds, err := loadCredentials()
	if err != nil {
		return nil, nil, fmt.Errorf("not logged in: %w\nRun 'bamf login' to authenticate", err)
	}

	if time.Now().After(creds.ExpiresAt) {
		return nil, nil, fmt.Errorf("credentials expired. Run 'bamf login' to refresh")
	}

	session, err := requestConnect(ctx, creds, resourceName, "")
	if err != nil {
		return nil, nil, fmt.Errorf("failed to request session: %w", err)
	}

	conn, err := dialBridge(ctx, session)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to connect to bridge: %w", err)
	}

	stream := tunnel.NewStream(conn, tunnel.DefaultBufSize)

	rb := &reconnectingBridge{
		stream:       stream,
		session:      session,
		creds:        creds,
		resourceName: resourceName,
		ctx:          ctx,
	}

	return rb, session, nil
}

// reconnectingBridge wraps a ReliableStream and handles bridge reconnection
// transparently. When the bridge dies, Read/Write block until reconnection
// completes, then resume. This makes bridge failures invisible to the
// application protocol (psql, ssh, etc.).
type reconnectingBridge struct {
	stream       *tunnel.ReliableStream
	session      *ConnectResponse
	creds        *tokenResponse
	resourceName string
	ctx          context.Context

	mu           sync.Mutex
	reconnecting bool
	reconnectCh  chan struct{}
}

func (rb *reconnectingBridge) Read(p []byte) (int, error) {
	for {
		n, err := rb.stream.Read(p)
		if errors.Is(err, tunnel.ErrClosed) {
			// Peer sent a close frame — clean shutdown, no reconnect.
			return n, io.EOF
		}
		if n > 0 || !errors.Is(err, tunnel.ErrConnLost) {
			return n, err
		}
		if reconnErr := rb.waitForReconnect(); reconnErr != nil {
			return 0, reconnErr
		}
		// Retry read after successful reconnection.
	}
}

func (rb *reconnectingBridge) Write(p []byte) (int, error) {
	written := 0
	for written < len(p) {
		n, err := rb.stream.Write(p[written:])
		written += n
		if err == nil {
			return written, nil
		}
		if errors.Is(err, tunnel.ErrConnLost) {
			// The reliable stream buffers frames before sending on wire,
			// so p[:written] is in the retransmit buffer and will be
			// delivered after reconnection. We just need to write p[written:].
			if reconnErr := rb.waitForReconnect(); reconnErr != nil {
				return written, reconnErr
			}
			continue
		}
		return written, err // Non-recoverable (ErrBufFull, ErrClosed)
	}
	return written, nil
}

func (rb *reconnectingBridge) Close() error {
	return rb.stream.Close()
}

// waitForReconnect coordinates reconnection between the Read and Write
// goroutines. The first goroutine to notice the break initiates reconnection;
// others wait for it to complete.
func (rb *reconnectingBridge) waitForReconnect() error {
	rb.mu.Lock()
	if rb.reconnecting {
		// Another goroutine is already reconnecting. Wait for it.
		ch := rb.reconnectCh
		rb.mu.Unlock()
		select {
		case <-ch:
			return nil
		case <-rb.ctx.Done():
			return rb.ctx.Err()
		}
	}

	// We're first. Start reconnecting.
	rb.reconnecting = true
	rb.reconnectCh = make(chan struct{})
	rb.mu.Unlock()

	err := rb.doReconnect()

	rb.mu.Lock()
	rb.reconnecting = false
	close(rb.reconnectCh)
	rb.mu.Unlock()

	return err
}

const (
	maxReconnectAttempts = 15
	reconnectBaseDelay   = 2 * time.Second
	reconnectMaxDelay    = 10 * time.Second
)

func (rb *reconnectingBridge) doReconnect() error {
	fmt.Fprintf(os.Stderr, "\nBridge connection lost, reconnecting...\n")

	for attempt := range maxReconnectAttempts {
		if attempt > 0 {
			delay := reconnectBaseDelay * time.Duration(1<<(attempt-1))
			if delay > reconnectMaxDelay {
				delay = reconnectMaxDelay
			}
			select {
			case <-time.After(delay):
			case <-rb.ctx.Done():
				return rb.ctx.Err()
			}
		}

		newSession, err := requestConnect(rb.ctx, rb.creds, rb.resourceName, rb.session.SessionID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Reconnect attempt %d/%d: API error: %v\n",
				attempt+1, maxReconnectAttempts, err)
			continue
		}

		newConn, err := dialBridge(rb.ctx, newSession)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Reconnect attempt %d/%d: bridge dial error: %v\n",
				attempt+1, maxReconnectAttempts, err)
			continue
		}

		if err := rb.stream.Reconnect(newConn); err != nil {
			fmt.Fprintf(os.Stderr, "Reconnect attempt %d/%d: stream handshake error: %v\n",
				attempt+1, maxReconnectAttempts, err)
			continue
		}

		rb.session = newSession
		fmt.Fprintf(os.Stderr, "Reconnected via %s\n", newSession.BridgeHostname)
		return nil
	}

	return fmt.Errorf("failed to reconnect after %d attempts", maxReconnectAttempts)
}

// dialBridge establishes an mTLS connection to the bridge and sends the
// session ID. Returns a ready-to-use connection for tunneling bytes.
func dialBridge(ctx context.Context, session *ConnectResponse) (net.Conn, error) {
	cert, err := tls.X509KeyPair([]byte(session.SessionCert), []byte(session.SessionKey))
	if err != nil {
		return nil, fmt.Errorf("failed to load session certificate: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM([]byte(session.CACertificate)) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		ServerName:   session.BridgeHostname,
		MinVersion:   tls.VersionTLS12,
	}

	bridgeAddr := net.JoinHostPort(session.BridgeHostname, strconv.Itoa(session.BridgePort))

	dialer := &net.Dialer{Timeout: 10 * time.Second}
	rawConn, err := dialer.DialContext(ctx, "tcp", bridgeAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to bridge (TCP): %w", err)
	}

	tlsConn := tls.Client(rawConn, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		rawConn.Close()
		return nil, fmt.Errorf("failed to connect to bridge (TLS): %w", err)
	}

	// Send session ID (line 1) and resource type (line 2).
	// The bridge reads both lines to determine routing (byte-splice vs SSH proxy).
	header := session.SessionID + "\n"
	if session.ResourceType != "" {
		header += "type=" + session.ResourceType + "\n"
	}
	if _, err := tlsConn.Write([]byte(header)); err != nil {
		tlsConn.Close()
		return nil, fmt.Errorf("failed to send session header: %w", err)
	}

	return tlsConn, nil
}

// splice copies bytes bidirectionally between two connections until one side
// closes or the context is cancelled. Closes both connections on exit to
// ensure no goroutines or file descriptors leak.
func splice(ctx context.Context, a, b io.ReadWriteCloser) error {
	errCh := make(chan error, 2)
	go func() { _, err := io.Copy(a, b); errCh <- err }()
	go func() { _, err := io.Copy(b, a); errCh <- err }()

	var result error
	select {
	case <-ctx.Done():
		result = ctx.Err()
	case err := <-errCh:
		if err != nil && err != io.EOF {
			result = err
		}
	}

	// Close both sides to unblock any stuck io.Copy goroutine.
	a.Close()
	b.Close()
	return result
}

func loadCredentials() (*tokenResponse, error) {
	bamfPath, err := bamfDir()
	if err != nil {
		return nil, err
	}

	credsFile := filepath.Join(bamfPath, "credentials.json")
	data, err := os.ReadFile(credsFile)
	if err != nil {
		return nil, err
	}

	var creds tokenResponse
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, err
	}

	return &creds, nil
}

// requestConnect calls POST /api/v1/connect. If reconnectSessionID is non-empty,
// it requests reconnection of an existing session through a new bridge.
func requestConnect(ctx context.Context, creds *tokenResponse, resource, reconnectSessionID string) (*ConnectResponse, error) {
	api := resolveAPIURL()
	if api == "" {
		return nil, fmt.Errorf("API URL not configured. Use --api flag or set BAMF_API_URL")
	}

	u, err := url.Parse(api)
	if err != nil {
		return nil, err
	}
	u.Path = "/api/v1/connect"

	reqBody := map[string]string{
		"resource_name": resource,
	}
	if reconnectSessionID != "" {
		reqBody["reconnect_session_id"] = reconnectSessionID
	}
	reqData, _ := json.Marshal(reqBody)

	req, err := http.NewRequestWithContext(ctx, "POST", u.String(), bytes.NewReader(reqData))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+creds.SessionToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("session expired or revoked. Run 'bamf login' to re-authenticate")
	}
	if resp.StatusCode == http.StatusForbidden {
		return nil, fmt.Errorf("access denied to resource %s", resource)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("resource not found: %s", resource)
	}
	if resp.StatusCode == http.StatusServiceUnavailable {
		var detail struct {
			Detail string `json:"detail"`
		}
		if err := json.Unmarshal(body, &detail); err != nil {
			return nil, fmt.Errorf("service unavailable: %s", string(body))
		}
		return nil, fmt.Errorf("service unavailable: %s", detail.Detail)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API error: %s - %s", resp.Status, string(body))
	}

	var session ConnectResponse
	if err := json.Unmarshal(body, &session); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return &session, nil
}
