package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mattrobinsonsre/bamf/pkg/tunnel"
)

// TunnelHandler handles a tunnel connection to a bridge.
//
// The bridge side uses a ReliableStream for exactly-once delivery across
// bridge reconnections. The target side is a plain TCP connection. When a
// bridge dies, ReconnectBridge() swaps the underlying bridge connection
// while keeping the target connection (and application session) alive.
type TunnelHandler struct {
	sessionID  string
	bridgeHost string
	bridgePort int
	resource   *ResourceConfig
	logger     *slog.Logger

	// stream wraps the bridge connection with reliable framing.
	stream     *tunnel.ReliableStream
	bridgeConn net.Conn
	closed     atomic.Bool
	closeCh    chan struct{}
	closeOnce  sync.Once
}

// NewTunnelHandler creates a new tunnel handler with session certificate.
func NewTunnelHandler(
	sessionID string,
	bridgeHost string,
	bridgePort int,
	resource *ResourceConfig,
	sessionCertPEM []byte,
	sessionKeyPEM []byte,
	caCertPEM []byte,
	logger *slog.Logger,
) (*TunnelHandler, error) {
	// Dial bridge and send session ID.
	bridgeConn, err := dialBridgeAgent(bridgeHost, bridgePort, sessionCertPEM, sessionKeyPEM, caCertPEM, sessionID)
	if err != nil {
		return nil, err
	}

	// Wrap in reliable stream for reconnection support.
	stream := tunnel.NewStream(bridgeConn, tunnel.DefaultBufSize)

	return &TunnelHandler{
		sessionID:  sessionID,
		bridgeHost: bridgeHost,
		bridgePort: bridgePort,
		resource:   resource,
		logger:     logger,
		stream:     stream,
		bridgeConn: bridgeConn,
		closeCh:    make(chan struct{}),
	}, nil
}

// dialBridgeAgent establishes an mTLS connection to the bridge, sends the
// session ID, and returns the raw connection.
func dialBridgeAgent(
	bridgeHost string,
	bridgePort int,
	sessionCertPEM []byte,
	sessionKeyPEM []byte,
	caCertPEM []byte,
	sessionID string,
) (net.Conn, error) {
	cert, err := tls.X509KeyPair(sessionCertPEM, sessionKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load session certificate: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		ServerName:   bridgeHost,
		MinVersion:   tls.VersionTLS12,
	}

	bridgeAddr := fmt.Sprintf("%s:%d", bridgeHost, bridgePort)
	conn, err := tls.Dial("tcp", bridgeAddr, tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to bridge: %w", err)
	}

	if _, err := conn.Write([]byte(sessionID + "\n")); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send session ID: %w", err)
	}

	return conn, nil
}

// Run splices bytes between the reliable bridge stream and the target.
// The target connection is established lazily on the first write (i.e.,
// when the first client data arrives through the tunnel). This avoids
// starting the target's authentication timeout before the client has
// actually connected — critical for `bamf tcp` where the user may take
// seconds or minutes to connect their client after the tunnel is open.
func (t *TunnelHandler) Run(ctx context.Context) error {
	targetAddr := net.JoinHostPort(t.resource.Hostname, fmt.Sprintf("%d", t.resource.Port))

	bridgeAddr := fmt.Sprintf("%s:%d", t.bridgeHost, t.bridgePort)
	t.logger.Info("tunnel established",
		"resource", t.resource.Name,
		"target", targetAddr,
		"bridge", bridgeAddr,
	)

	// Wrap target in a lazy connector: net.Dial happens on first Write,
	// which is when the first client data arrives through the bridge.
	target := &lazyTargetConn{
		addr:   targetAddr,
		logger: t.logger,
	}
	defer target.Close()

	// Wrap the stream in a reconnectable bridge adapter. This makes
	// ErrConnLost transparent to the io.Copy goroutines — they block
	// until ReconnectBridge() swaps the underlying connection, then
	// resume. No splice restart needed, no goroutine leak possible.
	rb := &reconnectableBridge{
		stream:  t.stream,
		closeCh: t.closeCh,
		closed:  &t.closed,
		logger:  t.logger,
	}

	// Bidirectional copy: target ↔ reconnectable bridge stream.
	errCh := make(chan error, 2)

	// bridge → target: reads from bridge, writes to target (triggers lazy dial).
	go func() {
		_, err := io.Copy(target, rb)
		errCh <- err
	}()

	// target → bridge: reads from target, writes to bridge.
	go func() {
		// Wait for the target connection to be established before reading.
		<-target.Ready()
		_, err := io.Copy(rb, target)
		errCh <- err
	}()

	select {
	case <-ctx.Done():
		t.Close()
		return ctx.Err()
	case <-t.closeCh:
		return nil
	case err := <-errCh:
		t.Close()
		if err != nil && err != io.EOF {
			return err
		}
		return nil
	}
}

// lazyTargetConn defers net.Dial until the first Write. This prevents the
// target service from starting its authentication timeout (e.g., PostgreSQL's
// authentication_timeout) before the client has actually connected.
type lazyTargetConn struct {
	addr   string
	logger *slog.Logger

	once    sync.Once
	conn    net.Conn
	err     error
	readyCh chan struct{} // closed when conn is established (or failed)
}

func (l *lazyTargetConn) Ready() <-chan struct{} {
	if l.readyCh == nil {
		l.readyCh = make(chan struct{})
	}
	return l.readyCh
}

func (l *lazyTargetConn) dial() {
	l.once.Do(func() {
		if l.readyCh == nil {
			l.readyCh = make(chan struct{})
		}
		l.logger.Debug("connecting to target (lazy)", "addr", l.addr)
		l.conn, l.err = net.Dial("tcp", l.addr)
		if l.err != nil {
			l.logger.Error("failed to connect to target", "addr", l.addr, "error", l.err)
		}
		close(l.readyCh)
	})
}

func (l *lazyTargetConn) Write(p []byte) (int, error) {
	l.dial()
	if l.err != nil {
		return 0, l.err
	}
	return l.conn.Write(p)
}

func (l *lazyTargetConn) Read(p []byte) (int, error) {
	l.dial()
	if l.err != nil {
		return 0, l.err
	}
	return l.conn.Read(p)
}

func (l *lazyTargetConn) Close() error {
	if l.conn != nil {
		return l.conn.Close()
	}
	// Unblock anything waiting on Ready() if we never dialed.
	l.once.Do(func() {
		if l.readyCh == nil {
			l.readyCh = make(chan struct{})
		}
		l.err = fmt.Errorf("closed before connect")
		close(l.readyCh)
	})
	return nil
}

// reconnectableBridge wraps a ReliableStream so that Read/Write block on
// ErrConnLost until ReconnectBridge() swaps the connection. This is the
// agent-side equivalent of the CLI's reconnectingBridge, but simpler:
// the agent doesn't initiate reconnection — it waits for the API to send
// a "redial" command via SSE, which triggers ReconnectBridge().
type reconnectableBridge struct {
	stream  *tunnel.ReliableStream
	closeCh chan struct{}
	closed  *atomic.Bool
	logger  *slog.Logger
}

func (rb *reconnectableBridge) Read(p []byte) (int, error) {
	for {
		n, err := rb.stream.Read(p)
		if errors.Is(err, tunnel.ErrClosed) {
			// Peer sent a close frame — clean shutdown, no reconnect.
			return n, io.EOF
		}
		if n > 0 || !errors.Is(err, tunnel.ErrConnLost) {
			return n, err
		}
		rb.logger.Info("bridge connection lost (read), waiting for reconnect...")
		if !rb.waitForReconnect() {
			return 0, io.EOF
		}
		rb.logger.Info("bridge reconnected (read), resuming")
	}
}

func (rb *reconnectableBridge) Write(p []byte) (int, error) {
	written := 0
	for written < len(p) {
		n, err := rb.stream.Write(p[written:])
		written += n
		if err == nil {
			return written, nil
		}
		if errors.Is(err, tunnel.ErrConnLost) {
			// Bytes p[:written] are in the retransmit buffer and will be
			// delivered after reconnection. Only p[written:] needs retry.
			rb.logger.Info("bridge connection lost (write), waiting for reconnect...")
			if !rb.waitForReconnect() {
				return written, io.EOF
			}
			rb.logger.Info("bridge reconnected (write), resuming")
			continue
		}
		return written, err // Non-recoverable (ErrBufFull, ErrClosed)
	}
	return written, nil
}

// reconnectWaitTimeout is how long the agent waits for a redial command
// before giving up. When a bridge dies, the API sends redial within seconds.
// If no reconnect arrives in this window, the tunnel is considered dead
// (e.g., the client disconnected cleanly and the bridge closed both sides).
const reconnectWaitTimeout = 5 * time.Minute

// waitForReconnect blocks until the stream is no longer in connLost state
// (ReconnectBridge was called), the tunnel is closed, or the timeout expires.
func (rb *reconnectableBridge) waitForReconnect() bool {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.After(reconnectWaitTimeout)
	for {
		select {
		case <-rb.closeCh:
			return false
		case <-deadline:
			rb.logger.Warn("reconnect wait timeout, closing tunnel")
			return false
		case <-ticker.C:
			if !rb.stream.IsConnLost() {
				return true
			}
		}
	}
}

// ReconnectBridge dials a new bridge with the provided session credentials
// and performs the reliable stream handshake (sequence exchange + retransmit).
// The target connection stays open — only the bridge side is replaced.
func (t *TunnelHandler) ReconnectBridge(
	bridgeHost string,
	bridgePort int,
	sessionCertPEM []byte,
	sessionKeyPEM []byte,
	caCertPEM []byte,
) error {
	if t.closed.Load() {
		return fmt.Errorf("tunnel is closed")
	}

	t.logger.Info("reconnecting bridge",
		"new_bridge", fmt.Sprintf("%s:%d", bridgeHost, bridgePort),
	)

	newConn, err := dialBridgeAgent(bridgeHost, bridgePort, sessionCertPEM, sessionKeyPEM, caCertPEM, t.sessionID)
	if err != nil {
		return fmt.Errorf("failed to dial new bridge: %w", err)
	}

	if err := t.stream.Reconnect(newConn); err != nil {
		newConn.Close()
		return fmt.Errorf("reliable stream reconnect failed: %w", err)
	}

	// Update bridge address for logging.
	t.bridgeHost = bridgeHost
	t.bridgePort = bridgePort
	t.bridgeConn = newConn

	t.logger.Info("bridge reconnection complete",
		"bridge", fmt.Sprintf("%s:%d", bridgeHost, bridgePort),
	)

	return nil
}

// Close closes the tunnel permanently.
func (t *TunnelHandler) Close() {
	t.closeOnce.Do(func() {
		t.closed.Store(true)
		close(t.closeCh)
		if t.stream != nil {
			t.stream.Close()
		}
	})
}

// IsClosed returns whether the tunnel is closed.
func (t *TunnelHandler) IsClosed() bool {
	return t.closed.Load()
}
