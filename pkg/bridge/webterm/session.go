package webterm

import (
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// ReconnectTimeout is how long the bridge keeps a detached session alive
// waiting for the client to reconnect.
const ReconnectTimeout = 30 * time.Second

// Session manages a web terminal session with reconnection support.
//
// The session holds the server-side state (SSH channel or PTY subprocess)
// and relays framed data to/from the API connection. When the API connection
// drops, the session enters "detached" mode: it buffers output from the
// server side into a ring buffer and waits for a new API connection.
type Session struct {
	ID       string
	Protocol string // "web-ssh" or "web-db"
	logger   *slog.Logger

	// agentIO is the server-side I/O: SSH channel or PTY master fd.
	agentIO io.ReadWriteCloser

	// clientConn is the current API connection (swappable on reconnect).
	clientConn net.Conn
	clientMu   sync.Mutex

	// Ring buffer for output during detached state.
	ringBuf *RingBuffer

	// Detach/reconnect coordination.
	detached    atomic.Bool
	reconnectCh chan net.Conn
	closeCh     chan struct{}
	closed      atomic.Bool

	// WarnCh receives drain warning messages (reuses bridge pattern).
	WarnCh chan string

	// resizeFn is called on resize frames (SSH window-change or PTY TIOCSWINSZ).
	resizeFn func(cols, rows uint16)
}

// NewSession creates a web terminal session.
func NewSession(id, protocol string, clientConn net.Conn, agentIO io.ReadWriteCloser, logger *slog.Logger) *Session {
	return &Session{
		ID:          id,
		Protocol:    protocol,
		logger:      logger,
		agentIO:     agentIO,
		clientConn:  clientConn,
		ringBuf:     NewRingBuffer(DefaultRingBufSize),
		reconnectCh: make(chan net.Conn, 1),
		closeCh:     make(chan struct{}),
		WarnCh:      make(chan string, 8),
	}
}

// SetResizeFunc sets the function called on resize frames.
func (s *Session) SetResizeFunc(fn func(cols, rows uint16)) {
	s.resizeFn = fn
}

// IsDetached returns true if the session is waiting for a client reconnection.
func (s *Session) IsDetached() bool {
	return s.detached.Load()
}

// Reconnect reattaches a new client connection to this session.
// Called when a new API connection arrives for the same session ID.
func (s *Session) Reconnect(conn net.Conn) {
	select {
	case s.reconnectCh <- conn:
	default:
		// Channel full — shouldn't happen, but don't block.
		conn.Close()
	}
}

// Run is the main session loop. It reads frames from the client and writes
// to agentIO, and reads from agentIO and writes frames to the client.
// On client disconnect, it enters detached mode and waits for reconnection.
func (s *Session) Run() error {
	defer s.Close()

	for {
		err := s.runConnected()
		if err == nil {
			// Clean shutdown (agentIO closed).
			return nil
		}

		if s.closed.Load() {
			return nil
		}

		// Client disconnected — enter detached mode.
		s.logger.Info("client disconnected, entering detached mode",
			"session_id", s.ID,
		)

		newConn, ok := s.waitForReconnect()
		if !ok {
			s.logger.Info("reconnect timeout, closing session",
				"session_id", s.ID,
			)
			return nil
		}

		// Reattach: drain ring buffer to new client, resume.
		s.clientMu.Lock()
		s.clientConn = newConn
		s.clientMu.Unlock()

		s.logger.Info("client reconnected, resuming session",
			"session_id", s.ID,
		)

		// Drain buffered output to new client.
		fw := NewFrameWriter(newConn)
		if err := fw.WriteStatus("resumed"); err != nil {
			s.logger.Warn("failed to send resumed status", "error", err)
			continue
		}
		buffered := s.ringBuf.ReadAll()
		if len(buffered) > 0 {
			if err := fw.WriteData(buffered); err != nil {
				s.logger.Warn("failed to drain ring buffer", "error", err)
				continue
			}
		}
	}
}

// runConnected runs the bidirectional relay while the client is connected.
// Returns nil if agentIO closes (clean exit), error if client disconnects.
func (s *Session) runConnected() error {
	s.detached.Store(false)

	s.clientMu.Lock()
	conn := s.clientConn
	s.clientMu.Unlock()

	fr := NewFrameReader(conn)
	fw := NewFrameWriter(conn)

	errCh := make(chan error, 2)

	// agentIO → client (with detach buffering)
	go func() {
		buf := make([]byte, 32*1024)
		for {
			n, err := s.agentIO.Read(buf)
			if n > 0 {
				data := buf[:n]
				if s.detached.Load() {
					// Buffer output while detached.
					_, _ = s.ringBuf.Write(data)
				} else {
					if writeErr := fw.WriteData(data); writeErr != nil {
						// Client write failed — will be caught as detach.
						_, _ = s.ringBuf.Write(data)
						s.detached.Store(true)
					}
				}
			}
			if err != nil {
				errCh <- fmt.Errorf("agentIO read: %w", err)
				return
			}
		}
	}()

	// client → agentIO (frame reader)
	go func() {
		for {
			typ, payload, err := fr.ReadFrame()
			if err != nil {
				errCh <- fmt.Errorf("client read: %w", err)
				return
			}

			switch typ {
			case FrameData:
				if _, err := s.agentIO.Write(payload); err != nil {
					errCh <- fmt.Errorf("agentIO write: %w", err)
					return
				}
			case FrameResize:
				if s.resizeFn != nil {
					cols, rows, err := ParseResize(payload)
					if err == nil {
						s.resizeFn(cols, rows)
					}
				}
			case FrameStatus:
				// Client shouldn't send status frames, ignore.
			}
		}
	}()

	// Drain warning monitor
	go func() {
		for {
			select {
			case msg, ok := <-s.WarnCh:
				if !ok {
					return
				}
				// Send drain warning as status frame.
				_ = fw.WriteStatus("warn:" + msg)
			case <-s.closeCh:
				return
			}
		}
	}()

	// Wait for either direction to fail.
	err := <-errCh

	// Determine if this is agent-side close (clean) or client-side (detach).
	if s.detached.Load() {
		return fmt.Errorf("client disconnected")
	}

	// Check if it's a client read error (client went away).
	// agentIO errors are clean exits.
	return err
}

// waitForReconnect enters detached mode and waits for a new client connection.
// Returns (newConn, true) on reconnect, (nil, false) on timeout.
func (s *Session) waitForReconnect() (net.Conn, bool) {
	s.detached.Store(true)

	select {
	case conn := <-s.reconnectCh:
		return conn, true
	case <-time.After(ReconnectTimeout):
		return nil, false
	case <-s.closeCh:
		return nil, false
	}
}

// Close closes the session, terminating the agentIO and client connection.
func (s *Session) Close() {
	if s.closed.CompareAndSwap(false, true) {
		close(s.closeCh)
		s.agentIO.Close()
		s.clientMu.Lock()
		if s.clientConn != nil {
			s.clientConn.Close()
		}
		s.clientMu.Unlock()
	}
}

// SendWarning sends a drain warning message to the session.
func (s *Session) SendWarning(msg string) {
	select {
	case s.WarnCh <- msg:
	default:
	}
}
