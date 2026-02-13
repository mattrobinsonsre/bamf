package bridge

import (
	"context"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// Tunnel represents an active tunnel between client and agent
type Tunnel struct {
	ID           string
	SessionToken string
	AgentID      string
	Protocol     string
	ClientConn   net.Conn
	AgentConn    net.Conn
	CreatedAt    time.Time
	BytesSent    atomic.Int64
	BytesRecv    atomic.Int64
	closed       atomic.Bool
	closeCh      chan struct{}
}

// NewTunnel creates a new tunnel
func NewTunnel(id, sessionToken, agentID, protocol string, clientConn, agentConn net.Conn) *Tunnel {
	return &Tunnel{
		ID:           id,
		SessionToken: sessionToken,
		AgentID:      agentID,
		Protocol:     protocol,
		ClientConn:   clientConn,
		AgentConn:    agentConn,
		CreatedAt:    time.Now(),
		closeCh:      make(chan struct{}),
	}
}

// Run starts bidirectional data transfer
func (t *Tunnel) Run(ctx context.Context) error {
	errCh := make(chan error, 2)

	// Client -> Agent
	go func() {
		n, err := io.Copy(t.AgentConn, t.ClientConn)
		t.BytesSent.Add(n)
		errCh <- err
	}()

	// Agent -> Client
	go func() {
		n, err := io.Copy(t.ClientConn, t.AgentConn)
		t.BytesRecv.Add(n)
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
		return err
	}
}

// Close closes the tunnel
func (t *Tunnel) Close() {
	if t.closed.CompareAndSwap(false, true) {
		close(t.closeCh)
		t.ClientConn.Close()
		t.AgentConn.Close()
	}
}

// IsClosed returns whether the tunnel is closed
func (t *Tunnel) IsClosed() bool {
	return t.closed.Load()
}

// TunnelManager manages active tunnels
type TunnelManager struct {
	logger  *slog.Logger
	tunnels map[string]*Tunnel
	mu      sync.RWMutex
}

// NewTunnelManager creates a new tunnel manager
func NewTunnelManager(logger *slog.Logger) *TunnelManager {
	return &TunnelManager{
		logger:  logger,
		tunnels: make(map[string]*Tunnel),
	}
}

// Add adds a tunnel
func (m *TunnelManager) Add(t *Tunnel) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tunnels[t.ID] = t
	m.logger.Debug("tunnel added", "id", t.ID, "protocol", t.Protocol)
}

// Get retrieves a tunnel by ID
func (m *TunnelManager) Get(id string) (*Tunnel, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tunnels[id]
	return t, ok
}

// Remove removes a tunnel
func (m *TunnelManager) Remove(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if t, ok := m.tunnels[id]; ok {
		t.Close()
		delete(m.tunnels, id)
		m.logger.Debug("tunnel removed", "id", id)
	}
}

// Count returns the number of active tunnels
func (m *TunnelManager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.tunnels)
}

// DrainAll closes all tunnels gracefully
// In production, this would coordinate migration with the API server
func (m *TunnelManager) DrainAll(ctx context.Context) error {
	m.mu.Lock()
	tunnels := make([]*Tunnel, 0, len(m.tunnels))
	for _, t := range m.tunnels {
		tunnels = append(tunnels, t)
	}
	m.mu.Unlock()

	m.logger.Info("draining tunnels", "count", len(tunnels))

	// In production:
	// 1. Notify API server that we're draining
	// 2. API assigns new bridge for each tunnel
	// 3. Buffer tunnel data
	// 4. Migrate tunnels to new bridge
	// 5. Close old connections

	// For now, just close all tunnels
	for _, t := range tunnels {
		t.Close()
	}

	return nil
}

// Stats returns tunnel statistics
func (m *TunnelManager) Stats() map[string]interface{} {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var totalSent, totalRecv int64
	protocols := make(map[string]int)

	for _, t := range m.tunnels {
		totalSent += t.BytesSent.Load()
		totalRecv += t.BytesRecv.Load()
		protocols[t.Protocol]++
	}

	return map[string]interface{}{
		"active_tunnels": len(m.tunnels),
		"bytes_sent":     totalSent,
		"bytes_received": totalRecv,
		"by_protocol":    protocols,
	}
}
