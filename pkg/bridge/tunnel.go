package bridge

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// NonMigratableProtocols lists tunnel protocols that maintain bridge-local state
// and cannot survive bridge migration. Only ssh-audit qualifies: the bridge
// terminates SSH and holds encryption state in-process. Database audit tunnels
// (postgres-audit, mysql-audit) use passive byte-stream tapping over a standard
// tunnel and ARE migratable — only the parser state is lost during reconnect.
var NonMigratableProtocols = map[string]bool{
	"ssh-audit": true,
	"web-ssh":   true,
	"web-db":    true,
}

// Tunnel represents an active tunnel between client and agent
type Tunnel struct {
	ID           string
	SessionToken string
	AgentID      string
	Protocol     string
	ClientConn   net.Conn
	AgentConn    net.Conn
	ClientReader io.Reader // if set, used instead of ClientConn for client→agent copy
	CreatedAt    time.Time
	BytesSent    atomic.Int64
	BytesRecv    atomic.Int64
	closed       atomic.Bool
	closeCh      chan struct{}

	// WarnCh receives drain warning messages for ssh-audit sessions.
	// The ssh-audit proxy goroutine monitors this channel and writes
	// messages to clientCh.Stderr() so users see warnings in their terminal.
	WarnCh chan string
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
		WarnCh:       make(chan string, 8),
	}
}

// SendWarning sends a drain warning message to the tunnel.
// Non-blocking — drops the message if the channel buffer is full.
func (t *Tunnel) SendWarning(msg string) {
	select {
	case t.WarnCh <- msg:
	default:
	}
}

// Run starts bidirectional data transfer
func (t *Tunnel) Run(ctx context.Context) error {
	errCh := make(chan error, 2)

	// Client -> Agent (use ClientReader if set, for tee/audit tapping)
	clientSrc := io.Reader(t.ClientConn)
	if t.ClientReader != nil {
		clientSrc = t.ClientReader
	}
	go func() {
		n, err := io.Copy(t.AgentConn, clientSrc)
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

// IsNonMigratable returns true if this tunnel's protocol prevents migration.
func (t *Tunnel) IsNonMigratable() bool {
	return NonMigratableProtocols[t.Protocol]
}

// DrainTunnelInfo holds session info collected for the drain API request.
type DrainTunnelInfo struct {
	SessionToken string `json:"session_token"`
	Protocol     string `json:"protocol"`
}

// TunnelManager manages active tunnels
type TunnelManager struct {
	logger  *slog.Logger
	tunnels map[string]*Tunnel
	mu      sync.RWMutex

	// countCh is closed+recreated whenever the tunnel count changes,
	// so WaitForCount can watch for changes without polling.
	countCh chan struct{}
}

// NewTunnelManager creates a new tunnel manager
func NewTunnelManager(logger *slog.Logger) *TunnelManager {
	return &TunnelManager{
		logger:  logger,
		tunnels: make(map[string]*Tunnel),
		countCh: make(chan struct{}),
	}
}

// Add adds a tunnel
func (m *TunnelManager) Add(t *Tunnel) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.tunnels[t.ID] = t
	m.notifyCountChange()
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
		m.notifyCountChange()
		m.logger.Debug("tunnel removed", "id", id)
	}
}

// Count returns the number of active tunnels
func (m *TunnelManager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.tunnels)
}

// NonMigratableCount returns the number of non-migratable tunnels.
func (m *TunnelManager) NonMigratableCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	count := 0
	for _, t := range m.tunnels {
		if t.IsNonMigratable() {
			count++
		}
	}
	return count
}

// CollectTunnelInfo returns drain info for all active tunnels.
func (m *TunnelManager) CollectTunnelInfo() []DrainTunnelInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	infos := make([]DrainTunnelInfo, 0, len(m.tunnels))
	for _, t := range m.tunnels {
		infos = append(infos, DrainTunnelInfo{
			SessionToken: t.SessionToken,
			Protocol:     t.Protocol,
		})
	}
	return infos
}

// WaitForCount blocks until the tunnel count reaches target or ctx expires.
func (m *TunnelManager) WaitForCount(ctx context.Context, target int) error {
	for {
		m.mu.RLock()
		count := len(m.tunnels)
		ch := m.countCh
		m.mu.RUnlock()

		if count <= target {
			return nil
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ch:
			// Count changed, re-check
		}
	}
}

// notifyCountChange signals all WaitForCount callers. Must be called with mu held.
func (m *TunnelManager) notifyCountChange() {
	close(m.countCh)
	m.countCh = make(chan struct{})
}

// closeAll force-closes all remaining tunnels.
func (m *TunnelManager) closeAll() {
	m.mu.Lock()
	tunnels := make([]*Tunnel, 0, len(m.tunnels))
	for _, t := range m.tunnels {
		tunnels = append(tunnels, t)
	}
	m.mu.Unlock()

	for _, t := range tunnels {
		t.Close()
	}
}

// DrainAll coordinates graceful tunnel migration via the API server.
//
// Two-phase drain:
//  1. Ask the API to migrate all migratable tunnels (sends "redial" to agents).
//     Wait for those tunnels to disconnect as agents reconnect to new bridges.
//  2. Non-migratable tunnels (ssh-audit, db-audit) remain open. Send escalating
//     warnings to ssh-audit sessions and wait for them to close naturally or
//     until the context deadline expires (terminationGracePeriodSeconds).
func (m *TunnelManager) DrainAll(ctx context.Context, apiClient *APIClient, bridgeID string) error {
	infos := m.CollectTunnelInfo()
	if len(infos) == 0 {
		return nil
	}

	m.logger.Info("draining tunnels", "count", len(infos))

	// Phase 1: Ask API to migrate migratable tunnels
	resp, err := apiClient.RequestDrain(ctx, bridgeID, infos)
	if err != nil {
		m.logger.Warn("drain request failed, force-closing all tunnels", "error", err)
		m.closeAll()
		return fmt.Errorf("drain request failed: %w", err)
	}

	m.logger.Info("drain response",
		"migrated", resp.MigratedCount,
		"non_migratable", len(resp.NonMigratableSessionIDs),
		"errors", len(resp.Errors),
	)

	// Wait for migrated tunnels to disconnect (agents redial to new bridge,
	// old connections drop naturally). 30s is generous — redial is fast.
	nonMigratableCount := len(resp.NonMigratableSessionIDs)
	migrationCtx, migrationCancel := context.WithTimeout(ctx, 30*time.Second)
	defer migrationCancel()
	if err := m.WaitForCount(migrationCtx, nonMigratableCount); err != nil {
		m.logger.Warn("timed out waiting for migrated tunnels to close",
			"remaining", m.Count(),
			"expected", nonMigratableCount,
		)
	}

	// Phase 2: Non-migratable sessions — send warnings and wait
	if m.Count() > 0 {
		m.sendDrainWarnings()

		deadline, hasDeadline := ctx.Deadline()
		if hasDeadline {
			m.logger.Info("waiting for non-migratable sessions to finish",
				"remaining", m.Count(),
				"deadline", deadline,
			)
		}

		m.waitWithWarnings(ctx)
	}

	// Force-close anything still open (SIGKILL imminent)
	remaining := m.Count()
	if remaining > 0 {
		m.logger.Warn("force-closing remaining tunnels", "count", remaining)
	}
	m.closeAll()
	return nil
}

// sendDrainWarnings sends the initial drain warning to all non-migratable tunnels.
func (m *TunnelManager) sendDrainWarnings() {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, t := range m.tunnels {
		if t.IsNonMigratable() {
			t.SendWarning(
				"\r\n*** BAMF: This bridge is shutting down. Your recorded session cannot be migrated.\r\n" +
					"*** BAMF: Please save your work and disconnect.\r\n",
			)
		}
	}
}

// sendWarningToAll sends a message to all remaining non-migratable tunnels.
func (m *TunnelManager) sendWarningToAll(msg string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, t := range m.tunnels {
		if t.IsNonMigratable() {
			t.SendWarning(msg)
		}
	}
}

// waitWithWarnings waits for all tunnels to close while sending escalating
// warnings at 5 minutes and 1 minute before the context deadline.
func (m *TunnelManager) waitWithWarnings(ctx context.Context) {
	deadline, hasDeadline := ctx.Deadline()

	// Calculate warning times
	var warn5min, warn1min time.Time
	if hasDeadline {
		warn5min = deadline.Add(-5 * time.Minute)
		warn1min = deadline.Add(-1 * time.Minute)
	}

	sent5min := false
	sent1min := false

	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		if m.Count() == 0 {
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := time.Now()
			if hasDeadline && !sent5min && now.After(warn5min) {
				sent5min = true
				remaining := time.Until(deadline).Round(time.Second)
				m.sendWarningToAll(fmt.Sprintf(
					"\r\n*** BAMF: WARNING — This session will be forcibly terminated in %s.\r\n"+
						"*** BAMF: Please save your work and disconnect NOW.\r\n",
					remaining,
				))
			}
			if hasDeadline && !sent1min && now.After(warn1min) {
				sent1min = true
				m.sendWarningToAll(
					"\r\n*** BAMF: FINAL WARNING — Session termination in 60 seconds.\r\n",
				)
			}
		}
	}
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
