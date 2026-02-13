package bridge

import (
	"bufio"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const relayIdleTimeout = 5 * time.Minute

// RelayPool manages relay connections from agents.
// Each agent maintains a single mTLS connection through the bridge's tunnel
// listener. The API sends HTTP requests to the bridge's internal endpoint,
// and the bridge forwards them over the relay connection to the agent.
// Idle connections are automatically reaped after relayIdleTimeout.
type RelayPool struct {
	logger *slog.Logger
	mu     sync.RWMutex
	conns  map[string]*relayConn // agent ID → relay connection
	stopCh chan struct{}
}

// relayConn wraps a relay connection with serialization.
// Only one HTTP request can be in flight per connection at a time.
type relayConn struct {
	conn       net.Conn
	reader     *bufio.Reader
	mu         sync.Mutex // serializes HTTP request/response pairs
	lastActive time.Time
}

// NewRelayPool creates a new relay pool and starts the idle reaper.
func NewRelayPool(logger *slog.Logger) *RelayPool {
	p := &RelayPool{
		logger: logger,
		conns:  make(map[string]*relayConn),
		stopCh: make(chan struct{}),
	}
	go p.reapLoop()
	return p
}

// Add registers a relay connection for an agent. If a previous connection
// exists for the same agent, it is closed and replaced.
func (p *RelayPool) Add(agentID string, conn net.Conn) {
	p.mu.Lock()
	old, exists := p.conns[agentID]
	p.conns[agentID] = &relayConn{
		conn:       conn,
		reader:     bufio.NewReader(conn),
		lastActive: time.Now(),
	}
	p.mu.Unlock()

	if exists {
		old.conn.Close()
	}

	p.logger.Info("relay connection added", "agent_id", agentID)
}

// Get returns the relay connection for an agent, or nil if none exists.
func (p *RelayPool) Get(agentID string) *relayConn {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.conns[agentID]
}

// Remove closes and removes a relay connection.
func (p *RelayPool) Remove(agentID string) {
	p.mu.Lock()
	rc, ok := p.conns[agentID]
	if ok {
		delete(p.conns, agentID)
	}
	p.mu.Unlock()

	if ok {
		rc.conn.Close()
		p.logger.Info("relay connection removed", "agent_id", agentID)
	}
}

// Count returns the number of active relay connections.
func (p *RelayPool) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.conns)
}

// CloseAll closes all relay connections and stops the reaper.
func (p *RelayPool) CloseAll() {
	close(p.stopCh)

	p.mu.Lock()
	for id, rc := range p.conns {
		rc.conn.Close()
		delete(p.conns, id)
	}
	p.mu.Unlock()
}

// reapLoop periodically checks for idle relay connections and closes them.
func (p *RelayPool) reapLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.stopCh:
			return
		case <-ticker.C:
			p.reapIdle()
		}
	}
}

// reapIdle closes relay connections that have been idle longer than relayIdleTimeout.
func (p *RelayPool) reapIdle() {
	now := time.Now()

	p.mu.Lock()
	var toRemove []string
	for id, rc := range p.conns {
		if now.Sub(rc.lastActive) > relayIdleTimeout {
			toRemove = append(toRemove, id)
		}
	}
	for _, id := range toRemove {
		if rc, ok := p.conns[id]; ok {
			rc.conn.Close()
			delete(p.conns, id)
		}
	}
	p.mu.Unlock()

	for _, id := range toRemove {
		p.logger.Info("relay connection reaped (idle)", "agent_id", id)
	}
}

// handleRelayRequest handles an HTTP relay request from the API server.
// The API sends requests to /relay/{agent_id}/... which are forwarded over
// the relay connection to the agent.
func (p *RelayPool) handleRelayRequest(w http.ResponseWriter, r *http.Request) {
	// Parse /relay/{agent_id}/... from the URL path
	path := strings.TrimPrefix(r.URL.Path, "/relay/")
	slashIdx := strings.Index(path, "/")

	var agentID, innerPath string
	if slashIdx == -1 {
		agentID = path
		innerPath = "/"
	} else {
		agentID = path[:slashIdx]
		innerPath = path[slashIdx:]
	}

	if agentID == "" {
		http.Error(w, "missing agent_id", http.StatusBadRequest)
		return
	}

	rc := p.Get(agentID)
	if rc == nil {
		http.Error(w, fmt.Sprintf("no relay connection for agent %s", agentID), http.StatusBadGateway)
		return
	}

	// Serialize requests on this connection
	rc.mu.Lock()
	defer rc.mu.Unlock()

	// Build the inner request to send to the agent
	innerReq, err := http.NewRequest(r.Method, innerPath, r.Body)
	if err != nil {
		http.Error(w, "failed to construct inner request", http.StatusInternalServerError)
		return
	}

	// Copy headers from the API request (already rewritten by the API proxy)
	innerReq.Header = r.Header.Clone()
	if fwdHost := r.Header.Get("X-Bamf-Forward-Host"); fwdHost != "" {
		innerReq.Host = fwdHost
	} else {
		innerReq.Host = r.Host
	}
	innerReq.RequestURI = innerPath
	if r.URL.RawQuery != "" {
		innerReq.RequestURI = innerPath + "?" + r.URL.RawQuery
		innerReq.URL.RawQuery = r.URL.RawQuery
	}

	// Write request to relay connection
	if err := innerReq.Write(rc.conn); err != nil {
		p.logger.Error("relay write error", "agent_id", agentID, "error", err)
		http.Error(w, "relay connection error", http.StatusBadGateway)
		p.Remove(agentID)
		return
	}

	// Read response from relay connection
	resp, err := http.ReadResponse(rc.reader, innerReq)
	if err != nil {
		p.logger.Error("relay read error", "agent_id", agentID, "error", err)
		http.Error(w, "relay connection error", http.StatusBadGateway)
		p.Remove(agentID)
		return
	}
	defer resp.Body.Close()

	// Mark connection as active
	rc.lastActive = time.Now()

	// Copy response headers, skipping hop-by-hop headers that must not be
	// forwarded through a proxy.  In particular, Transfer-Encoding and
	// Connection are managed by Go's HTTP server for the outer response;
	// copying them from the relay would cause the server to skip its own
	// chunked framing, producing a malformed response.
	hopByHop := map[string]bool{
		"Connection":          true,
		"Transfer-Encoding":   true,
		"Keep-Alive":          true,
		"Proxy-Authenticate":  true,
		"Proxy-Authorization": true,
		"Te":                  true,
		"Trailer":             true,
		"Upgrade":             true,
	}
	for k, vv := range resp.Header {
		if hopByHop[http.CanonicalHeaderKey(k)] {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}
