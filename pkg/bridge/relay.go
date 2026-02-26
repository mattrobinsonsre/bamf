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

// relayAcquireTimeout is how long to wait for a relay connection before
// giving up. Prevents indefinite blocking when the pool is exhausted
// (e.g. re-entrant requests that deadlock if all connections are held).
const relayAcquireTimeout = 10 * time.Second

// RelayPool manages relay connections from agents.
// Each agent may have multiple mTLS relay connections through the bridge's
// tunnel listener, enabling concurrent request handling. The API sends HTTP
// requests to the bridge's internal endpoint, and the bridge forwards them
// over an available relay connection to the agent.
// Idle connections are automatically reaped after relayIdleTimeout.
type RelayPool struct {
	logger *slog.Logger
	mu     sync.RWMutex
	conns  map[string][]*relayConn // agent ID → pool of relay connections
	stopCh chan struct{}
	done   chan struct{} // closed when reapLoop exits
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
		conns:  make(map[string][]*relayConn),
		stopCh: make(chan struct{}),
		done:   make(chan struct{}),
	}
	go p.reapLoop()
	return p
}

// Add registers a relay connection for an agent. Multiple connections per
// agent are supported for concurrent request handling.
func (p *RelayPool) Add(agentID string, conn net.Conn) {
	rc := &relayConn{
		conn:       conn,
		reader:     bufio.NewReader(conn),
		lastActive: time.Now(),
	}

	p.mu.Lock()
	p.conns[agentID] = append(p.conns[agentID], rc)
	poolSize := len(p.conns[agentID])
	p.mu.Unlock()

	p.logger.Info("relay connection added", "agent_id", agentID, "pool_size", poolSize)
}

// acquire returns an available (unlocked) relay connection for an agent.
// It tries each connection in the pool with TryLock. If all are busy, it
// polls with a timeout to avoid indefinite blocking (which would cause
// deadlocks when re-entrant requests exhaust the pool).
// Returns (conn, true) on success, (nil, false) if no connections exist
// or the timeout expires.
func (p *RelayPool) acquire(agentID string) (*relayConn, bool) {
	p.mu.RLock()
	pool := p.conns[agentID]
	if len(pool) == 0 {
		p.mu.RUnlock()
		return nil, false
	}
	// Copy the slice ref so we can release the read lock before locking a conn.
	conns := make([]*relayConn, len(pool))
	copy(conns, pool)
	p.mu.RUnlock()

	// First pass: try to find an idle connection without blocking.
	for _, rc := range conns {
		if rc.mu.TryLock() {
			return rc, true
		}
	}

	// All connections busy — poll with timeout instead of blocking forever.
	// This prevents deadlocks when re-entrant requests (e.g. kubamf calling
	// K8s API through kube proxy) exhaust the pool.
	deadline := time.Now().Add(relayAcquireTimeout)
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		for _, rc := range conns {
			if rc.mu.TryLock() {
				return rc, true
			}
		}
	}

	p.logger.Warn("relay pool acquire timeout", "agent_id", agentID,
		"pool_size", len(conns), "timeout", relayAcquireTimeout)
	return nil, false
}

// removeConn removes a specific connection from the pool and closes it.
func (p *RelayPool) removeConn(agentID string, rc *relayConn) {
	p.mu.Lock()
	pool := p.conns[agentID]
	for i, c := range pool {
		if c == rc {
			p.conns[agentID] = append(pool[:i], pool[i+1:]...)
			break
		}
	}
	if len(p.conns[agentID]) == 0 {
		delete(p.conns, agentID)
	}
	p.mu.Unlock()

	rc.conn.Close()
}

// detachConn removes a specific connection from the pool WITHOUT closing it.
func (p *RelayPool) detachConn(agentID string, rc *relayConn) {
	p.mu.Lock()
	pool := p.conns[agentID]
	for i, c := range pool {
		if c == rc {
			p.conns[agentID] = append(pool[:i], pool[i+1:]...)
			break
		}
	}
	if len(p.conns[agentID]) == 0 {
		delete(p.conns, agentID)
	}
	p.mu.Unlock()
}

// Remove closes and removes all relay connections for an agent.
func (p *RelayPool) Remove(agentID string) {
	p.mu.Lock()
	pool := p.conns[agentID]
	delete(p.conns, agentID)
	p.mu.Unlock()

	for _, rc := range pool {
		rc.conn.Close()
	}
	if len(pool) > 0 {
		p.logger.Info("relay connections removed", "agent_id", agentID, "count", len(pool))
	}
}

// Detach removes one relay connection from the pool WITHOUT closing it.
// Returns the relayConn so the caller can use it for a byte-splice.
// The idle reaper will no longer touch the returned connection.
func (p *RelayPool) Detach(agentID string) *relayConn {
	p.mu.Lock()
	pool := p.conns[agentID]
	if len(pool) == 0 {
		p.mu.Unlock()
		return nil
	}
	// Take the first connection from the pool.
	rc := pool[0]
	p.conns[agentID] = pool[1:]
	if len(p.conns[agentID]) == 0 {
		delete(p.conns, agentID)
	}
	p.mu.Unlock()

	p.logger.Info("relay connection detached for upgrade", "agent_id", agentID)
	return rc
}

// Count returns the number of agents with active relay connections.
func (p *RelayPool) Count() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return len(p.conns)
}

// CloseAll closes all relay connections and stops the reaper.
func (p *RelayPool) CloseAll() {
	close(p.stopCh)
	<-p.done // wait for reapLoop goroutine to exit

	p.mu.Lock()
	for id, pool := range p.conns {
		for _, rc := range pool {
			rc.conn.Close()
		}
		delete(p.conns, id)
	}
	p.mu.Unlock()
}

// reapLoop periodically checks for idle relay connections and closes them.
func (p *RelayPool) reapLoop() {
	defer close(p.done)
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
	for id, pool := range p.conns {
		var keep []*relayConn
		for _, rc := range pool {
			if now.Sub(rc.lastActive) > relayIdleTimeout {
				rc.conn.Close()
				p.logger.Info("relay connection reaped (idle)", "agent_id", id)
			} else {
				keep = append(keep, rc)
			}
		}
		if len(keep) == 0 {
			delete(p.conns, id)
		} else {
			p.conns[id] = keep
		}
	}
	p.mu.Unlock()
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

	rc, ok := p.acquire(agentID)
	if !ok {
		http.Error(w, fmt.Sprintf("no relay connection for agent %s", agentID), http.StatusBadGateway)
		return
	}

	isUpgrade := r.Header.Get("Upgrade") != ""

	// Build the inner request to send to the agent
	innerReq, err := http.NewRequest(r.Method, innerPath, r.Body)
	if err != nil {
		rc.mu.Unlock()
		http.Error(w, "failed to construct inner request", http.StatusInternalServerError)
		return
	}

	// Copy headers and content length from the API request (already rewritten
	// by the API proxy).  Without ContentLength, Go's Request.Write uses
	// chunked transfer encoding which many targets cannot decode.
	innerReq.ContentLength = r.ContentLength
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
		rc.mu.Unlock()
		http.Error(w, "relay connection error", http.StatusBadGateway)
		p.removeConn(agentID, rc)
		return
	}

	// Read response from relay connection
	resp, err := http.ReadResponse(rc.reader, innerReq)
	if err != nil {
		p.logger.Error("relay read error", "agent_id", agentID, "error", err)
		rc.mu.Unlock()
		http.Error(w, "relay connection error", http.StatusBadGateway)
		p.removeConn(agentID, rc)
		return
	}

	// Mark connection as active
	rc.lastActive = time.Now()

	// Upgrade response (101 Switching Protocols) — detach the relay conn
	// from the pool and splice bytes between the API conn and the relay conn.
	// IMPORTANT: detach BEFORE unlocking the mutex. If we unlock first, another
	// goroutine can acquire() this conn via TryLock and write a different HTTP
	// request on it, corrupting the WebSocket splice.
	if isUpgrade && resp.StatusCode == http.StatusSwitchingProtocols {
		p.detachConn(agentID, rc)
		rc.mu.Unlock()
		p.handleUpgradeResponse(w, r, agentID, rc, resp)
		return
	}

	defer func() {
		rc.mu.Unlock()
		resp.Body.Close()
	}()

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

	// For streaming responses (SSE), flush after each read so the client
	// receives events immediately rather than waiting for the buffer to fill.
	// Detach the relay conn from the pool so it doesn't block other requests.
	// The SSE stream continues on the detached conn until it ends naturally.
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.HasPrefix(ct, "text/event-stream") {
		p.detachConn(agentID, rc)
		flusher, ok := w.(http.Flusher)
		if ok {
			flusher.Flush() // flush headers immediately
			buf := make([]byte, 4096)
			for {
				n, err := resp.Body.Read(buf)
				if n > 0 {
					_, _ = w.Write(buf[:n])
					flusher.Flush()
				}
				if err != nil {
					break
				}
			}
			return
		}
	}

	_, _ = io.Copy(w, resp.Body)
}

// handleUpgradeResponse handles a 101 Switching Protocols response by
// hijacking the API→Bridge HTTP connection and splicing it with the
// relay connection to the agent.
func (p *RelayPool) handleUpgradeResponse(
	w http.ResponseWriter,
	r *http.Request,
	agentID string,
	rc *relayConn,
	resp *http.Response,
) {
	resp.Body.Close()

	// Relay conn is already detached from the pool by the caller
	// (handleRelayRequest detaches before unlocking the mutex to prevent
	// a race where another goroutine acquires the conn between unlock
	// and detach).

	// Hijack the API→Bridge HTTP connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		p.logger.Error("upgrade: ResponseWriter does not support Hijack")
		http.Error(w, "server does not support upgrades", http.StatusInternalServerError)
		rc.conn.Close()
		return
	}

	apiConn, apiBuf, err := hijacker.Hijack()
	if err != nil {
		p.logger.Error("upgrade: hijack failed", "error", err)
		rc.conn.Close()
		return
	}

	// Write the 101 response to the API connection
	resp.Proto = "HTTP/1.1"
	resp.ProtoMajor = 1
	resp.ProtoMinor = 1
	if err := resp.Write(apiConn); err != nil {
		p.logger.Error("upgrade: write 101 to API conn failed", "error", err)
		apiConn.Close()
		rc.conn.Close()
		return
	}

	p.logger.Info("upgrade: splicing API ↔ agent relay",
		"agent_id", agentID,
		"upgrade", resp.Header.Get("Upgrade"),
	)

	// Bidirectional byte splice: API conn ↔ relay conn
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(rc.conn, apiConn)
		done <- struct{}{}
	}()
	go func() {
		// Flush any buffered data from the relay reader first
		if rc.reader.Buffered() > 0 {
			buffered := make([]byte, rc.reader.Buffered())
			_, _ = rc.reader.Read(buffered)
			_, _ = apiConn.Write(buffered)
		}
		// Flush any buffered data from the API side (ReadWriter
		// embeds both Reader and Writer, so qualify with .Reader)
		if apiBuf != nil && apiBuf.Reader.Buffered() > 0 { //nolint:staticcheck // must qualify embedded Reader
			buffered := make([]byte, apiBuf.Reader.Buffered()) //nolint:staticcheck
			_, _ = apiBuf.Reader.Read(buffered)                //nolint:staticcheck
			_, _ = rc.conn.Write(buffered)
		}
		_, _ = io.Copy(apiConn, rc.conn)
		done <- struct{}{}
	}()
	<-done

	apiConn.Close()
	rc.conn.Close()
	p.logger.Info("upgrade: splice ended", "agent_id", agentID)
}
