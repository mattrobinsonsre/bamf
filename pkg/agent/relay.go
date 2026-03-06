package agent

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// relayPoolSize is the number of concurrent relay connections the agent
// opens to the bridge. Multiple connections allow the bridge to dispatch
// concurrent requests to the agent without head-of-line blocking.
//
// Size must account for re-entrant requests: when a proxied web app (e.g.
// kubamf) calls back through the same BAMF agent (e.g. K8s API via kube
// proxy), the inner request needs its own relay connection while the outer
// connection is still held. With N concurrent browser requests, up to 2N
// relay connections may be needed. Additionally, SSE streams detach
// connections permanently (replenished, but briefly unavailable).
//
// 32 supports up to ~12 concurrent re-entrant requests plus SSE headroom.
const relayPoolSize = 32

// RelayManager maintains mTLS connections to a bridge for relaying HTTP
// requests. Multiple connections are opened for concurrent request handling.
// Connections are established on-demand when the API sends a relay_connect
// SSE event, and close naturally when the bridge reaps them after an idle
// timeout. No auto-reconnect — the API sends a new relay_connect when
// the next browser request needs it.
type RelayManager struct {
	agentID   string
	resources []ResourceConfig
	tlsConfig *tls.Config
	logger    *slog.Logger

	mu      sync.Mutex
	workers []*relayWorker
	stopCh  chan struct{} // closed to signal all workers to stop

	// Cached bridge address for auto-reconnect after SSE/upgrade detach
	lastBridgeHost string
	lastBridgePort int
}

// relayWorker represents a single relay connection with its own serve loop.
type relayWorker struct {
	conn    net.Conn
	stopped chan struct{} // closed when the serve goroutine exits
}

// NewRelayManager creates a new relay manager.
func NewRelayManager(agentID string, resources []ResourceConfig, tlsConfig *tls.Config, logger *slog.Logger) *RelayManager {
	return &RelayManager{
		agentID:   agentID,
		resources: resources,
		tlsConfig: tlsConfig,
		logger:    logger,
	}
}

// Connect establishes relay connections to the bridge. If previous
// connections exist, they are closed first. Opens relayPoolSize connections
// for concurrent request handling. Each connection runs its own serve loop.
func (rm *RelayManager) Connect(bridgeHost string, bridgePort int) error {
	rm.closeAll()

	rm.mu.Lock()
	rm.lastBridgeHost = bridgeHost
	rm.lastBridgePort = bridgePort
	rm.stopCh = make(chan struct{})
	rm.mu.Unlock()

	for i := 0; i < relayPoolSize; i++ {
		conn, err := rm.dial(bridgeHost, bridgePort)
		if err != nil {
			if i == 0 {
				// First connection must succeed
				return err
			}
			rm.logger.Warn("relay pool: additional connection failed",
				"index", i, "error", err)
			break
		}
		rm.addWorker(conn)
	}

	rm.logger.Info("relay connections established",
		"bridge", fmt.Sprintf("%s:%d", bridgeHost, bridgePort),
		"pool_size", rm.workerCount(),
	)
	return nil
}

// closeAll stops all workers and waits for them to exit.
func (rm *RelayManager) closeAll() {
	rm.mu.Lock()
	workers := rm.workers
	rm.workers = nil
	stopCh := rm.stopCh
	rm.mu.Unlock()

	if len(workers) == 0 {
		return
	}

	// Signal all workers to stop
	if stopCh != nil {
		select {
		case <-stopCh:
			// Already closed
		default:
			close(stopCh)
		}
	}

	// Close all connections and wait for goroutines to exit
	for _, w := range workers {
		w.conn.Close()
	}
	for _, w := range workers {
		<-w.stopped
	}
}

// addWorker creates a new worker for a connection and starts its serve loop.
func (rm *RelayManager) addWorker(conn net.Conn) {
	w := &relayWorker{
		conn:    conn,
		stopped: make(chan struct{}),
	}

	rm.mu.Lock()
	rm.workers = append(rm.workers, w)
	rm.mu.Unlock()

	go rm.serve(w)
}

// removeWorker removes a worker from the list (does NOT close the connection).
func (rm *RelayManager) removeWorker(w *relayWorker) {
	rm.mu.Lock()
	for i, wk := range rm.workers {
		if wk == w {
			rm.workers = append(rm.workers[:i], rm.workers[i+1:]...)
			break
		}
	}
	rm.mu.Unlock()
}

// workerCount returns the number of active workers.
func (rm *RelayManager) workerCount() int {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	return len(rm.workers)
}

// dial connects to the bridge and sends the relay protocol header.
func (rm *RelayManager) dial(bridgeHost string, bridgePort int) (net.Conn, error) {
	addr := fmt.Sprintf("%s:%d", bridgeHost, bridgePort)

	tlsCfg := rm.tlsConfig.Clone()
	tlsCfg.ServerName = bridgeHost

	conn, err := tls.Dial("tcp", addr, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("relay dial failed: %w", err)
	}

	// Send relay protocol header
	if _, err := fmt.Fprintf(conn, "RELAY\n%s\n", rm.agentID); err != nil {
		conn.Close()
		return nil, fmt.Errorf("relay handshake failed: %w", err)
	}

	return conn, nil
}

// serve reads HTTP requests from a worker's relay connection and forwards
// them to target resources. When the connection drops, the worker exits.
func (rm *RelayManager) serve(w *relayWorker) {
	defer close(w.stopped)

	rm.mu.Lock()
	stopCh := rm.stopCh
	rm.mu.Unlock()

	conn := w.conn
	reader := bufio.NewReader(conn)

	// detached is set to true when the connection is handed off to a
	// background goroutine (streaming, upgrade). When true, the defer
	// must NOT close the connection — the goroutine owns it.
	detached := false

	defer func() {
		if !detached {
			rm.removeWorker(w)
			conn.Close()
		}

		// Replenish pool if below target and not shutting down
		select {
		case <-stopCh:
			// Manager is shutting down, don't reconnect
		default:
			count := rm.workerCount()
			if count == 0 {
				// All connections gone — delayed reconnect gives
				// API's relay_connect SSE priority
				rm.mu.Lock()
				host := rm.lastBridgeHost
				port := rm.lastBridgePort
				rm.mu.Unlock()
				go rm.reconnectIfNeeded(host, port)
			} else if count < relayPoolSize {
				// Pool degraded but not empty — replenish immediately
				go rm.replenishPool()
			}
		}
	}()

	for {
		select {
		case <-stopCh:
			return
		default:
		}

		req, err := http.ReadRequest(reader)
		if err != nil {
			// Connection closed by bridge (idle timeout) or network error.
			rm.logger.Info("relay connection closed", "error", err)
			return
		}

		// Upgrade requests (WebSocket) — consume the relay conn for
		// bidirectional byte-splice. After the upgrade finishes, the
		// relay conn is dead and the worker exits.
		if isUpgradeRequest(req) {
			rm.logger.Info("relay handling upgrade request",
				"path", req.URL.Path,
				"upgrade", req.Header.Get("Upgrade"),
			)
			// Detach this worker's conn so Close()/Connect() won't
			// interfere while the splice is running.
			rm.removeWorker(w)
			detached = true
			go rm.replenishPool()

			// handleUpgrade blocks until the splice ends, then closes conn
			rm.handleUpgrade(req, conn)
			return
		}

		// Check if the response should be streamed rather than buffered
		resp := rm.forwardRequest(req)

		if isStreamingResponse(resp) {
			// Streaming response (SSE). Detach this worker and let
			// the stream run in a background goroutine.
			rm.logger.Info("relay handling streaming response",
				"path", req.URL.Path,
				"content_type", resp.Header.Get("Content-Type"),
			)

			rm.removeWorker(w)
			detached = true
			go rm.replenishPool()

			go func() {
				resp.TransferEncoding = []string{"chunked"}
				resp.ContentLength = -1
				resp.Close = false
				resp.Proto = "HTTP/1.1"
				resp.ProtoMajor = 1
				resp.ProtoMinor = 1

				if err := resp.Write(conn); err != nil {
					rm.logger.Info("relay streaming write ended", "error", err)
				}
				resp.Body.Close()
				conn.Close()
			}()
			return
		}

		// Normalize response framing for the persistent relay connection.
		// The bridge detects body boundaries via Content-Length or chunked
		// encoding.  Previously this code used io.ReadAll() to buffer the
		// entire body and set Content-Length, but that caused OOM kills on
		// large K8s API responses.  Instead, use chunked transfer encoding
		// when Content-Length is unknown — Go's resp.Write() streams the
		// body in chunks without buffering it all in memory.
		resp.Proto = "HTTP/1.1"
		resp.ProtoMajor = 1
		resp.ProtoMinor = 1
		resp.Close = false
		if resp.ContentLength < 0 {
			resp.TransferEncoding = []string{"chunked"}
		}

		if err := resp.Write(conn); err != nil {
			rm.logger.Info("relay write error, connection lost", "error", err)
			return
		}
	}
}

// isUpgradeRequest returns true if the request contains an Upgrade header.
func isUpgradeRequest(req *http.Request) bool {
	return req.Header.Get("Upgrade") != ""
}

// isStreamingResponse returns true if the response is an unbounded stream
// (Server-Sent Events) that should trigger relay connection detach.
// Only SSE qualifies — regular chunked responses (HTML, JS, JSON) have
// finite bodies and complete naturally without blocking the relay.
func isStreamingResponse(resp *http.Response) bool {
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.HasPrefix(ct, "text/event-stream")
}

// handleUpgrade forwards an HTTP upgrade request (WebSocket) to the target
// using a raw TCP connection, then splices bytes bidirectionally between the
// relay conn and the target conn. When the splice ends, both conns are closed.
func (rm *RelayManager) handleUpgrade(req *http.Request, relayConn net.Conn) {
	defer relayConn.Close()

	targetURL := req.Header.Get("X-Bamf-Target")
	req.Header.Del("X-Bamf-Target")
	req.Header.Del("X-Bamf-Resource")

	if targetURL == "" {
		resp := errorResponse(req, http.StatusBadGateway, "missing X-Bamf-Target header")
		_ = resp.Write(relayConn)
		return
	}

	// Detect K8s request
	k8sGroups := req.Header.Get("X-Forwarded-K8s-Groups")
	userEmail := req.Header.Get("X-Forwarded-Email")
	isK8sRequest := k8sGroups != ""

	// Always strip Impersonate-* headers — prevent injection from clients
	for key := range req.Header {
		if strings.HasPrefix(strings.ToLower(key), "impersonate-") {
			req.Header.Del(key)
		}
	}

	parsed, err := url.Parse(targetURL)
	if err != nil {
		resp := errorResponse(req, http.StatusBadGateway, "invalid X-Bamf-Target: "+err.Error())
		_ = resp.Write(relayConn)
		return
	}

	// For K8s requests: strip forwarded headers and set impersonation headers
	if isK8sRequest {
		req.Header.Del("X-Forwarded-K8s-Groups")
		req.Header.Del("X-Forwarded-Email")
		req.Header.Del("X-Forwarded-User")
		req.Header.Del("X-Forwarded-Roles")
		req.Header.Del("X-Forwarded-Groups")
		req.Header.Del("X-Forwarded-Host")
		req.Header.Del("X-Forwarded-Proto")
		req.Header.Del("X-Forwarded-For")

		if userEmail == "" {
			resp := errorResponse(req, http.StatusForbidden, "missing X-Forwarded-Email for K8s request")
			_ = resp.Write(relayConn)
			return
		}
		req.Header.Set("Impersonate-User", userEmail)
		for _, group := range strings.Split(k8sGroups, ",") {
			group = strings.TrimSpace(group)
			if group != "" {
				req.Header.Add("Impersonate-Group", group)
			}
		}
		saToken, tokenErr := readSAToken()
		if tokenErr != nil {
			rm.logger.Error("failed to read SA token for upgrade", "error", tokenErr)
			resp := errorResponse(req, http.StatusBadGateway, "agent SA token unavailable")
			_ = resp.Write(relayConn)
			return
		}
		req.Header.Set("Authorization", "Bearer "+saToken)
	}

	// Dial target directly with raw TCP (or TLS for K8s/HTTPS targets)
	targetAddr := parsed.Host
	if !strings.Contains(targetAddr, ":") {
		if parsed.Scheme == "https" {
			targetAddr += ":443"
		} else {
			targetAddr += ":80"
		}
	}

	var targetConn net.Conn
	if parsed.Scheme == "https" {
		var tlsCfg *tls.Config
		if isK8sRequest {
			// Use K8s cluster CA
			caCert, readErr := os.ReadFile(saCACertPath)
			if readErr != nil {
				resp := errorResponse(req, http.StatusBadGateway, "agent K8s CA cert unavailable")
				_ = resp.Write(relayConn)
				return
			}
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(caCert)
			tlsCfg = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS13}
		} else {
			tlsCfg = &tls.Config{MinVersion: tls.VersionTLS13}
		}
		tlsCfg.ServerName = parsed.Hostname()
		targetConn, err = tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", targetAddr, tlsCfg)
	} else {
		targetConn, err = net.DialTimeout("tcp", targetAddr, 10*time.Second)
	}
	if err != nil {
		rm.logger.Error("upgrade: target dial failed", "target", targetAddr, "error", err)
		resp := errorResponse(req, http.StatusBadGateway, "target dial failed: "+err.Error())
		_ = resp.Write(relayConn)
		return
	}
	defer targetConn.Close()

	// Write the HTTP upgrade request to the target
	outURL := *parsed
	outURL.Path = req.URL.Path
	outURL.RawQuery = req.URL.RawQuery
	req.URL = &outURL
	req.Host = parsed.Host
	req.RequestURI = ""
	if err := req.Write(targetConn); err != nil {
		rm.logger.Error("upgrade: write to target failed", "error", err)
		resp := errorResponse(req, http.StatusBadGateway, "write to target failed")
		_ = resp.Write(relayConn)
		return
	}

	// Read the target's response
	targetReader := bufio.NewReader(targetConn)
	resp, err := http.ReadResponse(targetReader, req)
	if err != nil {
		rm.logger.Error("upgrade: read target response failed", "error", err)
		errResp := errorResponse(req, http.StatusBadGateway, "target response error")
		_ = errResp.Write(relayConn)
		return
	}

	if resp.StatusCode != http.StatusSwitchingProtocols {
		// Not a 101 — write the error response back to relay conn
		rm.logger.Warn("upgrade: target did not switch protocols",
			"status", resp.StatusCode,
		)
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		resp.Proto = "HTTP/1.1"
		resp.ProtoMajor = 1
		resp.ProtoMinor = 1
		_ = resp.Write(relayConn)
		return
	}
	resp.Body.Close()

	// Write the 101 response back to relay conn
	resp.Proto = "HTTP/1.1"
	resp.ProtoMajor = 1
	resp.ProtoMinor = 1
	if err := resp.Write(relayConn); err != nil {
		rm.logger.Error("upgrade: write 101 to relay failed", "error", err)
		return
	}

	rm.logger.Info("upgrade: splicing relay ↔ target",
		"path", outURL.Path,
		"upgrade", resp.Header.Get("Upgrade"),
	)

	// Bidirectional byte splice
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(targetConn, relayConn)
		done <- struct{}{}
	}()
	go func() {
		// Flush any buffered data from the target reader first
		if targetReader.Buffered() > 0 {
			buffered := make([]byte, targetReader.Buffered())
			_, _ = targetReader.Read(buffered)
			_, _ = relayConn.Write(buffered)
		}
		_, _ = io.Copy(relayConn, targetConn)
		done <- struct{}{}
	}()
	<-done

	rm.logger.Info("upgrade: splice ended", "path", outURL.Path)
}

// replenishPool opens new relay connections to bring the pool back up to
// relayPoolSize. Unlike Connect(), this does NOT close existing connections —
// it only adds new ones. Called when connections are detached for streaming or
// upgrade to maintain concurrency capacity.
// Each connection is dialed one at a time, re-checking the count after each
// add to avoid over-allocation from concurrent replenishPool calls.
func (rm *RelayManager) replenishPool() {
	for {
		rm.mu.Lock()
		host := rm.lastBridgeHost
		port := rm.lastBridgePort
		current := len(rm.workers)
		stopCh := rm.stopCh
		rm.mu.Unlock()

		if host == "" || current >= relayPoolSize {
			return
		}
		select {
		case <-stopCh:
			return
		default:
		}

		conn, err := rm.dial(host, port)
		if err != nil {
			rm.logger.Warn("relay pool replenish failed", "error", err)
			return
		}
		rm.addWorker(conn)
		rm.logger.Info("relay pool replenished",
			"pool_size", rm.workerCount())
	}
}

// reconnectIfNeeded opens new relay connections unless some were already
// established (e.g. by the API's relay_connect). This prevents the race
// between agent-initiated reconnect and API-initiated relay_connect — whichever
// arrives second finds IsConnected()=true and skips.
func (rm *RelayManager) reconnectIfNeeded(bridgeHost string, bridgePort int) {
	if bridgeHost == "" {
		return
	}
	// Wait long enough for the API's relay_connect to arrive and complete.
	// The API detects the 502 → sends relay_connect → agent handles it in
	// ~200-400ms total. 500ms gives relay_connect priority; if it hasn't
	// arrived by then, we self-heal.
	time.Sleep(500 * time.Millisecond)

	if rm.IsConnected() {
		return // relay_connect already handled it
	}

	if err := rm.Connect(bridgeHost, bridgePort); err != nil {
		rm.logger.Warn("relay auto-reconnect failed",
			"bridge", fmt.Sprintf("%s:%d", bridgeHost, bridgePort),
			"error", err,
		)
	} else {
		rm.logger.Info("relay auto-reconnect succeeded",
			"bridge", fmt.Sprintf("%s:%d", bridgeHost, bridgePort),
		)
	}
}

// forwardRequest forwards an HTTP request to the target resource and returns
// the response. The target is determined from the X-Bamf-Target header.
//
// For Kubernetes requests (detected by X-Forwarded-K8s-Groups header), the
// agent sets Impersonate-User/Group headers and authenticates with its own
// ServiceAccount token.
func (rm *RelayManager) forwardRequest(req *http.Request) *http.Response {
	// Extract target from X-Bamf-Target header (set by API proxy)
	targetURL := req.Header.Get("X-Bamf-Target")
	req.Header.Del("X-Bamf-Target")
	req.Header.Del("X-Bamf-Resource")

	if targetURL == "" {
		return errorResponse(req, http.StatusBadGateway, "missing X-Bamf-Target header")
	}

	// Detect K8s request by presence of X-Forwarded-K8s-Groups
	k8sGroups := req.Header.Get("X-Forwarded-K8s-Groups")
	userEmail := req.Header.Get("X-Forwarded-Email")
	isK8sRequest := k8sGroups != ""

	// Parse the target URL and construct the full URL
	parsed, err := url.Parse(targetURL)
	if err != nil {
		return errorResponse(req, http.StatusBadGateway, "invalid X-Bamf-Target: "+err.Error())
	}

	// Build the outgoing request URL
	outURL := *parsed
	outURL.Path = req.URL.Path
	outURL.RawQuery = req.URL.RawQuery

	// Create the outbound request
	outReq, err := http.NewRequest(req.Method, outURL.String(), req.Body)
	if err != nil {
		return errorResponse(req, http.StatusBadGateway, "failed to create request: "+err.Error())
	}

	// Copy headers (already rewritten by API proxy)
	outReq.Header = req.Header.Clone()
	outReq.Host = parsed.Host
	outReq.ContentLength = req.ContentLength

	// Always strip Impersonate-* headers — prevent injection from clients
	for key := range outReq.Header {
		if strings.HasPrefix(strings.ToLower(key), "impersonate-") {
			outReq.Header.Del(key)
		}
	}

	// For K8s requests: strip forwarded headers, add impersonation + SA token
	//
	// Use transport-level timeouts instead of http.Client.Timeout.
	// Client.Timeout covers the entire request lifecycle including reading
	// the response body, which kills long-lived streaming responses (SSE)
	// after the timeout. Transport timeouts only cover connection setup and
	// waiting for response headers — the body can stream indefinitely.
	client := &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: 10 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
		},
	}
	if isK8sRequest {
		// Strip X-Forwarded-* headers — consumed for impersonation, not passed to K8s API
		outReq.Header.Del("X-Forwarded-K8s-Groups")
		outReq.Header.Del("X-Forwarded-Email")
		outReq.Header.Del("X-Forwarded-User")
		outReq.Header.Del("X-Forwarded-Roles")
		outReq.Header.Del("X-Forwarded-Groups")
		outReq.Header.Del("X-Forwarded-Host")
		outReq.Header.Del("X-Forwarded-Proto")
		outReq.Header.Del("X-Forwarded-For")

		if userEmail == "" {
			return errorResponse(req, http.StatusForbidden, "missing X-Forwarded-Email for K8s request")
		}

		// Set impersonation headers
		outReq.Header.Set("Impersonate-User", userEmail)
		for _, group := range strings.Split(k8sGroups, ",") {
			group = strings.TrimSpace(group)
			if group != "" {
				outReq.Header.Add("Impersonate-Group", group)
			}
		}

		// Authenticate with SA token
		saToken, err := readSAToken()
		if err != nil {
			rm.logger.Error("failed to read SA token", "error", err)
			return errorResponse(req, http.StatusBadGateway, "agent SA token unavailable")
		}
		outReq.Header.Set("Authorization", "Bearer "+saToken)

		// Use K8s-aware HTTP client with cluster CA
		k8sClient, err := rm.getK8sClient()
		if err != nil {
			rm.logger.Error("failed to create K8s client", "error", err)
			return errorResponse(req, http.StatusBadGateway, "agent K8s client error: "+err.Error())
		}
		client = k8sClient
	}

	// Forward to target
	resp, err := client.Do(outReq)
	if err != nil {
		rm.logger.Error("relay forward error",
			"target", outURL.String(),
			"error", err,
		)
		return errorResponse(req, http.StatusBadGateway, "target error: "+err.Error())
	}

	return resp
}

// K8s ServiceAccount paths
const (
	saTokenPath  = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	saCACertPath = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// readSAToken reads the projected ServiceAccount token. The token is
// auto-refreshed by kubelet, so we read it fresh each time.
func readSAToken() (string, error) {
	data, err := os.ReadFile(saTokenPath)
	if err != nil {
		return "", fmt.Errorf("read SA token: %w", err)
	}
	return strings.TrimSpace(string(data)), nil
}

// getK8sClient returns an HTTP client configured with the in-cluster CA
// for connecting to the Kubernetes API server.
func (rm *RelayManager) getK8sClient() (*http.Client, error) {
	caCert, err := os.ReadFile(saCACertPath)
	if err != nil {
		return nil, fmt.Errorf("read K8s CA cert: %w", err)
	}

	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCert) {
		return nil, fmt.Errorf("failed to parse K8s CA cert")
	}

	return &http.Client{
		Transport: &http.Transport{
			DialContext: (&net.Dialer{
				Timeout: 10 * time.Second,
			}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			TLSClientConfig: &tls.Config{
				RootCAs:    caCertPool,
				MinVersion: tls.VersionTLS13,
			},
		},
	}, nil
}

// errorResponse creates an HTTP error response for sending back over the relay.
func errorResponse(req *http.Request, status int, msg string) *http.Response {
	body := io.NopCloser(strings.NewReader(msg))
	return &http.Response{
		StatusCode:    status,
		Status:        fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": {"text/plain"}},
		Body:          body,
		ContentLength: int64(len(msg)),
		Request:       req,
	}
}

// Close shuts down the relay manager and closes all connections.
func (rm *RelayManager) Close() {
	rm.closeAll()
	rm.logger.Info("relay manager stopped")
}

// UpdateResources updates the resource list (called when agent config changes).
func (rm *RelayManager) UpdateResources(resources []ResourceConfig) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.resources = resources
}

// UpdateTLSConfig updates the TLS config (called when relay_connect provides a fresh CA).
func (rm *RelayManager) UpdateTLSConfig(cfg *tls.Config) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	rm.tlsConfig = cfg
}

// IsConnected returns true if the relay has any active connections.
func (rm *RelayManager) IsConnected() bool {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	return len(rm.workers) > 0
}
