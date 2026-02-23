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

// RelayManager maintains an mTLS connection to a bridge for relaying HTTP
// requests. The connection is established on-demand when the API sends a
// relay_connect SSE event, and closes naturally when the bridge reaps it
// after an idle timeout. No auto-reconnect — the API sends a new
// relay_connect when the next browser request needs it.
type RelayManager struct {
	agentID   string
	resources []ResourceConfig
	tlsConfig *tls.Config
	logger    *slog.Logger

	mu      sync.Mutex
	conn    net.Conn
	running bool
	stopCh  chan struct{}
	stopped chan struct{}

	// Cached bridge address for auto-reconnect after upgrade consumes a conn
	lastBridgeHost string
	lastBridgePort int
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

// Connect establishes a relay connection to the bridge. If a previous
// connection exists, it is closed first. The relay serves HTTP requests
// until the connection drops (bridge idle timeout, network error, etc.),
// then goes dormant until the next Connect() call.
func (rm *RelayManager) Connect(bridgeHost string, bridgePort int) error {
	rm.mu.Lock()
	if rm.running {
		// Close old connection and wait for serve goroutine to finish
		if rm.conn != nil {
			rm.conn.Close()
		}
		close(rm.stopCh)
		rm.mu.Unlock()
		<-rm.stopped
		rm.mu.Lock()
	}
	rm.mu.Unlock()

	conn, err := rm.dial(bridgeHost, bridgePort)
	if err != nil {
		return err
	}

	rm.mu.Lock()
	rm.conn = conn
	rm.running = true
	rm.stopCh = make(chan struct{})
	rm.stopped = make(chan struct{})
	rm.lastBridgeHost = bridgeHost
	rm.lastBridgePort = bridgePort
	go rm.serve()
	rm.mu.Unlock()

	rm.logger.Info("relay connection established",
		"bridge", fmt.Sprintf("%s:%d", bridgeHost, bridgePort),
	)
	return nil
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

// serve reads HTTP requests from the relay connection and forwards them
// to target resources. When the connection drops, it logs and returns.
// No auto-reconnect — the API sends a new relay_connect when needed.
func (rm *RelayManager) serve() {
	defer func() {
		rm.mu.Lock()
		rm.running = false
		if rm.conn != nil {
			rm.conn.Close()
			rm.conn = nil
		}
		rm.mu.Unlock()
		close(rm.stopped)
	}()

	rm.mu.Lock()
	conn := rm.conn
	rm.mu.Unlock()

	reader := bufio.NewReader(conn)

	for {
		select {
		case <-rm.stopCh:
			return
		default:
		}

		req, err := http.ReadRequest(reader)
		if err != nil {
			// Connection closed by bridge (idle timeout) or network error.
			// This is expected — just log and stop.
			rm.logger.Info("relay connection closed", "error", err)
			return
		}

		// Upgrade requests (WebSocket) — consume the relay conn for
		// bidirectional byte-splice. After the upgrade finishes, the
		// relay conn is dead and serve() returns.
		if isUpgradeRequest(req) {
			rm.logger.Info("relay handling upgrade request",
				"path", req.URL.Path,
				"upgrade", req.Header.Get("Upgrade"),
			)
			// Detach conn from the manager so Close()/Connect() won't
			// interfere while the splice is running.
			rm.mu.Lock()
			rm.conn = nil
			rm.mu.Unlock()

			// Proactively open a new relay conn for subsequent HTTP traffic
			rm.mu.Lock()
			bridgeHost := rm.lastBridgeHost
			bridgePort := rm.lastBridgePort
			rm.mu.Unlock()
			go rm.reconnect(bridgeHost, bridgePort)

			// handleUpgrade blocks until the splice ends, then closes conn
			rm.handleUpgrade(req, conn)
			return
		}

		// Check if the response should be streamed rather than buffered
		resp := rm.forwardRequest(req)

		if isStreamingResponse(resp) {
			// Streaming response (SSE, chunked without Content-Length).
			// Write the response using Go's http.Response.Write which
			// handles chunked transfer encoding automatically.
			resp.TransferEncoding = []string{"chunked"}
			resp.ContentLength = -1
			resp.Close = false
			resp.Proto = "HTTP/1.1"
			resp.ProtoMajor = 1
			resp.ProtoMinor = 1

			if err := resp.Write(conn); err != nil {
				rm.logger.Info("relay streaming write error", "error", err)
				resp.Body.Close()
				return
			}
			resp.Body.Close()
			continue
		}

		// Buffered response — read the full body so we can set
		// Content-Length for proper relay framing.
		body, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()
		if readErr != nil {
			rm.logger.Error("relay body read error", "error", readErr)
			return
		}
		resp.Body = io.NopCloser(bytes.NewReader(body))
		resp.ContentLength = int64(len(body))
		resp.TransferEncoding = nil
		resp.Close = false
		resp.Proto = "HTTP/1.1"
		resp.ProtoMajor = 1
		resp.ProtoMinor = 1

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

// isStreamingResponse returns true if the response should be streamed
// rather than fully buffered. Detected by Content-Type text/event-stream
// or chunked Transfer-Encoding with no Content-Length.
func isStreamingResponse(resp *http.Response) bool {
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.HasPrefix(ct, "text/event-stream") {
		return true
	}
	// Chunked with no known Content-Length — stream it
	if resp.ContentLength < 0 {
		for _, te := range resp.TransferEncoding {
			if strings.EqualFold(te, "chunked") {
				return true
			}
		}
	}
	return false
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
			tlsCfg = &tls.Config{RootCAs: pool}
		} else {
			tlsCfg = &tls.Config{}
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

// reconnect opens a new relay connection in the background. Used after
// an upgrade request consumes the current relay conn.
func (rm *RelayManager) reconnect(bridgeHost string, bridgePort int) {
	if bridgeHost == "" {
		return
	}
	// Brief delay to avoid racing with the bridge detaching the old conn
	time.Sleep(500 * time.Millisecond)

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
	client := &http.Client{Timeout: 30 * time.Second}
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
	saTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
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
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: caCertPool,
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

// Close shuts down the relay manager and closes the connection.
func (rm *RelayManager) Close() {
	rm.mu.Lock()
	if !rm.running {
		rm.mu.Unlock()
		return
	}
	close(rm.stopCh)
	if rm.conn != nil {
		rm.conn.Close()
	}
	rm.mu.Unlock()

	<-rm.stopped
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

