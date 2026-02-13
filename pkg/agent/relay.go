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

		// Forward to target and write response.
		// Read the full body so we can set Content-Length for proper relay
		// framing.  Target servers may use HTTP/1.0 with body-terminated-by-
		// close, which doesn't work on a persistent relay connection.
		resp := rm.forwardRequest(req)
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

	// Strip forwarded/bamf headers — never pass them to the target
	req.Header.Del("X-Forwarded-K8s-Groups")
	req.Header.Del("X-Forwarded-Email")
	req.Header.Del("X-Forwarded-User")
	req.Header.Del("X-Forwarded-Roles")
	req.Header.Del("X-Forwarded-Host")
	req.Header.Del("X-Forwarded-Proto")
	req.Header.Del("X-Forwarded-For")

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

	// For K8s requests: add impersonation headers and SA token auth
	client := &http.Client{Timeout: 30 * time.Second}
	if isK8sRequest {
		if userEmail == "" {
			return errorResponse(req, http.StatusForbidden, "missing X-Forwarded-Email for K8s request")
		}

		// Strip any existing Impersonate-* headers (prevent injection)
		for key := range outReq.Header {
			if strings.HasPrefix(strings.ToLower(key), "impersonate-") {
				outReq.Header.Del(key)
			}
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

