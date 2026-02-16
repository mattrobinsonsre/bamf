package bridge

// Architecture: docs/architecture/overview.md

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Server is the main bridge server
type Server struct {
	cfg    *Config
	logger *slog.Logger

	// Listeners
	httpsListener  net.Listener
	healthListener net.Listener
	tunnelListener net.Listener

	// Servers
	httpServer   *http.Server
	healthServer *http.Server

	// TLS configuration
	tlsConfig  *tls.Config
	mtlsConfig *tls.Config // For tunnel connections (mTLS with session certs)
	certPEM    []byte      // PEM cert for API authentication

	// Session management
	tunnels      *TunnelManager
	relays       *RelayPool
	apiClient    *APIClient

	// Pending connections waiting for match (keyed by session ID)
	pendingConns   map[string]*pendingConnection
	pendingConnsMu sync.Mutex

	// Shutdown coordination
	shutdownOnce sync.Once
	shutdownCh   chan struct{}
}

// pendingConnection holds a connection waiting for its match
type pendingConnection struct {
	conn       net.Conn
	sessionID  string
	isClient   bool // true = CLI client, false = agent
	resource   string
	receivedAt time.Time
	matchCh    chan net.Conn // receives the matched connection
}

// NewServer creates a new bridge server
func NewServer(cfg *Config, logger *slog.Logger) (*Server, error) {
	s := &Server{
		cfg:        cfg,
		logger:     logger,
		shutdownCh: make(chan struct{}),
	}

	// Bootstrap certificates if they don't exist
	if err := s.bootstrapIfNeeded(); err != nil {
		return nil, fmt.Errorf("failed to bootstrap: %w", err)
	}

	// Load TLS certificates
	if err := s.loadTLSConfig(); err != nil {
		return nil, fmt.Errorf("failed to load TLS config: %w", err)
	}

	// Initialize API client with certificate auth
	s.apiClient = NewAPIClient(cfg.APIServerURL, logger)
	s.apiClient.Client.SetClientCert(s.certPEM)

	// Initialize tunnel manager
	s.tunnels = NewTunnelManager(logger)

	// Initialize relay pool
	s.relays = NewRelayPool(logger)

	// Initialize pending connections map
	s.pendingConns = make(map[string]*pendingConnection)

	return s, nil
}

// bootstrapIfNeeded requests a certificate from the API if one doesn't exist
func (s *Server) bootstrapIfNeeded() error {
	// Check if certificate already exists
	if _, err := os.Stat(s.cfg.TLSCertFile); err == nil {
		s.logger.Info("certificate exists, skipping bootstrap", "cert_file", s.cfg.TLSCertFile)
		return nil
	}

	// Need to bootstrap - verify we have a token
	if s.cfg.BootstrapToken == "" {
		return fmt.Errorf("no certificate found and BAMF_BOOTSTRAP_TOKEN not set")
	}

	s.logger.Info("bootstrapping bridge certificate",
		"bridge_id", s.cfg.BridgeID,
		"hostname", s.cfg.Hostname,
		"api_url", s.cfg.APIServerURL,
	)

	// Create API client without cert auth for bootstrap
	apiClient := NewAPIClient(s.cfg.APIServerURL, s.logger)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := apiClient.Bootstrap(ctx, s.cfg.BridgeID, s.cfg.Hostname, s.cfg.BootstrapToken)
	if err != nil {
		return fmt.Errorf("bootstrap API call failed: %w", err)
	}

	// Ensure data directory exists
	if err := os.MkdirAll(s.cfg.DataDir, 0700); err != nil {
		return fmt.Errorf("failed to create data directory: %w", err)
	}

	// Write certificate
	certPath := s.cfg.TLSCertFile
	if err := os.WriteFile(certPath, []byte(resp.Certificate), 0600); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Write private key
	keyPath := s.cfg.TLSKeyFile
	if err := os.WriteFile(keyPath, []byte(resp.PrivateKey), 0600); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Write CA certificate
	caPath := s.cfg.CACertFile
	if err := os.WriteFile(caPath, []byte(resp.CACertificate), 0644); err != nil {
		return fmt.Errorf("failed to write CA certificate: %w", err)
	}

	s.logger.Info("bootstrap complete",
		"cert_file", certPath,
		"key_file", keyPath,
		"ca_file", caPath,
		"expires_at", resp.ExpiresAt,
	)

	return nil
}

func (s *Server) loadTLSConfig() error {
	// Load server certificate
	cert, err := tls.LoadX509KeyPair(s.cfg.TLSCertFile, s.cfg.TLSKeyFile)
	if err != nil {
		return fmt.Errorf("failed to load TLS certificate: %w", err)
	}

	// Load CA certificate for mTLS
	caCert, err := os.ReadFile(s.cfg.CACertFile)
	if err != nil {
		return fmt.Errorf("failed to read CA certificate: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to parse CA certificate")
	}

	// Standard TLS config (client auth optional)
	s.tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		// SNI routing callback
		GetConfigForClient: s.getConfigForClient,
	}

	// mTLS config for agent connections (client auth required)
	s.mtlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientCAs:    caPool,
		ClientAuth:   tls.RequireAndVerifyClientCert,
		MinVersion:   tls.VersionTLS12,
	}

	// Load cert PEM for API client authentication (X-Bamf-Client-Cert header)
	certPEM, err := os.ReadFile(s.cfg.TLSCertFile)
	if err != nil {
		return fmt.Errorf("failed to read certificate PEM: %w", err)
	}
	s.certPEM = certPEM

	return nil
}

// getConfigForClient handles SNI-based routing
func (s *Server) getConfigForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	// Extract session from SNI if present
	// SNI format: {session-token}.tunnel.bamf.example.com
	s.logger.Debug("TLS client hello", "server_name", hello.ServerName)
	return nil, nil // Use default config
}

// Run starts all bridge listeners
func (s *Server) Run(ctx context.Context) error {
	var err error

	// Start HTTPS listener
	s.httpsListener, err = tls.Listen("tcp", s.cfg.HTTPSAddr, s.tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to start HTTPS listener: %w", err)
	}

	// Start health listener (plain HTTP for Kubernetes probes)
	s.healthListener, err = net.Listen("tcp", s.cfg.HealthAddr)
	if err != nil {
		return fmt.Errorf("failed to start health listener: %w", err)
	}

	// Start tunnel listener (mTLS - single port for all tunnel protocols)
	s.tunnelListener, err = tls.Listen("tcp", s.cfg.TunnelAddr, s.mtlsConfig)
	if err != nil {
		return fmt.Errorf("failed to start tunnel listener: %w", err)
	}

	// Setup HTTP server
	s.httpServer = &http.Server{
		Handler: s.httpHandler(),
	}

	// Setup health server (plain HTTP for Kubernetes probes)
	s.healthServer = &http.Server{
		Handler: s.healthHandler(),
	}

	// Register with API server
	if err := s.registerWithAPI(ctx); err != nil {
		return fmt.Errorf("failed to register with API: %w", err)
	}

	// Start heartbeat
	go s.heartbeatLoop(ctx)

	// Start all handlers
	errCh := make(chan error, 5)

	go func() {
		if err := s.httpServer.Serve(s.httpsListener); err != http.ErrServerClosed {
			errCh <- fmt.Errorf("HTTPS server error: %w", err)
		}
	}()

	go func() {
		if err := s.healthServer.Serve(s.healthListener); err != http.ErrServerClosed {
			errCh <- fmt.Errorf("health server error: %w", err)
		}
	}()

	go func() {
		if err := s.serveTunnels(ctx); err != nil {
			errCh <- fmt.Errorf("tunnel server error: %w", err)
		}
	}()

	// Wait for context cancellation or error
	select {
	case <-ctx.Done():
		return nil
	case err := <-errCh:
		return err
	}
}

// Shutdown gracefully shuts down the bridge server
func (s *Server) Shutdown(ctx context.Context) error {
	s.shutdownOnce.Do(func() {
		close(s.shutdownCh)
	})

	s.logger.Info("initiating graceful shutdown")

	// Notify API server we're draining
	if err := s.notifyDraining(ctx); err != nil {
		s.logger.Warn("failed to notify API of draining", "error", err)
	}

	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(ctx, s.cfg.ShutdownTimeout)
	defer cancel()

	// Stop accepting new connections
	if s.httpsListener != nil {
		s.httpsListener.Close()
	}
	if s.healthListener != nil {
		s.healthListener.Close()
	}
	if s.tunnelListener != nil {
		s.tunnelListener.Close()
	}

	// Gracefully shutdown HTTP server
	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(shutdownCtx); err != nil {
			s.logger.Warn("HTTP server shutdown error", "error", err)
		}
	}

	// Gracefully shutdown health server
	if s.healthServer != nil {
		if err := s.healthServer.Shutdown(shutdownCtx); err != nil {
			s.logger.Warn("health server shutdown error", "error", err)
		}
	}

	// Close all relay connections
	s.relays.CloseAll()

	// Wait for all tunnels to migrate or close
	if err := s.tunnels.DrainAll(shutdownCtx); err != nil {
		s.logger.Warn("tunnel drain error", "error", err)
	}

	s.logger.Info("graceful shutdown complete")
	return nil
}

func (s *Server) httpHandler() http.Handler {
	mux := http.NewServeMux()

	// Health endpoints (also available on HTTPS for internal checks)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/ready", s.handleReady)

	return mux
}

func (s *Server) healthHandler() http.Handler {
	mux := http.NewServeMux()

	// Health endpoints for Kubernetes probes (plain HTTP)
	mux.HandleFunc("/health", s.handleHealth)
	mux.HandleFunc("/ready", s.handleReady)

	// Relay endpoint for HTTP proxy: API forwards requests here.
	// On the internal port (8080) so only reachable within the cluster.
	mux.HandleFunc("/relay/", s.relays.handleRelayRequest)

	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"healthy"}`))
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	// Check if we're draining
	select {
	case <-s.shutdownCh:
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"status":"draining"}`))
		return
	default:
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ready"}`))
}

func (s *Server) registerWithAPI(ctx context.Context) error {
	return s.apiClient.RegisterBridge(ctx, s.cfg.BridgeID, s.cfg.Hostname)
}

func (s *Server) notifyDraining(ctx context.Context) error {
	return s.apiClient.UpdateBridgeStatus(ctx, s.cfg.BridgeID, "draining")
}

func (s *Server) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.shutdownCh:
			return
		case <-ticker.C:
			if err := s.apiClient.SendHeartbeat(ctx, s.cfg.BridgeID, s.tunnels.Count()); err != nil {
				s.logger.Warn("heartbeat failed", "error", err)
			}
		}
	}
}

func (s *Server) serveTunnels(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		conn, err := s.tunnelListener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				s.logger.Error("tunnel accept error", "error", err)
				continue
			}
		}

		go s.handleTunnelConnection(ctx, conn)
	}
}

// handleTunnelConnection handles an mTLS tunnel connection.
// It validates the session cert, matches client with agent, and splices the tunnel.
// The bridge is protocol-agnostic — it never interprets the tunneled bytes.
func (s *Server) handleTunnelConnection(ctx context.Context, conn net.Conn) {
	protocol := "tunnel"
	// Connection is already TLS (listener uses mtlsConfig)
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		s.logger.Error("connection is not TLS", "protocol", protocol)
		conn.Close()
		return
	}

	// Force TLS handshake (it's lazy in Go — ConnectionState() won't trigger it)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		s.logger.Error("TLS handshake failed", "protocol", protocol, "error", err)
		conn.Close()
		return
	}

	// Get peer certificate (validated by TLS handshake)
	state := tlsConn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		s.logger.Error("no client certificate presented", "protocol", protocol)
		conn.Close()
		return
	}
	peerCert := state.PeerCertificates[0]

	// Read first line: either a session ID (tunnel) or "RELAY" (persistent HTTP relay).
	// Must happen before extractSessionInfo because relay connections use identity
	// certs (no session SANs), not session certs.
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		s.logger.Error("failed to read first line", "protocol", protocol, "error", err)
		conn.Close()
		return
	}
	firstLine := strings.TrimSpace(line)

	// Check if this is a relay connection (agent establishing persistent HTTP relay).
	if firstLine == "RELAY" {
		agentLine, err := reader.ReadString('\n')
		if err != nil {
			s.logger.Error("failed to read agent ID for relay", "error", err)
			conn.Close()
			return
		}
		agentID := strings.TrimSpace(agentLine)
		s.logger.Info("relay connection established",
			"agent_id", agentID,
			"cn", peerCert.Subject.CommonName,
		)
		s.relays.Add(agentID, conn)
		return // Connection stays open — managed by relay pool
	}

	// Standard tunnel connection: extract session info from certificate SAN URIs.
	info, err := extractSessionInfo(peerCert)
	if err != nil {
		s.logger.Error("failed to extract session info from cert", "protocol", protocol, "error", err)
		conn.Close()
		return
	}

	sessionID := info.SessionID
	resource := info.Resource

	// Verify this connection is for this bridge
	if info.BridgeID != "" && info.BridgeID != s.cfg.BridgeID {
		s.logger.Error("session cert is for different bridge",
			"protocol", protocol,
			"expected", s.cfg.BridgeID,
			"got", info.BridgeID,
		)
		conn.Close()
		return
	}

	// Standard tunnel connection: first line is session ID.
	lineSessionID := firstLine

	// Verify session ID matches cert
	if lineSessionID != sessionID {
		s.logger.Error("session ID mismatch",
			"protocol", protocol,
			"cert", sessionID,
			"line", lineSessionID,
		)
		conn.Close()
		return
	}

	// Determine if this is a client or agent from the bamf://role/ SAN URI.
	// Falls back to CN-based heuristic (email contains @) for old certs.
	isClient := info.Role == "client"
	if info.Role == "" {
		isClient = strings.Contains(peerCert.Subject.CommonName, "@")
	}

	s.logger.Debug("connection authenticated",
		"protocol", protocol,
		"session_id", sessionID[:16]+"...",
		"resource", resource,
		"role", info.Role,
		"is_client", isClient,
		"cn", peerCert.Subject.CommonName,
	)

	// Try to match with pending connection
	s.pendingConnsMu.Lock()
	pending, exists := s.pendingConns[sessionID]
	if exists && pending.isClient != isClient {
		// Found a match! Remove from pending and splice
		delete(s.pendingConns, sessionID)
		s.pendingConnsMu.Unlock()

		// Signal the waiting goroutine
		pending.matchCh <- conn

		s.logger.Info("session matched",
			"protocol", protocol,
			"session_id", sessionID[:16]+"...",
			"resource", resource,
		)
		return
	}
	s.pendingConnsMu.Unlock()

	// No match yet, store as pending and wait
	matchCh := make(chan net.Conn, 1)
	pc := &pendingConnection{
		conn:       conn,
		sessionID:  sessionID,
		isClient:   isClient,
		resource:   resource,
		receivedAt: time.Now(),
		matchCh:    matchCh,
	}

	s.pendingConnsMu.Lock()
	s.pendingConns[sessionID] = pc
	s.pendingConnsMu.Unlock()

	s.logger.Debug("connection waiting for match",
		"protocol", protocol,
		"session_id", sessionID[:16]+"...",
		"is_client", isClient,
	)

	// Wait for match or timeout
	matchTimeout := 30 * time.Second
	select {
	case <-ctx.Done():
		s.cleanupPending(sessionID)
		conn.Close()
		return
	case <-time.After(matchTimeout):
		s.logger.Warn("session match timeout",
			"protocol", protocol,
			"session_id", sessionID[:16]+"...",
			"is_client", isClient,
		)
		s.cleanupPending(sessionID)
		conn.Close()
		return
	case otherConn := <-matchCh:
		// We got a match! Create tunnel and run it
		var clientConn, agentConn net.Conn
		if isClient {
			clientConn = conn
			agentConn = otherConn
		} else {
			clientConn = otherConn
			agentConn = conn
		}

		tunnel := NewTunnel(
			sessionID,
			sessionID, // session token same as ID
			"",        // agent ID from cert if needed
			protocol,
			clientConn,
			agentConn,
		)

		s.tunnels.Add(tunnel)
		defer s.tunnels.Remove(sessionID)

		s.logger.Info("tunnel established",
			"protocol", protocol,
			"session_id", sessionID[:16]+"...",
			"resource", resource,
		)

		if err := tunnel.Run(ctx); err != nil {
			s.logger.Debug("tunnel closed", "protocol", protocol, "session_id", sessionID[:16]+"...", "error", err)
		}
	}
}

// cleanupPending removes a pending connection from the map
func (s *Server) cleanupPending(sessionID string) {
	s.pendingConnsMu.Lock()
	defer s.pendingConnsMu.Unlock()
	delete(s.pendingConns, sessionID)
}

// sessionInfo holds fields extracted from a session certificate's SAN URIs.
type sessionInfo struct {
	SessionID string
	Resource  string
	BridgeID  string
	Role      string // "client" or "agent"
}

// extractSessionInfo extracts session ID, resource name, bridge ID, and role from cert SAN URIs.
// URIs are in format: bamf://session/{id}, bamf://resource/{name}, bamf://bridge/{id}, bamf://role/{role}
// Go's url.Parse puts the authority in Host and the rest in Path:
//
//	bamf://session/abc123 → Scheme="bamf", Host="session", Path="/abc123"
func extractSessionInfo(cert *x509.Certificate) (sessionInfo, error) {
	var info sessionInfo
	for _, uri := range cert.URIs {
		if uri.Scheme != "bamf" {
			continue
		}
		value := strings.TrimPrefix(uri.Path, "/")
		if value == "" {
			continue
		}
		switch uri.Host {
		case "session":
			info.SessionID = value
		case "resource":
			info.Resource = value
		case "bridge":
			info.BridgeID = value
		case "role":
			info.Role = value
		}
	}
	if info.SessionID == "" {
		return sessionInfo{}, fmt.Errorf("no session ID in certificate SANs")
	}
	return info, nil
}

