package agent

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"
)

// Agent represents a BAMF agent
type Agent struct {
	cfg    *Config
	logger *slog.Logger

	// State
	registered    bool
	agentID       string
	certNotBefore time.Time
	certExpiry    time.Time

	// Certificate storage
	certStore CertStore

	// Connections
	apiClient *APIClient
	sseClient *SSEClient
	tlsConfig *tls.Config

	// Active tunnels
	tunnels   map[string]*TunnelHandler
	tunnelsMu sync.RWMutex

	// HTTP relay
	relay *RelayManager

	// Shutdown
	shutdownOnce sync.Once
	shutdownCh   chan struct{}
}

// New creates a new agent
func New(cfg *Config, logger *slog.Logger) (*Agent, error) {
	a := &Agent{
		cfg:        cfg,
		logger:     logger,
		tunnels:    make(map[string]*TunnelHandler),
		shutdownCh: make(chan struct{}),
	}

	// Ensure data directory exists
	if err := os.MkdirAll(cfg.DataDir, 0700); err != nil {
		return nil, fmt.Errorf("failed to create data directory: %w", err)
	}

	// Initialize certificate store based on environment
	if IsRunningInKubernetes() {
		namespace := GetNamespace()
		secretName := os.Getenv("BAMF_CERT_SECRET_NAME")
		if secretName == "" {
			secretName = "bamf-agent-certs"
		}
		store, err := NewK8sSecretCertStore(namespace, secretName, cfg.DataDir)
		if err != nil {
			return nil, fmt.Errorf("failed to create K8s cert store: %w", err)
		}
		a.certStore = store
		logger.Info("using Kubernetes Secret for certificate storage",
			"namespace", namespace,
			"secret", secretName,
		)
	} else {
		a.certStore = NewFileCertStore(cfg.DataDir)
		logger.Info("using filesystem for certificate storage",
			"data_dir", cfg.DataDir,
		)
	}

	// Initialize API client
	a.apiClient = NewAPIClient(cfg.APIServerURL, logger)

	return a, nil
}

// Run starts the agent
func (a *Agent) Run(ctx context.Context) error {
	// Check if we have existing certificates
	if !a.hasCertificates(ctx) {
		// Need to join the cluster
		if a.cfg.JoinToken == "" {
			return fmt.Errorf("no certificates found and no join token provided")
		}
		if err := a.join(ctx); err != nil {
			return fmt.Errorf("failed to join cluster: %w", err)
		}
	}

	// Load certificates
	if err := a.loadCertificates(ctx); err != nil {
		return fmt.Errorf("failed to load certificates: %w", err)
	}

	// Check if certificate needs renewal (e.g., VM was suspended for a while)
	if _, err := a.checkAndRenewCertificate(ctx); err != nil {
		// Log but don't fail startup - cert might still be valid
		a.logger.Warn("certificate renewal check failed", "error", err)
	}

	a.registered = true

	// Send initial heartbeat to register resources immediately
	if err := a.sendHeartbeat(ctx); err != nil {
		a.logger.Warn("initial heartbeat failed", "error", err)
	}

	// Start main loop
	return a.mainLoop(ctx)
}

// Shutdown gracefully shuts down the agent
func (a *Agent) Shutdown(ctx context.Context) error {
	a.shutdownOnce.Do(func() {
		close(a.shutdownCh)
	})

	a.logger.Info("shutting down agent")

	// Close relay connection
	if a.relay != nil {
		a.relay.Close()
	}

	// Close all tunnels
	a.tunnelsMu.Lock()
	for id, t := range a.tunnels {
		t.Close()
		delete(a.tunnels, id)
	}
	a.tunnelsMu.Unlock()

	// Notify API server
	if a.registered {
		_ = a.apiClient.UpdateStatus(ctx, a.agentID, "offline")
	}

	return nil
}

func (a *Agent) hasCertificates(ctx context.Context) bool {
	return a.certStore.HasCertificates(ctx)
}

func (a *Agent) join(ctx context.Context) error {
	a.logger.Info("joining cluster", "token_prefix", a.cfg.JoinToken[:8]+"...")

	// Request certificate from API using join token
	cert, key, ca, agentID, err := a.apiClient.Join(ctx, a.cfg.JoinToken, a.cfg.AgentName, a.cfg.Labels)
	if err != nil {
		return err
	}

	// Save certificates to store (filesystem or K8s Secret)
	if err := a.certStore.SaveCertificates(ctx, cert, key, ca); err != nil {
		return fmt.Errorf("failed to save certificates: %w", err)
	}

	a.agentID = agentID
	a.logger.Info("joined cluster successfully", "agent_id", agentID)

	return nil
}

func (a *Agent) loadCertificates(ctx context.Context) error {
	// Load certificates from store (also writes to local cache for K8s case)
	certPEM, _, caCert, err := a.certStore.LoadCertificates(ctx)
	if err != nil {
		return fmt.Errorf("failed to load certificates from store: %w", err)
	}

	// Load TLS certificate from files (certStore ensures files exist)
	cert, err := tls.LoadX509KeyPair(a.certStore.CertFile(), a.certStore.KeyFile())
	if err != nil {
		return fmt.Errorf("failed to load certificate: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return fmt.Errorf("failed to parse CA certificate")
	}

	// Extract agent ID and validity period from certificate
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}
	a.agentID = x509Cert.Subject.CommonName
	a.certNotBefore = x509Cert.NotBefore
	a.certExpiry = x509Cert.NotAfter

	a.tlsConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS12,
	}

	// Set cert on API client for X-Bamf-Client-Cert header auth
	a.apiClient.Client.SetClientCert(certPEM)

	a.logger.Info("loaded certificates",
		"agent_id", a.agentID,
		"expires_at", a.certExpiry.Format(time.RFC3339),
		"expires_in", time.Until(a.certExpiry).Round(time.Hour),
	)
	return nil
}

// sendHeartbeat sends a single heartbeat with current resources and labels.
func (a *Agent) sendHeartbeat(ctx context.Context) error {
	return a.apiClient.Heartbeat(ctx, a.agentID, a.cfg.Resources, a.cfg.Labels, a.cfg.ClusterInternal)
}

// checkAndRenewCertificate checks if the certificate is past its halfway point and renews it.
// Returns true if the certificate was renewed.
func (a *Agent) checkAndRenewCertificate(ctx context.Context) (bool, error) {
	now := time.Now()

	// If cert is already expired, we can't renew (need a new join token)
	if now.After(a.certExpiry) {
		return false, fmt.Errorf("certificate has expired; re-registration with a new join token is required")
	}

	// Calculate the halfway point of the certificate's validity period
	totalValidity := a.certExpiry.Sub(a.certNotBefore)
	halfwayPoint := a.certNotBefore.Add(totalValidity / 2)

	// If we haven't reached the halfway point, no renewal needed
	if now.Before(halfwayPoint) {
		a.logger.Debug("certificate renewal not needed",
			"expires_in", time.Until(a.certExpiry).Round(time.Hour),
			"renews_at", halfwayPoint.Format(time.RFC3339),
			"renews_in", time.Until(halfwayPoint).Round(time.Hour),
		)
		return false, nil
	}

	a.logger.Info("certificate past halfway point, requesting renewal",
		"expires_in", time.Until(a.certExpiry).Round(time.Hour),
		"validity_period", totalValidity.Round(time.Hour),
	)

	// Request new certificate using current cert for authentication
	cert, key, expiresAt, err := a.apiClient.RenewCertificate(ctx, a.agentID)
	if err != nil {
		return false, fmt.Errorf("failed to renew certificate: %w", err)
	}

	// Load existing CA from store (renewal only replaces cert+key, not CA)
	_, _, ca, err := a.certStore.LoadCertificates(ctx)
	if err != nil {
		return false, fmt.Errorf("failed to load CA for renewal: %w", err)
	}

	// Save new certificate and key (with existing CA)
	if err := a.certStore.SaveCertificates(ctx, cert, key, ca); err != nil {
		return false, fmt.Errorf("failed to save renewed certificates: %w", err)
	}

	a.certExpiry = expiresAt
	a.logger.Info("certificate renewed successfully",
		"new_expiry", expiresAt.Format(time.RFC3339),
		"expires_in", time.Until(expiresAt).Round(time.Hour),
	)

	// Reload certificates to update TLS config and API client
	if err := a.loadCertificates(ctx); err != nil {
		return true, fmt.Errorf("certificate renewed but failed to reload: %w", err)
	}

	return true, nil
}

func (a *Agent) mainLoop(ctx context.Context) error {
	// Start heartbeat ticker
	go a.heartbeatLoop(ctx)

	// Connect to API via SSE for tunnel requests.
	// The SSE client handles reconnection internally.
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-a.shutdownCh:
			return nil
		default:
		}

		if err := a.connectSSE(ctx); err != nil {
			a.logger.Error("SSE connection error", "error", err)
		}

		// Reconnect with backoff
		delay := a.calculateBackoff()
		a.logger.Info("reconnecting SSE", "delay", delay)

		select {
		case <-ctx.Done():
			return nil
		case <-a.shutdownCh:
			return nil
		case <-time.After(delay):
		}
	}
}

func (a *Agent) connectSSE(ctx context.Context) error {
	a.logger.Debug("connecting to API via SSE")

	a.sseClient = NewSSEClient(a.apiClient.Client, a.agentID, a.logger)

	eventCh, err := a.sseClient.Connect(ctx)
	if err != nil {
		return err
	}

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-a.shutdownCh:
			return nil
		case event, ok := <-eventCh:
			if !ok {
				return fmt.Errorf("SSE connection closed")
			}
			a.handleEvent(ctx, event)
		}
	}
}

func (a *Agent) handleEvent(ctx context.Context, event SSEEvent) {
	switch event.Type {
	case "tunnel_request":
		go a.handleTunnelRequest(ctx, event.Data)
	case "relay_connect":
		go a.handleRelayConnect(event.Data)
	case "heartbeat":
		// API keepalive, no action needed
	case "revoke":
		// Agent has been deleted by administrator
		reason, _ := event.Data["reason"].(string)
		a.logger.Error("agent certificate revoked by administrator",
			"reason", reason,
		)
		// Trigger graceful shutdown
		a.shutdownOnce.Do(func() {
			close(a.shutdownCh)
		})
	default:
		a.logger.Warn("unknown event type", "type", event.Type)
	}
}

// handleRelayConnect establishes a persistent relay connection to a bridge
// for HTTP proxy traffic. Called when the API assigns a bridge for relay.
func (a *Agent) handleRelayConnect(data map[string]interface{}) {
	bridgeHost, _ := data["bridge_host"].(string)
	bridgePort, _ := data["bridge_port"].(float64)
	caCertPEM, _ := data["ca_certificate"].(string)

	if bridgeHost == "" || bridgePort == 0 {
		a.logger.Error("relay_connect: missing bridge_host or bridge_port")
		return
	}

	a.logger.Info("received relay_connect command",
		"bridge", fmt.Sprintf("%s:%.0f", bridgeHost, bridgePort),
	)

	// Build TLS config using the CA cert from the event (always current)
	// rather than a.tlsConfig which may have a stale CA from initial join.
	tlsCfg := a.tlsConfig
	if caCertPEM != "" {
		caPool := x509.NewCertPool()
		if caPool.AppendCertsFromPEM([]byte(caCertPEM)) {
			tlsCfg = a.tlsConfig.Clone()
			tlsCfg.RootCAs = caPool
		} else {
			a.logger.Warn("relay_connect: failed to parse CA cert from event, using stored CA")
		}
	}

	// Create or reuse relay manager
	if a.relay == nil {
		a.relay = NewRelayManager(a.agentID, a.cfg.Resources, tlsCfg, a.logger)
	} else {
		a.relay.UpdateResources(a.cfg.Resources)
		a.relay.UpdateTLSConfig(tlsCfg)
	}

	if err := a.relay.Connect(bridgeHost, int(bridgePort)); err != nil {
		a.logger.Error("relay connection failed", "error", err)
	}
}

func (a *Agent) handleTunnelRequest(ctx context.Context, data map[string]interface{}) {
	command, _ := data["command"].(string)
	sessionID, _ := data["session_id"].(string)
	bridgeHost, _ := data["bridge_host"].(string)
	bridgePort, _ := data["bridge_port"].(float64)
	resourceName, _ := data["resource_name"].(string)
	sessionCert, _ := data["session_cert"].(string)
	sessionKey, _ := data["session_key"].(string)
	caCert, _ := data["ca_certificate"].(string)

	a.logger.Info("received tunnel request",
		"command", command,
		"resource", resourceName,
		"bridge", fmt.Sprintf("%s:%.0f", bridgeHost, bridgePort),
	)

	// Validate required fields
	if sessionCert == "" || sessionKey == "" || caCert == "" {
		a.logger.Error("missing session certificate in tunnel command",
			"has_cert", sessionCert != "",
			"has_key", sessionKey != "",
			"has_ca", caCert != "",
		)
		return
	}

	if command == "redial" {
		a.handleRedial(sessionID, bridgeHost, int(bridgePort),
			[]byte(sessionCert), []byte(sessionKey), []byte(caCert))
		return
	}

	// command == "dial" (or empty for backwards compatibility): new tunnel.

	// Find resource
	var resource *ResourceConfig
	for i := range a.cfg.Resources {
		if a.cfg.Resources[i].Name == resourceName {
			resource = &a.cfg.Resources[i]
			break
		}
	}

	if resource == nil {
		a.logger.Error("resource not found", "name", resourceName)
		return
	}

	// Use the resource_type from the SSE event for the bridge header.
	// This may differ from the resource's native type — e.g., "web-ssh"
	// instead of "ssh" for web terminal sessions.
	protocolType, _ := data["resource_type"].(string)
	if protocolType == "" {
		protocolType = resource.ResourceType
	}

	// Create tunnel handler with session certificate
	handler, err := NewTunnelHandler(
		sessionID,
		bridgeHost,
		int(bridgePort),
		resource,
		protocolType,
		[]byte(sessionCert),
		[]byte(sessionKey),
		[]byte(caCert),
		a.logger,
	)
	if err != nil {
		a.logger.Error("failed to create tunnel handler", "error", err)
		return
	}

	// Store tunnel
	a.tunnelsMu.Lock()
	a.tunnels[sessionID] = handler
	a.tunnelsMu.Unlock()

	// Run tunnel (blocks until tunnel closes or reconnects finish)
	if err := handler.Run(ctx); err != nil {
		a.logger.Error("tunnel error", "error", err, "resource", resourceName)
	}

	// Remove tunnel
	a.tunnelsMu.Lock()
	delete(a.tunnels, sessionID)
	a.tunnelsMu.Unlock()
}

// handleRedial reconnects an existing tunnel through a new bridge.
// Called when the API sends a "redial" command after a bridge dies.
func (a *Agent) handleRedial(
	sessionID string,
	bridgeHost string,
	bridgePort int,
	sessionCertPEM []byte,
	sessionKeyPEM []byte,
	caCertPEM []byte,
) {
	a.tunnelsMu.RLock()
	handler, ok := a.tunnels[sessionID]
	a.tunnelsMu.RUnlock()

	if !ok {
		a.logger.Warn("redial: tunnel not found, ignoring",
			"session_id", sessionID,
		)
		return
	}

	if handler.IsClosed() {
		a.logger.Warn("redial: tunnel already closed, ignoring",
			"session_id", sessionID,
		)
		return
	}

	if err := handler.ReconnectBridge(bridgeHost, bridgePort, sessionCertPEM, sessionKeyPEM, caCertPEM); err != nil {
		a.logger.Error("redial: bridge reconnection failed",
			"session_id", sessionID,
			"error", err,
		)
		return
	}

	a.logger.Info("redial: bridge reconnected successfully",
		"session_id", sessionID,
		"new_bridge", fmt.Sprintf("%s:%d", bridgeHost, bridgePort),
	)
}

func (a *Agent) heartbeatLoop(ctx context.Context) {
	ticker := time.NewTicker(a.cfg.HeartbeatInterval)
	defer ticker.Stop()

	// Check certificate renewal once per day (not on every heartbeat)
	renewalCheckInterval := 24 * time.Hour
	lastRenewalCheck := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.shutdownCh:
			return
		case <-ticker.C:
			if err := a.sendHeartbeat(ctx); err != nil {
				a.logger.Warn("heartbeat failed", "error", err)
			}

			// Periodic certificate renewal check (once per day)
			if time.Since(lastRenewalCheck) >= renewalCheckInterval {
				lastRenewalCheck = time.Now()
				if _, err := a.checkAndRenewCertificate(ctx); err != nil {
					a.logger.Warn("periodic certificate renewal check failed", "error", err)
				}
			}
		}
	}
}

func (a *Agent) calculateBackoff() time.Duration {
	// Simple backoff with jitter. The SSE client will get proper
	// exponential backoff in Task 2; this is a fallback for the
	// outer reconnection loop.
	baseDelay := a.cfg.ReconnectBaseDelay
	maxDelay := a.cfg.ReconnectMaxDelay
	jitterRatio := a.cfg.ReconnectJitterRatio

	jitter := time.Duration(float64(baseDelay) * jitterRatio)
	delay := baseDelay + jitter

	if delay > maxDelay {
		delay = maxDelay
	}

	return delay
}
