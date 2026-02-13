package bridge

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/mattrobinsonsre/bamf/pkg/apiclient"
)

// APIClient communicates with the BAMF API server for bridge operations.
//
// Contract: these methods correspond to Python API endpoints in
// services/bamf/api/routers/internal_bridges.py. Changes to request/response
// shapes must be coordinated between Go and Python.
type APIClient struct {
	Client *apiclient.Client
}

// NewAPIClient creates a new bridge API client.
func NewAPIClient(baseURL string, logger *slog.Logger) *APIClient {
	return &APIClient{
		Client: apiclient.New(apiclient.Config{
			BaseURL:   baseURL,
			Timeout:   10 * time.Second,
			UserAgent: "bamf-bridge/dev",
			Logger:    logger,
		}),
	}
}

// BootstrapResponse contains the certificate material from bootstrap.
type BootstrapResponse struct {
	Certificate   string `json:"certificate"`
	PrivateKey    string `json:"private_key"`
	CACertificate string `json:"ca_certificate"`
	ExpiresAt     string `json:"expires_at"`
}

// Bootstrap requests a certificate for this bridge.
// Called on first startup before the bridge has a certificate.
// Calls: POST /api/v1/internal/bridges/bootstrap
func (c *APIClient) Bootstrap(ctx context.Context, bridgeID, hostname, bootstrapToken string) (*BootstrapResponse, error) {
	body := map[string]any{
		"bridge_id":       bridgeID,
		"hostname":        hostname,
		"bootstrap_token": bootstrapToken,
	}

	var resp BootstrapResponse
	if err := c.Client.Post(ctx, "/api/v1/internal/bridges/bootstrap", body, &resp); err != nil {
		return nil, err
	}

	return &resp, nil
}

// RegisterBridge registers this bridge with the API server.
// Calls: POST /api/v1/internal/bridges/register
func (c *APIClient) RegisterBridge(ctx context.Context, bridgeID, hostname string) error {
	body := map[string]any{
		"bridge_id": bridgeID,
		"hostname":  hostname,
	}

	return c.Client.Post(ctx, "/api/v1/internal/bridges/register", body, nil)
}

// UpdateBridgeStatus updates the bridge status.
// Calls: POST /api/v1/internal/bridges/{id}/status
func (c *APIClient) UpdateBridgeStatus(ctx context.Context, bridgeID, status string) error {
	body := map[string]any{
		"status": status,
	}

	return c.Client.Post(ctx, fmt.Sprintf("/api/v1/internal/bridges/%s/status", bridgeID), body, nil)
}

// SendHeartbeat sends a heartbeat to the API server.
// Calls: POST /api/v1/internal/bridges/{id}/heartbeat
func (c *APIClient) SendHeartbeat(ctx context.Context, bridgeID string, activeTunnels int) error {
	body := map[string]any{
		"active_tunnels": activeTunnels,
	}

	return c.Client.Post(ctx, fmt.Sprintf("/api/v1/internal/bridges/%s/heartbeat", bridgeID), body, nil)
}

// ValidateSessionResponse contains the API response for session validation.
type ValidateSessionResponse struct {
	Token        string `json:"token"`
	UserID       string `json:"user_id"`
	UserEmail    string `json:"user_email"`
	ResourceID   string `json:"resource_id"`
	ResourceName string `json:"resource_name"`
	AgentID      string `json:"agent_id"`
	Protocol     string `json:"protocol"`
	ExpiresAt    string `json:"expires_at"`
}

// ValidateSession validates a session token with the API server.
// Calls: POST /api/v1/internal/sessions/validate
func (c *APIClient) ValidateSession(ctx context.Context, token string) (*ValidateSessionResponse, error) {
	body := map[string]any{
		"session_token": token,
	}

	var session ValidateSessionResponse
	if err := c.Client.Post(ctx, "/api/v1/internal/sessions/validate", body, &session); err != nil {
		return nil, err
	}

	return &session, nil
}

// GetAgentConnection requests the API to establish agent connection.
// Calls: POST /api/v1/internal/tunnels/establish
func (c *APIClient) GetAgentConnection(ctx context.Context, sessionToken, agentID string) (*AgentConnectionInfo, error) {
	body := map[string]any{
		"session_token": sessionToken,
		"agent_id":      agentID,
	}

	var info AgentConnectionInfo
	if err := c.Client.Post(ctx, "/api/v1/internal/tunnels/establish", body, &info); err != nil {
		return nil, err
	}

	return &info, nil
}

// NotifyTunnelEstablished notifies the API that a tunnel has been established.
// Calls: POST /api/v1/internal/tunnels/established
func (c *APIClient) NotifyTunnelEstablished(ctx context.Context, sessionToken, tunnelID string) error {
	body := map[string]any{
		"session_token": sessionToken,
		"tunnel_id":     tunnelID,
	}

	return c.Client.Post(ctx, "/api/v1/internal/tunnels/established", body, nil)
}

// NotifyTunnelClosed notifies the API that a tunnel has been closed.
// Calls: POST /api/v1/internal/tunnels/closed
func (c *APIClient) NotifyTunnelClosed(ctx context.Context, tunnelID string, bytesSent, bytesRecv int64) error {
	body := map[string]any{
		"tunnel_id":      tunnelID,
		"bytes_sent":     bytesSent,
		"bytes_received": bytesRecv,
	}

	return c.Client.Post(ctx, "/api/v1/internal/tunnels/closed", body, nil)
}

// AgentConnectionInfo contains information for establishing agent connection.
// Matches Python TunnelEstablishResponse in services/bamf/api/models/bridges.py.
type AgentConnectionInfo struct {
	AgentID      string `json:"agent_id"`
	AgentName    string `json:"agent_name"`
	ResourceID   string `json:"resource_id"`
	ResourceName string `json:"resource_name"`
	ResourceType string `json:"resource_type"`
	TargetHost   string `json:"target_host"`
	TargetPort   int    `json:"target_port"`
	TunnelToken  string `json:"tunnel_token"`
}
