package agent

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/mattrobinsonsre/bamf/pkg/apiclient"
)

// APIClient communicates with the BAMF API server for agent operations.
//
// Contract: these methods correspond to Python API endpoints in
// services/bamf/api/routers/agents.py. Changes to request/response
// shapes must be coordinated between Go and Python.
type APIClient struct {
	Client *apiclient.Client
}

// NewAPIClient creates a new agent API client.
func NewAPIClient(baseURL string, logger *slog.Logger) *APIClient {
	return &APIClient{
		Client: apiclient.New(apiclient.Config{
			BaseURL:   baseURL,
			Timeout:   30 * time.Second,
			UserAgent: "bamf-agent/dev",
			Logger:    logger,
		}),
	}
}

// joinResponse matches the Python AgentRegisterResponse model
// (services/bamf/api/models/agents.py).
type joinResponse struct {
	AgentID              string `json:"agent_id"`
	Certificate          string `json:"certificate"`
	CertificateExpiresAt string `json:"certificate_expires_at"`
	PrivateKey           string `json:"private_key"`
	CACert               string `json:"ca_certificate"`
}

// Join registers the agent with a join token.
// Calls: POST /api/v1/agents/join
func (c *APIClient) Join(ctx context.Context, token, agentName string, labels map[string]string) (cert, key, ca []byte, agentID string, err error) {
	body := map[string]any{
		"join_token": token,
		"name":       agentName,
		"labels":     labels,
	}

	var resp joinResponse
	if err := c.Client.Post(ctx, "/api/v1/agents/join", body, &resp); err != nil {
		return nil, nil, nil, "", err
	}

	return []byte(resp.Certificate), []byte(resp.PrivateKey), []byte(resp.CACert), resp.AgentID, nil
}

// heartbeatWebhook matches the Python HeartbeatWebhook model
// (services/bamf/api/routers/agents.py).
type heartbeatWebhook struct {
	Path        string   `json:"path"`
	Methods     []string `json:"methods"`
	SourceCIDRs []string `json:"source_cidrs,omitempty"`
}

// heartbeatResource matches the Python HeartbeatResource model
// (services/bamf/api/routers/agents.py).
type heartbeatResource struct {
	Name           string              `json:"name"`
	ResourceType   string              `json:"resource_type"`
	Labels         map[string]string   `json:"labels"`
	Hostname       string              `json:"hostname,omitempty"`
	Port           int                 `json:"port,omitempty"`
	TunnelHostname string              `json:"tunnel_hostname,omitempty"`
	Webhooks       []heartbeatWebhook  `json:"webhooks,omitempty"`
}

// heartbeatRequest matches the Python AgentHeartbeatRequest model
// (services/bamf/api/routers/agents.py).
type heartbeatRequest struct {
	Resources       []heartbeatResource `json:"resources"`
	Labels          map[string]string   `json:"labels"`
	ClusterInternal bool                `json:"cluster_internal"`
	InstanceID      string              `json:"instance_id,omitempty"`
	ActiveTunnels   int                 `json:"active_tunnels"`
}

// Heartbeat sends a heartbeat to the API with the agent's current
// resources, labels, cluster_internal flag, instance identifier, and
// active tunnel count (for self-correcting Redis tunnel counts).
// Calls: POST /api/v1/agents/{id}/heartbeat
func (c *APIClient) Heartbeat(ctx context.Context, agentID string, resources []ResourceConfig, labels map[string]string, clusterInternal bool, instanceID string, activeTunnels int) error {
	hbResources := make([]heartbeatResource, len(resources))
	for i, r := range resources {
		hbResources[i] = heartbeatResource{
			Name:           r.Name,
			ResourceType:   r.ResourceType,
			Labels:         r.Labels,
			Hostname:       r.Hostname,
			Port:           r.Port,
			TunnelHostname: r.TunnelHostname,
		}
		for _, wh := range r.Webhooks {
			hbResources[i].Webhooks = append(hbResources[i].Webhooks, heartbeatWebhook(wh))
		}
	}

	body := heartbeatRequest{
		Resources:       hbResources,
		Labels:          labels,
		ClusterInternal: clusterInternal,
		InstanceID:      instanceID,
		ActiveTunnels:   activeTunnels,
	}

	return c.Client.Post(ctx, fmt.Sprintf("/api/v1/agents/%s/heartbeat", agentID), body, nil)
}

// UpdateStatus updates the agent status.
// Calls: POST /api/v1/agents/{id}/status
func (c *APIClient) UpdateStatus(ctx context.Context, agentID, status string) error {
	body := map[string]any{
		"status": status,
	}

	return c.Client.Post(ctx, fmt.Sprintf("/api/v1/agents/%s/status", agentID), body, nil)
}

// DrainInstance notifies the API that this instance is draining (shutting down).
// The API stops routing new commands to it.
// Calls: POST /api/v1/agents/{id}/drain
func (c *APIClient) DrainInstance(ctx context.Context, agentID, instanceID string) error {
	body := map[string]any{
		"instance_id": instanceID,
	}
	return c.Client.Post(ctx, fmt.Sprintf("/api/v1/agents/%s/drain", agentID), body, nil)
}

// RemoveInstance removes this instance from the agent's instances hash.
// Called after tunnels have drained and the instance is fully offline.
// Calls: POST /api/v1/agents/{id}/instance/{iid}/offline
func (c *APIClient) RemoveInstance(ctx context.Context, agentID, instanceID string) error {
	return c.Client.Post(ctx, fmt.Sprintf("/api/v1/agents/%s/instance/%s/offline", agentID, instanceID), nil, nil)
}

// RenewCertificate renews the agent's certificate before it expires.
// The agent authenticates using its current valid certificate.
// Calls: POST /api/v1/agents/{id}/renew
func (c *APIClient) RenewCertificate(ctx context.Context, agentID string) (cert, key []byte, expiresAt time.Time, err error) {
	var resp joinResponse
	if err := c.Client.Post(ctx, fmt.Sprintf("/api/v1/agents/%s/renew", agentID), nil, &resp); err != nil {
		return nil, nil, time.Time{}, err
	}

	// Parse the expiry time
	expiresAt, err = time.Parse(time.RFC3339, resp.CertificateExpiresAt)
	if err != nil {
		return nil, nil, time.Time{}, fmt.Errorf("parse certificate expiry: %w", err)
	}

	return []byte(resp.Certificate), []byte(resp.PrivateKey), expiresAt, nil
}
