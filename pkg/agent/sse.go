package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"

	"github.com/mattrobinsonsre/bamf/pkg/apiclient"
)

// SSEEvent represents a server-sent event received from the API.
//
// Contract: the API endpoint GET /api/v1/agents/{id}/events
// (services/bamf/api/routers/agents.py:agent_events) sends two event types:
//
//	event: tunnel_request
//	data: {"command":"dial","session_id":"...","bridge_host":"...","bridge_port":3022,"resource_name":"...","resource_type":"ssh"}
//
//	event: heartbeat
//	data: {}
type SSEEvent struct {
	Type string
	Data map[string]interface{}
}

// SSEConfig holds reconnection parameters for the SSE client.
type SSEConfig struct {
	BaseDelay   time.Duration // Initial reconnect delay (default 1s)
	MaxDelay    time.Duration // Maximum reconnect delay (default 5m)
	JitterRatio float64       // Random jitter as ratio of delay (default 0.2)
}

// DefaultSSEConfig returns sensible defaults for SSE reconnection.
func DefaultSSEConfig() SSEConfig {
	return SSEConfig{
		BaseDelay:   1 * time.Second,
		MaxDelay:    5 * time.Minute,
		JitterRatio: 0.2,
	}
}

// SSEClient handles Server-Sent Events connection to the BAMF API.
// It uses the shared apiclient.Client for auth headers and TLS config.
type SSEClient struct {
	client  *apiclient.Client
	agentID string
	logger  *slog.Logger
	cfg     SSEConfig

	// httpClient is a dedicated HTTP client for SSE with no timeout
	// (SSE connections are long-lived).
	httpClient *http.Client
}

// NewSSEClient creates a new SSE client.
//
// The apiclient.Client is used for:
//   - BaseURL() — API server address
//   - UserAgentString() — User-Agent header
//   - CertHeader() — X-Bamf-Client-Cert header for auth
//   - HTTPClient().Transport — TLS configuration (reused without timeout)
func NewSSEClient(client *apiclient.Client, agentID string, logger *slog.Logger) *SSEClient {
	// Create a dedicated HTTP client for SSE: same TLS transport, no timeout.
	var transport http.RoundTripper
	if t := client.HTTPClient().Transport; t != nil {
		transport = t
	} else {
		transport = http.DefaultTransport
	}

	return &SSEClient{
		client:  client,
		agentID: agentID,
		logger:  logger,
		cfg:     DefaultSSEConfig(),
		httpClient: &http.Client{
			Transport: transport,
			// No Timeout — SSE connections are long-lived.
		},
	}
}

// Connect establishes a single SSE connection and returns an event channel.
// The channel is closed when the connection drops or the context is cancelled.
// Callers should use ConnectWithReconnect for automatic reconnection.
func (c *SSEClient) Connect(ctx context.Context) (<-chan SSEEvent, error) {
	url := fmt.Sprintf("%s/api/v1/agents/%s/events", c.client.BaseURL(), c.agentID)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("sse: create request: %w", err)
	}

	// SSE headers
	req.Header.Set("Accept", "text/event-stream")
	req.Header.Set("Cache-Control", "no-cache")

	// Auth headers — same as all API calls
	if ua := c.client.UserAgentString(); ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	if cert := c.client.CertHeader(); cert != "" {
		req.Header.Set("X-Bamf-Client-Cert", cert)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sse: connect failed: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("sse: unexpected status: %s", resp.Status)
	}

	eventCh := make(chan SSEEvent, 10)

	go func() {
		defer resp.Body.Close()
		defer close(eventCh)

		scanner := bufio.NewScanner(resp.Body)
		var eventType string
		var dataLines []string

		for scanner.Scan() {
			line := scanner.Text()

			if line == "" {
				// Empty line = end of event
				if eventType != "" && len(dataLines) > 0 {
					data := strings.Join(dataLines, "\n")
					var parsed map[string]interface{}
					if err := json.Unmarshal([]byte(data), &parsed); err != nil {
						c.logger.Warn("failed to parse SSE data", "error", err, "data", data)
					} else {
						select {
						case eventCh <- SSEEvent{Type: eventType, Data: parsed}:
						case <-ctx.Done():
							return
						}
					}
				}
				eventType = ""
				dataLines = nil
				continue
			}

			if strings.HasPrefix(line, "event:") {
				eventType = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
			} else if strings.HasPrefix(line, "data:") {
				// Trim "data:" prefix and the optional leading space per SSE spec
				dataLines = append(dataLines, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
			}
		}

		if err := scanner.Err(); err != nil {
			c.logger.Error("SSE scanner error", "error", err)
		}
	}()

	return eventCh, nil
}

// backoff calculates the delay for a given attempt using exponential backoff
// with jitter: min(baseDelay * 2^attempt, maxDelay) + random jitter.
func (c *SSEClient) backoff(attempt int) time.Duration {
	delay := float64(c.cfg.BaseDelay) * math.Pow(2, float64(attempt))
	if delay > float64(c.cfg.MaxDelay) {
		delay = float64(c.cfg.MaxDelay)
	}

	// Add random jitter
	jitter := delay * c.cfg.JitterRatio * rand.Float64()
	return time.Duration(delay + jitter)
}
