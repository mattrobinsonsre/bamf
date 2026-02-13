// Package apiclient provides a shared HTTP client for communicating with
// the BAMF API server. All Go components (agent, bridge, CLI) use this
// package rather than maintaining their own HTTP plumbing.
package apiclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// Config holds options for creating a Client.
type Config struct {
	// BaseURL is the BAMF API server URL (e.g. "https://bamf.example.com").
	BaseURL string

	// Timeout for HTTP requests. Defaults to 30s if zero.
	Timeout time.Duration

	// TLSConfig is an optional TLS configuration for cert-based auth.
	// When set, requests use this TLS config (e.g. for mTLS to the API
	// via BAMF CA certs). When nil, the default system TLS config is used.
	TLSConfig *tls.Config

	// UserAgent is sent with every request (e.g. "bamf-agent/dev").
	UserAgent string

	// Logger for request-level debug logging. If nil, no logging occurs.
	Logger *slog.Logger
}

// Client is the shared HTTP client for talking to the BAMF API server.
type Client struct {
	baseURL    string
	httpClient *http.Client
	userAgent  string
	certPEM    []byte // PEM cert for X-Bamf-Client-Cert header
	logger     *slog.Logger
}

// New creates a Client from the given Config.
func New(cfg Config) *Client {
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}

	transport := &http.Transport{}
	if cfg.TLSConfig != nil {
		transport.TLSClientConfig = cfg.TLSConfig
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &Client{
		baseURL: cfg.BaseURL,
		httpClient: &http.Client{
			Timeout:   timeout,
			Transport: transport,
		},
		userAgent: cfg.UserAgent,
		logger:    logger,
	}
}

// SetClientCert sets the PEM-encoded certificate that will be sent as
// a base64-encoded X-Bamf-Client-Cert header on every request. This is
// the mechanism for cert-based auth through the Istio Gateway (which
// terminates TLS and passes the cert as a header).
func (c *Client) SetClientCert(certPEM []byte) {
	c.certPEM = certPEM
}

// BaseURL returns the configured API base URL.
func (c *Client) BaseURL() string {
	return c.baseURL
}

// HTTPClient returns the underlying http.Client. Used by the SSE client
// to reuse TLS configuration for long-lived streaming connections.
func (c *Client) HTTPClient() *http.Client {
	return c.httpClient
}

// UserAgent returns the configured User-Agent string.
func (c *Client) UserAgentString() string {
	return c.userAgent
}

// CertHeader returns the base64-encoded cert header value, or empty if
// no client cert is set.
func (c *Client) CertHeader() string {
	if len(c.certPEM) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(c.certPEM)
}

// Post sends a JSON POST request and decodes the response into the
// response parameter. If response is nil, the response body is discarded.
func (c *Client) Post(ctx context.Context, path string, body any, response any) error {
	jsonBody, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("apiclient: marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(jsonBody))
	if err != nil {
		return fmt.Errorf("apiclient: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	return c.do(req, response)
}

// Get sends a GET request and decodes the JSON response.
func (c *Client) Get(ctx context.Context, path string, response any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("apiclient: create request: %w", err)
	}

	return c.do(req, response)
}

// Delete sends a DELETE request and decodes the JSON response.
func (c *Client) Delete(ctx context.Context, path string, response any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.baseURL+path, nil)
	if err != nil {
		return fmt.Errorf("apiclient: create request: %w", err)
	}

	return c.do(req, response)
}

// do executes the request, sets common headers, handles errors, and
// optionally decodes the response body.
func (c *Client) do(req *http.Request, response any) error {
	// Set common headers
	if c.userAgent != "" {
		req.Header.Set("User-Agent", c.userAgent)
	}
	if len(c.certPEM) > 0 {
		req.Header.Set("X-Bamf-Client-Cert", c.CertHeader())
	}

	c.logger.Debug("API request",
		"method", req.Method,
		"path", req.URL.Path,
	)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("apiclient: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return parseErrorResponse(resp)
	}

	if response != nil {
		if err := json.NewDecoder(resp.Body).Decode(response); err != nil {
			return fmt.Errorf("apiclient: decode response: %w", err)
		}
	}

	return nil
}

// APIError represents an error response from the BAMF API server.
type APIError struct {
	StatusCode int
	Status     string
	Detail     string
}

func (e *APIError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("API error %d: %s", e.StatusCode, e.Detail)
	}
	return fmt.Sprintf("API error: %s", e.Status)
}

// IsNotFound returns true if the error is a 404.
func (e *APIError) IsNotFound() bool {
	return e.StatusCode == http.StatusNotFound
}

// IsUnauthorized returns true if the error is a 401.
func (e *APIError) IsUnauthorized() bool {
	return e.StatusCode == http.StatusUnauthorized
}

// parseErrorResponse reads the response body and tries to extract a
// FastAPI-style {"detail": "..."} message.
func parseErrorResponse(resp *http.Response) *APIError {
	apiErr := &APIError{
		StatusCode: resp.StatusCode,
		Status:     resp.Status,
	}

	// Read up to 4KB of error body
	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil || len(body) == 0 {
		return apiErr
	}

	// Try FastAPI error format: {"detail": "..."}
	var fastapiErr struct {
		Detail string `json:"detail"`
	}
	if json.Unmarshal(body, &fastapiErr) == nil && fastapiErr.Detail != "" {
		apiErr.Detail = fastapiErr.Detail
		return apiErr
	}

	// Fall back to raw body text
	apiErr.Detail = string(body)
	return apiErr
}
