// Package client is a minimal HTTP client for the BAMF REST API (/api/v1),
// used by the Terraform provider. It is intentionally self-contained rather
// than depending on the main bamf Go module.
package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ErrNotFound is returned when the API responds 404 for a resource.
var ErrNotFound = errors.New("bamf: not found")

// Client talks to a BAMF API server. Auth is an admin session token presented
// as a Bearer header (the same token `bamf login` stores).
type Client struct {
	endpoint string
	token    string
	http     *http.Client
}

// New returns a client for endpoint (e.g. https://bamf.example.com) using the
// given admin session token.
func New(endpoint, token string) *Client {
	return &Client{
		endpoint: strings.TrimRight(endpoint, "/"),
		token:    token,
		http:     &http.Client{Timeout: 30 * time.Second},
	}
}

// PermissionsBlock mirrors the API's allow/deny block.
type PermissionsBlock struct {
	Labels map[string][]string `json:"labels"`
	Names  []string            `json:"names"`
}

// Role mirrors the API role model (services/bamf/api/models/roles.py).
type Role struct {
	Name             string           `json:"name"`
	Description      *string          `json:"description,omitempty"`
	Allow            PermissionsBlock `json:"allow"`
	Deny             PermissionsBlock `json:"deny"`
	KubernetesGroups []string         `json:"kubernetes_groups"`
	IsBuiltin        bool             `json:"is_builtin,omitempty"`
}

func (c *Client) do(ctx context.Context, method, path string, body, out any) error {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("bamf: marshal request: %w", err)
		}
		reader = bytes.NewReader(b)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, reader)
	if err != nil {
		return fmt.Errorf("bamf: new request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("bamf: %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode >= 400 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("bamf: %s %s: status %d: %s", method, path, resp.StatusCode, strings.TrimSpace(string(msg)))
	}
	if out != nil && resp.StatusCode != http.StatusNoContent {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			return fmt.Errorf("bamf: decode %s %s: %w", method, path, err)
		}
	}
	return nil
}

// CreateRole creates a custom role.
func (c *Client) CreateRole(ctx context.Context, role Role) (*Role, error) {
	var out Role
	if err := c.do(ctx, http.MethodPost, "/api/v1/roles", role, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetRole fetches a role by name. Returns ErrNotFound if it doesn't exist.
func (c *Client) GetRole(ctx context.Context, name string) (*Role, error) {
	var out Role
	if err := c.do(ctx, http.MethodGet, "/api/v1/roles/"+name, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// roleUpdate is the PUT body — the API's RoleUpdate shape (no name/is_builtin,
// which the create-only fields would be rejected as extras).
type roleUpdate struct {
	Description      *string          `json:"description,omitempty"`
	Allow            PermissionsBlock `json:"allow"`
	Deny             PermissionsBlock `json:"deny"`
	KubernetesGroups []string         `json:"kubernetes_groups"`
}

// UpdateRole updates a role's description/allow/deny/kubernetes_groups.
func (c *Client) UpdateRole(ctx context.Context, name string, role Role) (*Role, error) {
	body := roleUpdate{
		Description:      role.Description,
		Allow:            role.Allow,
		Deny:             role.Deny,
		KubernetesGroups: role.KubernetesGroups,
	}
	var out Role
	if err := c.do(ctx, http.MethodPatch, "/api/v1/roles/"+name, body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// DeleteRole removes a custom role.
func (c *Client) DeleteRole(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, "/api/v1/roles/"+name, nil, nil)
}
