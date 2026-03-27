package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewAPIClient(t *testing.T) {
	c := NewAPIClient("https://bamf.example.com", slog.Default())
	require.NotNil(t, c)
	require.NotNil(t, c.Client)
}

func TestAPIClient_Join(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/api/v1/agents/join", r.URL.Path)

		var body map[string]any
		err := json.NewDecoder(r.Body).Decode(&body)
		require.NoError(t, err)
		require.Equal(t, "bamf_test_token", body["join_token"])
		require.Equal(t, "my-agent", body["name"])

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]string{
			"agent_id":               "agent-uuid-123",
			"certificate":            "CERT",
			"private_key":            "KEY",
			"ca_certificate":         "CA",
			"certificate_expires_at": "2026-12-31T23:59:59Z",
		}))
	}))
	defer srv.Close()

	c := NewAPIClient(srv.URL, slog.Default())
	cert, key, ca, agentID, err := c.Join(context.Background(), "bamf_test_token", "my-agent", map[string]string{"env": "prod"})
	require.NoError(t, err)
	require.Equal(t, "agent-uuid-123", agentID)
	require.Equal(t, []byte("CERT"), cert)
	require.Equal(t, []byte("KEY"), key)
	require.Equal(t, []byte("CA"), ca)
}

func TestAPIClient_Join_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"detail": "Invalid join token"}`))
	}))
	defer srv.Close()

	c := NewAPIClient(srv.URL, slog.Default())
	_, _, _, _, err := c.Join(context.Background(), "bad_token", "agent", nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "401")
}

func TestAPIClient_Heartbeat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/api/v1/agents/agent-123/heartbeat", r.URL.Path)

		var body heartbeatRequest
		err := json.NewDecoder(r.Body).Decode(&body)
		require.NoError(t, err)
		require.Len(t, body.Resources, 1)
		require.Equal(t, "web-01", body.Resources[0].Name)
		require.Equal(t, "ssh", body.Resources[0].ResourceType)
		require.True(t, body.ClusterInternal)
		require.Equal(t, "inst-1", body.InstanceID)
		require.Equal(t, 3, body.ActiveTunnels)

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewAPIClient(srv.URL, slog.Default())
	resources := []ResourceConfig{
		{
			Name:         "web-01",
			ResourceType: "ssh",
			Hostname:     "web-01.internal",
			Port:         22,
			Labels:       map[string]string{"env": "prod"},
		},
	}
	err := c.Heartbeat(context.Background(), "agent-123", resources, map[string]string{"env": "prod"}, true, "inst-1", 3)
	require.NoError(t, err)
}

func TestAPIClient_UpdateStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/agents/agent-123/status", r.URL.Path)

		var body map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "online", body["status"])

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewAPIClient(srv.URL, slog.Default())
	err := c.UpdateStatus(context.Background(), "agent-123", "online")
	require.NoError(t, err)
}

func TestAPIClient_DrainInstance(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/agents/agent-123/drain", r.URL.Path)

		var body map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "inst-1", body["instance_id"])

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewAPIClient(srv.URL, slog.Default())
	err := c.DrainInstance(context.Background(), "agent-123", "inst-1")
	require.NoError(t, err)
}

func TestAPIClient_RemoveInstance(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/agents/agent-123/instance/inst-1/offline", r.URL.Path)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewAPIClient(srv.URL, slog.Default())
	err := c.RemoveInstance(context.Background(), "agent-123", "inst-1")
	require.NoError(t, err)
}

func TestAPIClient_RenewCertificate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/agents/agent-123/renew", r.URL.Path)

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]string{
			"certificate":            "NEW_CERT",
			"private_key":            "NEW_KEY",
			"ca_certificate":         "CA",
			"certificate_expires_at": "2027-06-15T12:00:00Z",
		}))
	}))
	defer srv.Close()

	c := NewAPIClient(srv.URL, slog.Default())
	cert, key, expiresAt, err := c.RenewCertificate(context.Background(), "agent-123")
	require.NoError(t, err)
	require.Equal(t, []byte("NEW_CERT"), cert)
	require.Equal(t, []byte("NEW_KEY"), key)
	require.Equal(t, 2027, expiresAt.Year())
	require.Equal(t, 6, int(expiresAt.Month()))
}

func TestAPIClient_RenewCertificate_BadExpiry(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]string{
			"certificate":            "CERT",
			"private_key":            "KEY",
			"certificate_expires_at": "not-a-date",
		}))
	}))
	defer srv.Close()

	c := NewAPIClient(srv.URL, slog.Default())
	_, _, _, err := c.RenewCertificate(context.Background(), "agent-123")
	require.Error(t, err)
	require.Contains(t, err.Error(), "parse certificate expiry")
}

func TestAPIClient_Heartbeat_WithWebhooks(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body heartbeatRequest
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Len(t, body.Resources, 1)
		require.Len(t, body.Resources[0].Webhooks, 1)
		require.Equal(t, "/webhook", body.Resources[0].Webhooks[0].Path)
		require.Equal(t, []string{"POST"}, body.Resources[0].Webhooks[0].Methods)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewAPIClient(srv.URL, slog.Default())
	resources := []ResourceConfig{
		{
			Name:         "app",
			ResourceType: "http",
			Hostname:     "app.internal",
			Port:         8080,
			Labels:       map[string]string{},
			Webhooks: []WebhookConfig{
				{Path: "/webhook", Methods: []string{"POST"}},
			},
		},
	}
	err := c.Heartbeat(context.Background(), "agent-1", resources, nil, false, "inst-1", 0)
	require.NoError(t, err)
}
