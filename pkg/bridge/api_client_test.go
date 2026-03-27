package bridge

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestBridgeNewAPIClient(t *testing.T) {
	c := NewAPIClient("https://bamf.example.com", slog.Default())
	require.NotNil(t, c)
	require.NotNil(t, c.Client)
}

func TestBridgeAPIClient_Bootstrap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/api/v1/internal/bridges/bootstrap", r.URL.Path)

		var body map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "bridge-0", body["bridge_id"])
		require.Equal(t, "0.bridge.tunnel.bamf.local", body["hostname"])
		require.Equal(t, "secret-token", body["bootstrap_token"])

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(BootstrapResponse{
			Certificate:   "CERT_PEM",
			PrivateKey:    "KEY_PEM",
			CACertificate: "CA_PEM",
			ExpiresAt:     "2026-12-31T23:59:59Z",
			SSHHostKey:    "SSH_KEY_PEM",
		}))
	}))
	defer srv.Close()

	c := NewAPIClient(srv.URL, slog.Default())
	resp, err := c.Bootstrap(context.Background(), "bridge-0", "0.bridge.tunnel.bamf.local", "secret-token")
	require.NoError(t, err)
	require.Equal(t, "CERT_PEM", resp.Certificate)
	require.Equal(t, "KEY_PEM", resp.PrivateKey)
	require.Equal(t, "CA_PEM", resp.CACertificate)
	require.Equal(t, "SSH_KEY_PEM", resp.SSHHostKey)
}

func TestBridgeAPIClient_Bootstrap_Error(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"detail": "Invalid bootstrap token"}`))
	}))
	defer srv.Close()

	c := NewAPIClient(srv.URL, slog.Default())
	_, err := c.Bootstrap(context.Background(), "bridge-0", "host", "bad-token")
	require.Error(t, err)
}

func TestBridgeAPIClient_RenewCertificate(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/internal/bridges/renew", r.URL.Path)

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(RenewResponse{
			Certificate:   "NEW_CERT",
			PrivateKey:    "NEW_KEY",
			CACertificate: "CA",
			ExpiresAt:     "2027-01-01T00:00:00Z",
		}))
	}))
	defer srv.Close()

	c := NewAPIClient(srv.URL, slog.Default())
	resp, err := c.RenewCertificate(context.Background())
	require.NoError(t, err)
	require.Equal(t, "NEW_CERT", resp.Certificate)
	require.Equal(t, "NEW_KEY", resp.PrivateKey)
}

func TestBridgeAPIClient_RegisterBridge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/internal/bridges/register", r.URL.Path)

		var body map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "bridge-1", body["bridge_id"])
		require.Equal(t, "1.bridge.tunnel.bamf.local", body["hostname"])

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewAPIClient(srv.URL, slog.Default())
	err := c.RegisterBridge(context.Background(), "bridge-1", "1.bridge.tunnel.bamf.local")
	require.NoError(t, err)
}

func TestBridgeAPIClient_UpdateBridgeStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/internal/bridges/bridge-0/status", r.URL.Path)

		var body map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "draining", body["status"])

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewAPIClient(srv.URL, slog.Default())
	err := c.UpdateBridgeStatus(context.Background(), "bridge-0", "draining")
	require.NoError(t, err)
}

func TestBridgeAPIClient_SendHeartbeat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/internal/bridges/bridge-0/heartbeat", r.URL.Path)

		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, float64(5), body["active_tunnels"])

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewAPIClient(srv.URL, slog.Default())
	err := c.SendHeartbeat(context.Background(), "bridge-0", 5)
	require.NoError(t, err)
}

func TestBridgeAPIClient_ValidateSession(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/internal/sessions/validate", r.URL.Path)

		var body map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "session-token-123", body["session_token"])

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(ValidateSessionResponse{
			Token:        "session-token-123",
			UserEmail:    "alice@example.com",
			ResourceName: "web-01",
			AgentID:      "agent-uuid",
			Protocol:     "ssh",
		}))
	}))
	defer srv.Close()

	c := NewAPIClient(srv.URL, slog.Default())
	resp, err := c.ValidateSession(context.Background(), "session-token-123")
	require.NoError(t, err)
	require.Equal(t, "alice@example.com", resp.UserEmail)
	require.Equal(t, "web-01", resp.ResourceName)
	require.Equal(t, "ssh", resp.Protocol)
}

func TestBridgeAPIClient_GetAgentConnection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/internal/tunnels/establish", r.URL.Path)

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(AgentConnectionInfo{
			AgentID:      "agent-uuid",
			AgentName:    "datacenter-agent",
			ResourceName: "web-01",
			ResourceType: "ssh",
			TargetHost:   "web-01.internal",
			TargetPort:   22,
		}))
	}))
	defer srv.Close()

	c := NewAPIClient(srv.URL, slog.Default())
	info, err := c.GetAgentConnection(context.Background(), "session-token", "agent-uuid")
	require.NoError(t, err)
	require.Equal(t, "datacenter-agent", info.AgentName)
	require.Equal(t, "web-01.internal", info.TargetHost)
	require.Equal(t, 22, info.TargetPort)
}

func TestBridgeAPIClient_NotifyTunnelEstablished(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/internal/tunnels/established", r.URL.Path)

		var body map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "session-123", body["session_token"])
		require.Equal(t, "tunnel-456", body["tunnel_id"])

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewAPIClient(srv.URL, slog.Default())
	err := c.NotifyTunnelEstablished(context.Background(), "session-123", "tunnel-456")
	require.NoError(t, err)
}

func TestBridgeAPIClient_NotifyTunnelClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/internal/tunnels/closed", r.URL.Path)

		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "session-123", body["session_token"])
		require.Equal(t, float64(1024), body["bytes_sent"])
		require.Equal(t, float64(2048), body["bytes_received"])

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewAPIClient(srv.URL, slog.Default())
	err := c.NotifyTunnelClosed(context.Background(), "session-123", "tunnel-456", 1024, 2048)
	require.NoError(t, err)
}

func TestBridgeAPIClient_UploadSessionRecording(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/internal/sessions/sess-123/recording", r.URL.Path)

		var body map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "asciicast-v2", body["format"])
		require.Contains(t, body["data"], "recording data")

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewAPIClient(srv.URL, slog.Default())
	err := c.UploadSessionRecording(context.Background(), "sess-123", []byte("recording data"))
	require.NoError(t, err)
}

func TestBridgeAPIClient_UploadQueryRecording(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/internal/sessions/sess-456/recording", r.URL.Path)

		var body map[string]string
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "queries-v1", body["format"])
		require.Equal(t, "queries", body["recording_type"])

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := NewAPIClient(srv.URL, slog.Default())
	err := c.UploadQueryRecording(context.Background(), "sess-456", `[{"query":"SELECT 1"}]`)
	require.NoError(t, err)
}

func TestBridgeAPIClient_RequestDrain(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/internal/bridges/bridge-0/drain", r.URL.Path)

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(DrainResponse{
			MigratedCount:           3,
			NonMigratableSessionIDs: []string{"ssh-audit-1"},
			Errors:                  nil,
		}))
	}))
	defer srv.Close()

	c := NewAPIClient(srv.URL, slog.Default())
	resp, err := c.RequestDrain(context.Background(), "bridge-0", []DrainTunnelInfo{
		{SessionToken: "s1", Protocol: "ssh"},
		{SessionToken: "s2", Protocol: "ssh-audit"},
	})
	require.NoError(t, err)
	require.Equal(t, 3, resp.MigratedCount)
	require.Equal(t, []string{"ssh-audit-1"}, resp.NonMigratableSessionIDs)
}
