package cmd

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ── Tests: runResources ─────────────────────────────────────────────

func TestRunResources_NoCredentials(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	err := runResources(resourcesCmd, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not logged in")
}

func TestRunResources_ExpiredCredentials(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))
	creds := tokenResponse{
		SessionToken: "expired",
		ExpiresAt:    time.Now().Add(-1 * time.Hour),
		Email:        "alice@example.com",
	}
	data, _ := json.MarshalIndent(creds, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), data, 0600))

	err := runResources(resourcesCmd, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "credentials expired")
}

func TestRunResources_Success(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))
	creds := tokenResponse{
		SessionToken: "tok",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}
	data, _ := json.MarshalIndent(creds, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), data, 0600))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/resources", r.URL.Path)
		require.Equal(t, "GET", r.Method)
		require.Equal(t, "Bearer tok", r.Header.Get("Authorization"))

		resp := map[string]any{
			"resources": []resource{
				{
					Name:         "web-prod-01",
					ResourceType: "ssh",
					Status:       "online",
					Labels:       map[string]string{"env": "prod"},
					AgentName:    "agent-01",
				},
				{
					Name:         "orders-db",
					ResourceType: "postgres",
					Status:       "online",
					Labels:       map[string]string{"env": "prod", "team": "orders"},
					AgentName:    "agent-02",
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	oldJSON := jsonOutput
	jsonOutput = false
	defer func() { jsonOutput = oldJSON }()

	// Reset filter flags
	oldType := resourcesType
	oldLabels := resourcesLabels
	resourcesType = ""
	resourcesLabels = ""
	defer func() {
		resourcesType = oldType
		resourcesLabels = oldLabels
	}()

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runResources(resourcesCmd, nil)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	r.Close()
	output := string(buf[:n])

	require.Contains(t, output, "web-prod-01")
	require.Contains(t, output, "orders-db")
	require.Contains(t, output, "ssh")
	require.Contains(t, output, "postgres")
	require.Contains(t, output, "NAME")
	require.Contains(t, output, "TYPE")
}

func TestRunResources_EmptyList(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))
	creds := tokenResponse{
		SessionToken: "tok",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}
	data, _ := json.MarshalIndent(creds, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), data, 0600))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"resources": []resource{}})
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	oldType := resourcesType
	oldLabels := resourcesLabels
	resourcesType = ""
	resourcesLabels = ""
	defer func() {
		resourcesType = oldType
		resourcesLabels = oldLabels
	}()

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runResources(resourcesCmd, nil)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	r.Close()
	output := string(buf[:n])
	require.Contains(t, output, "No resources found")
}

func TestRunResources_WithTypeFilter(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))
	creds := tokenResponse{
		SessionToken: "tok",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}
	data, _ := json.MarshalIndent(creds, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), data, 0600))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "ssh", r.URL.Query().Get("type"))
		_ = json.NewEncoder(w).Encode(map[string]any{"resources": []resource{}})
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	oldType := resourcesType
	oldLabels := resourcesLabels
	resourcesType = "ssh"
	resourcesLabels = ""
	defer func() {
		resourcesType = oldType
		resourcesLabels = oldLabels
	}()

	oldStdout := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	err := runResources(resourcesCmd, nil)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)
}

func TestRunResources_WithLabelFilter(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))
	creds := tokenResponse{
		SessionToken: "tok",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}
	data, _ := json.MarshalIndent(creds, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), data, 0600))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "env=prod,team=platform", r.URL.Query().Get("labels"))
		_ = json.NewEncoder(w).Encode(map[string]any{"resources": []resource{}})
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	oldType := resourcesType
	oldLabels := resourcesLabels
	resourcesType = ""
	resourcesLabels = "env=prod,team=platform"
	defer func() {
		resourcesType = oldType
		resourcesLabels = oldLabels
	}()

	oldStdout := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	err := runResources(resourcesCmd, nil)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)
}

func TestRunResources_JSONOutput(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))
	creds := tokenResponse{
		SessionToken: "tok",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}
	data, _ := json.MarshalIndent(creds, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), data, 0600))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"resources": []resource{
				{Name: "web-01", ResourceType: "ssh", Status: "online"},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	oldJSON := jsonOutput
	jsonOutput = true
	defer func() { jsonOutput = oldJSON }()

	oldType := resourcesType
	oldLabels := resourcesLabels
	resourcesType = ""
	resourcesLabels = ""
	defer func() {
		resourcesType = oldType
		resourcesLabels = oldLabels
	}()

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runResources(resourcesCmd, nil)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	r.Close()
	output := string(buf[:n])

	var parsed []any
	require.NoError(t, json.Unmarshal([]byte(output), &parsed))
	require.Len(t, parsed, 1)
}

func TestRunResources_APIError(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))
	creds := tokenResponse{
		SessionToken: "tok",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}
	data, _ := json.MarshalIndent(creds, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), data, 0600))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	oldType := resourcesType
	oldLabels := resourcesLabels
	resourcesType = ""
	resourcesLabels = ""
	defer func() {
		resourcesType = oldType
		resourcesLabels = oldLabels
	}()

	err := runResources(resourcesCmd, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "API error")
}

// ── Tests: runAgents ────────────────────────────────────────────────

func TestRunAgents_NoCredentials(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	err := runAgents(agentsCmd, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not logged in")
}

func TestRunAgents_ExpiredCredentials(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))
	creds := tokenResponse{
		SessionToken: "expired",
		ExpiresAt:    time.Now().Add(-1 * time.Hour),
	}
	data, _ := json.MarshalIndent(creds, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), data, 0600))

	err := runAgents(agentsCmd, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "credentials expired")
}

func TestRunAgents_Success(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))
	creds := tokenResponse{
		SessionToken: "tok",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}
	data, _ := json.MarshalIndent(creds, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), data, 0600))

	hb := time.Now().Add(-30 * time.Second)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/agents", r.URL.Path)
		require.Equal(t, "GET", r.Method)

		resp := map[string]any{
			"agents": []agent{
				{
					Name:          "agent-01",
					Status:        "online",
					Labels:        map[string]string{"env": "prod"},
					LastHeartbeat: &hb,
					ResourceCount: 3,
				},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	oldJSON := jsonOutput
	jsonOutput = false
	defer func() { jsonOutput = oldJSON }()

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runAgents(agentsCmd, nil)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	r.Close()
	output := string(buf[:n])

	require.Contains(t, output, "agent-01")
	require.Contains(t, output, "online")
	require.Contains(t, output, "NAME")
}

func TestRunAgents_EmptyList(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))
	creds := tokenResponse{
		SessionToken: "tok",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}
	data, _ := json.MarshalIndent(creds, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), data, 0600))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"agents": []agent{}})
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runAgents(agentsCmd, nil)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	r.Close()
	output := string(buf[:n])
	require.Contains(t, output, "No agents registered")
}

func TestRunAgents_JSONOutput(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))
	creds := tokenResponse{
		SessionToken: "tok",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}
	data, _ := json.MarshalIndent(creds, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), data, 0600))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]any{
			"agents": []agent{
				{Name: "agent-01", Status: "online", ResourceCount: 5},
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	oldJSON := jsonOutput
	jsonOutput = true
	defer func() { jsonOutput = oldJSON }()

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runAgents(agentsCmd, nil)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	r.Close()
	output := string(buf[:n])

	var parsed []any
	require.NoError(t, json.Unmarshal([]byte(output), &parsed))
	require.Len(t, parsed, 1)
}

// ── Tests: runLogout ────────────────────────────────────────────────

func TestRunLogout_NotLoggedIn(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Create .bamf directory but no credentials
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".bamf"), 0700))

	oldStdout := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	err := runLogout(logoutCmd, nil)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err) // Should succeed even if no credentials
}

func TestRunLogout_WithCredentials(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	bamfPath := filepath.Join(home, ".bamf")
	keysDir := filepath.Join(bamfPath, "keys")
	require.NoError(t, os.MkdirAll(keysDir, 0700))

	// Write credentials file
	creds := tokenResponse{
		SessionToken: "tok-to-revoke",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		Email:        "alice@example.com",
		APIURL:       "https://bamf.example.com",
	}
	data, _ := json.MarshalIndent(creds, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), data, 0600))

	// Write some key files
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "user.crt"), []byte("cert"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "user.key"), []byte("key"), 0600))

	// Mock server for session revocation
	revoked := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/auth/logout" {
			revoked = true
			w.WriteHeader(http.StatusOK)
		}
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	oldStdout := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	err := runLogout(logoutCmd, nil)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)
	require.True(t, revoked)

	// Verify credentials file was removed
	_, err = os.Stat(filepath.Join(bamfPath, "credentials.json"))
	require.True(t, os.IsNotExist(err))

	// Verify key files were removed
	entries, _ := os.ReadDir(keysDir)
	require.Empty(t, entries)
}
