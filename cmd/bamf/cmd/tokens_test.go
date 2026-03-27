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

// ── Tests: parseTTLToHours ──────────────────────────────────────────
// (These are in ssh_test.go as TestParseTTLToHours — additional edge cases here)

func TestParseTTLToHours_LargeValues(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  int
	}{
		{name: "365 days", input: "365d", want: 8760},
		{name: "48 hours", input: "48h", want: 48},
		{name: "2h30m", input: "2h30m", want: 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTTLToHours(tt.input)
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

// ── Tests: runTokensList ────────────────────────────────────────────

func TestRunTokensList_NoCredentials(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	err := runTokensList(tokensListCmd, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not logged in")
}

func TestRunTokensList_Success(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))
	creds := tokenResponse{
		SessionToken: "tok",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		Email:        "admin@example.com",
		APIURL:       "https://bamf.example.com",
	}
	data, _ := json.MarshalIndent(creds, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), data, 0600))

	maxUses := 10
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/tokens", r.URL.Path)
		require.Equal(t, "GET", r.Method)
		require.Equal(t, "Bearer tok", r.Header.Get("Authorization"))

		resp := map[string]any{
			"tokens": []joinToken{
				{
					Name:      "dev-token",
					ExpiresAt: time.Now().Add(24 * time.Hour),
					MaxUses:   &maxUses,
					UseCount:  3,
					CreatedBy: "admin@example.com",
					CreatedAt: time.Now().Add(-1 * time.Hour),
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

	err := runTokensList(tokensListCmd, nil)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	r.Close()
	output := string(buf[:n])

	require.Contains(t, output, "dev-token")
	require.Contains(t, output, "active")
	require.Contains(t, output, "3/10")
}

func TestRunTokensList_EmptyList(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))
	creds := tokenResponse{
		SessionToken: "tok",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		APIURL:       "https://bamf.example.com",
	}
	data, _ := json.MarshalIndent(creds, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), data, 0600))

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"tokens": []joinToken{}})
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runTokensList(tokensListCmd, nil)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	r.Close()
	output := string(buf[:n])
	require.Contains(t, output, "No join tokens found")
}

func TestRunTokensList_JSONOutput(t *testing.T) {
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
			"tokens": []joinToken{
				{Name: "test-token", ExpiresAt: time.Now().Add(1 * time.Hour)},
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

	err := runTokensList(tokensListCmd, nil)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	r.Close()
	output := string(buf[:n])

	// Should be valid JSON array
	var parsed []any
	require.NoError(t, json.Unmarshal([]byte(output), &parsed))
	require.Len(t, parsed, 1)
}

func TestRunTokensList_RevokedToken(t *testing.T) {
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
			"tokens": []joinToken{
				{
					Name:      "revoked-token",
					ExpiresAt: time.Now().Add(1 * time.Hour),
					IsRevoked: true,
					CreatedBy: "admin@example.com",
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

	err := runTokensList(tokensListCmd, nil)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	r.Close()
	output := string(buf[:n])

	require.Contains(t, output, "revoked-token")
	require.Contains(t, output, "revoked")
}

func TestRunTokensList_NoAPIURL(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("BAMF_API_URL", "")

	oldAPIURL := apiURL
	apiURL = ""
	defer func() { apiURL = oldAPIURL }()

	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))
	creds := tokenResponse{
		SessionToken: "tok",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
	}
	data, _ := json.MarshalIndent(creds, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), data, 0600))

	err := runTokensList(tokensListCmd, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "API URL not configured")
}

// ── Tests: runTokensCreate ──────────────────────────────────────────

func TestRunTokensCreate_Success(t *testing.T) {
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
		require.Equal(t, "/api/v1/tokens", r.URL.Path)
		require.Equal(t, "POST", r.Method)
		require.Equal(t, "application/json", r.Header.Get("Content-Type"))

		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		require.Equal(t, float64(24), body["expires_in_hours"])

		maxUses := 5
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(joinToken{
			Name:      "new-token",
			Token:     "bamf_jt_abc123",
			ExpiresAt: time.Now().Add(24 * time.Hour),
			MaxUses:   &maxUses,
			CreatedBy: "admin@example.com",
		})
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	// Set up token creation flags
	oldTTL := tokenTTL
	oldMaxUses := tokenMaxUses
	oldName := tokenName
	oldLabels := tokenLabels
	tokenTTL = "24h"
	tokenMaxUses = 5
	tokenName = ""
	tokenLabels = ""
	defer func() {
		tokenTTL = oldTTL
		tokenMaxUses = oldMaxUses
		tokenName = oldName
		tokenLabels = oldLabels
	}()

	oldJSON := jsonOutput
	jsonOutput = false
	defer func() { jsonOutput = oldJSON }()

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runTokensCreate(tokensCreateCmd, nil)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	r.Close()
	output := string(buf[:n])

	require.Contains(t, output, "new-token")
	require.Contains(t, output, "bamf_jt_abc123")
}

func TestRunTokensCreate_WithLabels(t *testing.T) {
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
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)

		labels, ok := body["agent_labels"].(map[string]any)
		require.True(t, ok)
		require.Equal(t, "prod", labels["env"])
		require.Equal(t, "us-east-1", labels["region"])

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(joinToken{
			Name:      "labeled-token",
			Token:     "bamf_jt_xyz",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		})
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	oldTTL := tokenTTL
	oldLabels := tokenLabels
	oldMaxUses := tokenMaxUses
	oldName := tokenName
	tokenTTL = "1h"
	tokenLabels = "env=prod,region=us-east-1"
	tokenMaxUses = 0
	tokenName = ""
	defer func() {
		tokenTTL = oldTTL
		tokenLabels = oldLabels
		tokenMaxUses = oldMaxUses
		tokenName = oldName
	}()

	oldJSON := jsonOutput
	jsonOutput = false
	defer func() { jsonOutput = oldJSON }()

	oldStdout := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	err := runTokensCreate(tokensCreateCmd, nil)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)
}

// ── Tests: runTokensRevoke ──────────────────────────────────────────

func TestRunTokensRevoke_Success(t *testing.T) {
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
		require.Equal(t, "/api/v1/tokens/my-token/revoke", r.URL.Path)
		require.Equal(t, "POST", r.Method)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	oldStdout := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	err := runTokensRevoke(tokensRevokeCmd, []string{"my-token"})

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)
}

func TestRunTokensRevoke_NotFound(t *testing.T) {
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
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	err := runTokensRevoke(tokensRevokeCmd, []string{"nonexistent"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "token not found")
}
