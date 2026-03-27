package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ── Tests: runKubeCredentials ───────────────────────────────────────

func TestRunKubeCredentials_ValidCredentials(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	// Write valid credentials
	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))

	expiresAt := time.Now().Add(1 * time.Hour)
	creds := tokenResponse{
		SessionToken: "test-session-token-abc",
		ExpiresAt:    expiresAt,
		Email:        "alice@example.com",
		Roles:        []string{"admin"},
		APIURL:       "https://bamf.example.com",
	}
	data, err := json.MarshalIndent(creds, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), data, 0600))

	// Capture stdout
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stdout = w

	err = runKubeCredentials(kubeCredentialsCmd, nil)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	// Read captured output
	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	r.Close()
	output := string(buf[:n])

	// Parse output as JSON
	var execCred map[string]any
	require.NoError(t, json.Unmarshal([]byte(output), &execCred))

	require.Equal(t, "client.authentication.k8s.io/v1beta1", execCred["apiVersion"])
	require.Equal(t, "ExecCredential", execCred["kind"])

	status, ok := execCred["status"].(map[string]any)
	require.True(t, ok)
	require.Equal(t, "test-session-token-abc", status["token"])

	// Verify expiration timestamp is present and valid RFC3339
	expTS, ok := status["expirationTimestamp"].(string)
	require.True(t, ok)
	parsedTime, err := time.Parse(time.RFC3339, expTS)
	require.NoError(t, err)
	require.WithinDuration(t, expiresAt, parsedTime, time.Second)
}

func TestRunKubeCredentials_NoCredentials(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	err := runKubeCredentials(kubeCredentialsCmd, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not logged in")
}

func TestRunKubeCredentials_ExpiredCredentials(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))

	// Write expired credentials
	creds := tokenResponse{
		SessionToken: "expired-token",
		ExpiresAt:    time.Now().Add(-1 * time.Hour), // expired 1 hour ago
		Email:        "alice@example.com",
		APIURL:       "https://bamf.example.com",
	}
	data, err := json.MarshalIndent(creds, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), data, 0600))

	err = runKubeCredentials(kubeCredentialsCmd, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "credentials expired")
}

// ── Tests: ExecCredential JSON format ───────────────────────────────

func TestExecCredentialFormat(t *testing.T) {
	// Verify the exact JSON structure that kubectl expects
	expiresAt := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	execCred := map[string]any{
		"apiVersion": "client.authentication.k8s.io/v1beta1",
		"kind":       "ExecCredential",
		"status": map[string]any{
			"token":               "my-session-token",
			"expirationTimestamp": expiresAt.Format(time.RFC3339),
		},
	}

	data, err := json.Marshal(execCred)
	require.NoError(t, err)

	// Verify round-trip
	var parsed map[string]any
	require.NoError(t, json.Unmarshal(data, &parsed))

	require.Equal(t, "client.authentication.k8s.io/v1beta1", parsed["apiVersion"])
	require.Equal(t, "ExecCredential", parsed["kind"])

	status := parsed["status"].(map[string]any)
	require.Equal(t, "my-session-token", status["token"])
	require.Equal(t, "2026-06-15T12:00:00Z", status["expirationTimestamp"])
}

// ── Tests: kubeconfig context naming ────────────────────────────────

func TestKubeContextNaming(t *testing.T) {
	tests := []struct {
		name         string
		resourceName string
		wantContext  string
		wantServer   string
	}{
		{
			name:         "simple name",
			resourceName: "prod-cluster",
			wantContext:  "bamf-prod-cluster",
			wantServer:   "https://bamf.example.com/api/v1/kube/prod-cluster",
		},
		{
			name:         "short name",
			resourceName: "dev",
			wantContext:  "bamf-dev",
			wantServer:   "https://bamf.example.com/api/v1/kube/dev",
		},
		{
			name:         "hyphenated name",
			resourceName: "us-east-1-k8s",
			wantContext:  "bamf-us-east-1-k8s",
			wantServer:   "https://bamf.example.com/api/v1/kube/us-east-1-k8s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contextName := "bamf-" + tt.resourceName
			require.Equal(t, tt.wantContext, contextName)

			apiBase := "https://bamf.example.com"
			serverURL := apiBase + "/api/v1/kube/" + tt.resourceName
			require.Equal(t, tt.wantServer, serverURL)
		})
	}
}

// ── Tests: runKubeLogin ─────────────────────────────────────────────

func TestRunKubeLogin_NoCredentials(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	err := runKubeLogin(kubeLoginCmd, []string{"prod-cluster"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "not logged in")
}

func TestRunKubeLogin_ExpiredCredentials(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))

	creds := tokenResponse{
		SessionToken: "expired-token",
		ExpiresAt:    time.Now().Add(-1 * time.Hour),
		Email:        "alice@example.com",
		APIURL:       "https://bamf.example.com",
	}
	data, err := json.MarshalIndent(creds, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), data, 0600))

	err = runKubeLogin(kubeLoginCmd, []string{"prod-cluster"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "credentials expired")
}

func TestRunKubeLogin_NoAPIURL(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("BAMF_API_URL", "")

	oldAPIURL := apiURL
	apiURL = ""
	defer func() { apiURL = oldAPIURL }()

	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))

	creds := tokenResponse{
		SessionToken: "valid-token",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		Email:        "alice@example.com",
		APIURL:       "", // No API URL saved either
	}
	data, err := json.MarshalIndent(creds, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), data, 0600))

	err = runKubeLogin(kubeLoginCmd, []string{"prod-cluster"})
	require.Error(t, err)
	require.Contains(t, err.Error(), "API URL not configured")
}

func TestRunKubeLogin_WritesKubeconfig(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("BAMF_API_URL", "https://bamf.example.com")

	// Set KUBECONFIG to a temp file so we don't pollute the real kubeconfig
	kubeconfigPath := filepath.Join(home, ".kube", "config")
	require.NoError(t, os.MkdirAll(filepath.Join(home, ".kube"), 0700))
	t.Setenv("KUBECONFIG", kubeconfigPath)

	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))

	creds := tokenResponse{
		SessionToken: "valid-token",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		Email:        "alice@example.com",
		APIURL:       "https://bamf.example.com",
	}
	data, err := json.MarshalIndent(creds, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), data, 0600))

	// Capture stdout to suppress output
	oldStdout := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	err = runKubeLogin(kubeLoginCmd, []string{"prod-cluster"})

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	// Verify kubeconfig was written
	_, err = os.Stat(kubeconfigPath)
	require.NoError(t, err)

	// Read and verify the kubeconfig content
	kcData, err := os.ReadFile(kubeconfigPath)
	require.NoError(t, err)
	kcStr := string(kcData)

	// Verify key content
	require.Contains(t, kcStr, "bamf-prod-cluster")
	require.Contains(t, kcStr, "https://bamf.example.com/api/v1/kube/prod-cluster")
	require.Contains(t, kcStr, "kube-credentials")
	require.Contains(t, kcStr, "client.authentication.k8s.io/v1beta1")
}
