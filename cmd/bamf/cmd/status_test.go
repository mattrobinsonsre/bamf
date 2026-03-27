package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestRunStatus_NotLoggedIn(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runStatus(statusCmd, nil)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	r.Close()
	output := string(buf[:n])
	require.Contains(t, output, "Not logged in")
}

func TestRunStatus_ValidCredentials(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))

	expiresAt := time.Now().Add(6 * time.Hour)
	creds := tokenResponse{
		SessionToken: "active-token",
		ExpiresAt:    expiresAt,
		Email:        "alice@example.com",
		Roles:        []string{"admin", "sre"},
	}
	data, _ := json.MarshalIndent(creds, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), data, 0600))

	// Ensure text output (not JSON)
	oldJSON := jsonOutput
	jsonOutput = false
	defer func() { jsonOutput = oldJSON }()

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runStatus(statusCmd, nil)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	r.Close()
	output := string(buf[:n])

	require.Contains(t, output, "alice@example.com")
	require.Contains(t, output, "admin, sre")
	require.Contains(t, output, "Session expires:")
	require.Contains(t, output, "Time remaining:")
}

func TestRunStatus_ExpiredCredentials(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))

	creds := tokenResponse{
		SessionToken: "expired-token",
		ExpiresAt:    time.Now().Add(-1 * time.Hour),
		Email:        "bob@example.com",
	}
	data, _ := json.MarshalIndent(creds, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), data, 0600))

	oldJSON := jsonOutput
	jsonOutput = false
	defer func() { jsonOutput = oldJSON }()

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runStatus(statusCmd, nil)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	r.Close()
	output := string(buf[:n])

	require.Contains(t, output, "bob@example.com")
	require.Contains(t, output, "Session expired:")
	require.Contains(t, output, "bamf login")
}

func TestRunStatus_JSONOutput(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))

	expiresAt := time.Now().Add(2 * time.Hour)
	creds := tokenResponse{
		SessionToken: "active-token",
		ExpiresAt:    expiresAt,
		Email:        "alice@example.com",
		Roles:        []string{"developer"},
	}
	data, _ := json.MarshalIndent(creds, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), data, 0600))

	// Enable JSON output
	oldJSON := jsonOutput
	jsonOutput = true
	defer func() { jsonOutput = oldJSON }()

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runStatus(statusCmd, nil)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	r.Close()
	output := string(buf[:n])

	var parsed map[string]any
	require.NoError(t, json.Unmarshal([]byte(output), &parsed))
	require.Equal(t, true, parsed["logged_in"])
	require.Equal(t, "alice@example.com", parsed["user"])
	require.Equal(t, false, parsed["expired"])
}

func TestRunStatus_InvalidCredentialsFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), []byte("bad json"), 0600))

	err := runStatus(statusCmd, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid credentials file")
}

func TestRunStatus_NoRoles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))

	creds := tokenResponse{
		SessionToken: "tok",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		Email:        "noroles@example.com",
	}
	data, _ := json.MarshalIndent(creds, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), data, 0600))

	oldJSON := jsonOutput
	jsonOutput = false
	defer func() { jsonOutput = oldJSON }()

	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	err := runStatus(statusCmd, nil)

	w.Close()
	os.Stdout = oldStdout

	require.NoError(t, err)

	buf := make([]byte, 4096)
	n, _ := r.Read(buf)
	r.Close()
	output := string(buf[:n])

	require.Contains(t, output, "noroles@example.com")
	// Should NOT contain "Roles:" since there are none
	require.NotContains(t, output, "Roles:")
}
