package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// writeOutpostTestCreds writes a credentials.json into a temp HOME and returns
// nothing — callers set BAMF_API_URL to their test server.
func writeOutpostTestCreds(t *testing.T) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))
	creds := tokenResponse{
		SessionToken: "tok",
		ExpiresAt:    time.Now().Add(time.Hour),
		Email:        "admin@example.com",
		APIURL:       "https://bamf.example.com",
	}
	data, _ := json.MarshalIndent(creds, "", "  ")
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), data, 0600))
}

func captureStdout(t *testing.T, fn func() error) (string, error) {
	t.Helper()
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	err := fn()
	_ = w.Close()
	os.Stdout = old
	out, _ := io.ReadAll(r)
	return string(out), err
}

func TestRunOutpostTokensList_NoCredentials(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	err := runOutpostTokensList(outpostTokensListCmd, nil)
	require.Error(t, err)
}

func TestRunOutpostTokensList_Success(t *testing.T) {
	writeOutpostTestCreds(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/outpost-tokens", r.URL.Path)
		require.Equal(t, "GET", r.Method)
		require.Equal(t, "Bearer tok", r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items": []outpostToken{{
				Name: "eu-token", OutpostName: "eu", UseCount: 1,
				ExpiresAt: time.Now().Add(24 * time.Hour), CreatedBy: "admin@example.com",
			}},
		})
	}))
	defer srv.Close()
	t.Setenv("BAMF_API_URL", srv.URL)

	out, err := captureStdout(t, func() error { return runOutpostTokensList(outpostTokensListCmd, nil) })
	require.NoError(t, err)
	require.Contains(t, out, "eu-token")
	require.Contains(t, out, "eu")
}

func TestRunOutpostTokensCreate_Success(t *testing.T) {
	writeOutpostTestCreds(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/outpost-tokens", r.URL.Path)
		require.Equal(t, "POST", r.Method)
		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "eu-token", body["name"])
		require.Equal(t, "eu", body["outpost_name"])
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "eu-token", "outpost_name": "eu", "token": "bamf_out_secret",
			"expires_at": time.Now().Add(24 * time.Hour), "use_count": 0,
			"created_by": "admin@example.com",
		})
	}))
	defer srv.Close()
	t.Setenv("BAMF_API_URL", srv.URL)

	outpostTokenOutpost = "eu"
	defer func() { outpostTokenOutpost = "" }()

	out, err := captureStdout(t, func() error { return runOutpostTokensCreate(outpostTokensCreateCmd, []string{"eu-token"}) })
	require.NoError(t, err)
	require.Contains(t, out, "bamf_out_secret")
	require.True(t, strings.Contains(out, "only once"))
}

func TestRunOutpostsList_Success(t *testing.T) {
	writeOutpostTestCreds(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/outposts", r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items": []outpostInfo{{ID: "out-1", Name: "eu", IsActive: true}},
		})
	}))
	defer srv.Close()
	t.Setenv("BAMF_API_URL", srv.URL)

	out, err := captureStdout(t, func() error { return runOutpostsList(outpostsListCmd, nil) })
	require.NoError(t, err)
	require.Contains(t, out, "eu")
	require.Contains(t, out, "out-1")
}
