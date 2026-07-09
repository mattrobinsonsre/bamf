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

// writeEdgeTestCreds writes a credentials.json into a temp HOME and returns
// nothing — callers set BAMF_API_URL to their test server.
func writeEdgeTestCreds(t *testing.T) {
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

func TestRunEdgeTokensList_NoCredentials(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	err := runEdgeTokensList(edgeTokensListCmd, nil)
	require.Error(t, err)
}

func TestRunEdgeTokensList_Success(t *testing.T) {
	writeEdgeTestCreds(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/edge-tokens", r.URL.Path)
		require.Equal(t, "GET", r.Method)
		require.Equal(t, "Bearer tok", r.Header.Get("Authorization"))
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items": []edgeToken{{
				Name: "eu-token", EdgeName: "eu", UseCount: 1,
				ExpiresAt: time.Now().Add(24 * time.Hour), CreatedBy: "admin@example.com",
			}},
		})
	}))
	defer srv.Close()
	t.Setenv("BAMF_API_URL", srv.URL)

	out, err := captureStdout(t, func() error { return runEdgeTokensList(edgeTokensListCmd, nil) })
	require.NoError(t, err)
	require.Contains(t, out, "eu-token")
	require.Contains(t, out, "eu")
}

func TestRunEdgeTokensCreate_Success(t *testing.T) {
	writeEdgeTestCreds(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/edge-tokens", r.URL.Path)
		require.Equal(t, "POST", r.Method)
		var body map[string]any
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		require.Equal(t, "eu-token", body["name"])
		require.Equal(t, "eu", body["edge_name"])
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"name": "eu-token", "edge_name": "eu", "token": "bamf_edge_secret",
			"expires_at": time.Now().Add(24 * time.Hour), "use_count": 0,
			"created_by": "admin@example.com",
		})
	}))
	defer srv.Close()
	t.Setenv("BAMF_API_URL", srv.URL)

	edgeTokenEdge = "eu"
	defer func() { edgeTokenEdge = "" }()

	out, err := captureStdout(t, func() error { return runEdgeTokensCreate(edgeTokensCreateCmd, []string{"eu-token"}) })
	require.NoError(t, err)
	require.Contains(t, out, "bamf_edge_secret")
	require.True(t, strings.Contains(out, "only once"))
}

func TestRunEdgesList_Success(t *testing.T) {
	writeEdgeTestCreds(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/edges", r.URL.Path)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items": []edgeInfo{{ID: "out-1", Name: "eu", IsActive: true}},
		})
	}))
	defer srv.Close()
	t.Setenv("BAMF_API_URL", srv.URL)

	out, err := captureStdout(t, func() error { return runEdgesList(edgesListCmd, nil) })
	require.NoError(t, err)
	require.Contains(t, out, "eu")
	require.Contains(t, out, "out-1")
}
