package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ── Tests: loadCredentials edge cases ───────────────────────────────

func TestLoadCredentials_EmptyFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), []byte(""), 0600))

	_, err := loadCredentials()
	require.Error(t, err)
}

func TestLoadCredentials_PartialJSON(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), []byte(`{"session_token":"tok"`), 0600))

	_, err := loadCredentials()
	require.Error(t, err) // malformed JSON
}

func TestLoadCredentials_WithAllFields(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))

	expiresAt := time.Date(2027, 6, 15, 12, 0, 0, 0, time.UTC)
	creds := tokenResponse{
		SessionToken: "tok-xyz",
		ExpiresAt:    expiresAt,
		Email:        "bob@example.com",
		Roles:        []string{"admin", "developer"},
		APIURL:       "https://bamf.corp.com",
	}
	data, err := json.MarshalIndent(creds, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), data, 0600))

	loaded, err := loadCredentials()
	require.NoError(t, err)
	require.Equal(t, "tok-xyz", loaded.SessionToken)
	require.Equal(t, "bob@example.com", loaded.Email)
	require.Equal(t, []string{"admin", "developer"}, loaded.Roles)
	require.Equal(t, "https://bamf.corp.com", loaded.APIURL)
	require.Equal(t, expiresAt, loaded.ExpiresAt)
}

func TestLoadCredentials_NullValues(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))

	// JSON with null roles — should deserialize as nil slice
	creds := `{"session_token":"tok","expires_at":"2027-01-01T00:00:00Z","email":"a@b.com","roles":null}`
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), []byte(creds), 0600))

	loaded, err := loadCredentials()
	require.NoError(t, err)
	require.Nil(t, loaded.Roles)
}

func TestLoadCredentials_ExtraFields(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))

	// JSON with extra fields — should not error (Go JSON unmarshalling ignores extra fields)
	creds := `{"session_token":"tok","expires_at":"2027-01-01T00:00:00Z","email":"a@b.com","unknown_field":"value"}`
	require.NoError(t, os.WriteFile(filepath.Join(bamfPath, "credentials.json"), []byte(creds), 0600))

	loaded, err := loadCredentials()
	require.NoError(t, err)
	require.Equal(t, "tok", loaded.SessionToken)
}

// ── Tests: saveCredentials ──────────────────────────────────────────

func TestSaveCredentials_WritesFile(t *testing.T) {
	bamfPath := filepath.Join(t.TempDir(), ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))

	expiresAt := time.Date(2027, 3, 15, 10, 30, 0, 0, time.UTC)
	tokens := &tokenResponse{
		SessionToken: "session-abc-123",
		ExpiresAt:    expiresAt,
		Email:        "alice@example.com",
		Roles:        []string{"admin", "sre"},
		APIURL:       "https://bamf.example.com",
	}

	err := saveCredentials(bamfPath, tokens)
	require.NoError(t, err)

	// Verify file exists with correct permissions
	credsFile := filepath.Join(bamfPath, "credentials.json")
	info, err := os.Stat(credsFile)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0600), info.Mode().Perm())

	// Verify content
	data, err := os.ReadFile(credsFile)
	require.NoError(t, err)

	var loaded tokenResponse
	require.NoError(t, json.Unmarshal(data, &loaded))
	require.Equal(t, "session-abc-123", loaded.SessionToken)
	require.Equal(t, "alice@example.com", loaded.Email)
	require.Equal(t, []string{"admin", "sre"}, loaded.Roles)
	require.Equal(t, "https://bamf.example.com", loaded.APIURL)
	require.Equal(t, expiresAt, loaded.ExpiresAt)
}

func TestSaveCredentials_Overwrite(t *testing.T) {
	bamfPath := filepath.Join(t.TempDir(), ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))

	// Write first credentials
	tokens1 := &tokenResponse{
		SessionToken: "first-token",
		ExpiresAt:    time.Now().Add(1 * time.Hour),
		Email:        "first@example.com",
	}
	require.NoError(t, saveCredentials(bamfPath, tokens1))

	// Overwrite with second credentials
	tokens2 := &tokenResponse{
		SessionToken: "second-token",
		ExpiresAt:    time.Now().Add(2 * time.Hour),
		Email:        "second@example.com",
	}
	require.NoError(t, saveCredentials(bamfPath, tokens2))

	// Verify second credentials are stored
	data, err := os.ReadFile(filepath.Join(bamfPath, "credentials.json"))
	require.NoError(t, err)

	var loaded tokenResponse
	require.NoError(t, json.Unmarshal(data, &loaded))
	require.Equal(t, "second-token", loaded.SessionToken)
	require.Equal(t, "second@example.com", loaded.Email)
}

func TestSaveCredentials_PrettyPrinted(t *testing.T) {
	bamfPath := filepath.Join(t.TempDir(), ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))

	tokens := &tokenResponse{
		SessionToken: "tok",
		ExpiresAt:    time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
		Email:        "a@b.com",
	}
	require.NoError(t, saveCredentials(bamfPath, tokens))

	data, err := os.ReadFile(filepath.Join(bamfPath, "credentials.json"))
	require.NoError(t, err)

	// MarshalIndent with 2-space indent should produce multi-line output
	require.Contains(t, string(data), "\n")
	require.Contains(t, string(data), "  ")
}

func TestSaveCredentials_InvalidPath(t *testing.T) {
	err := saveCredentials("/nonexistent/path/that/does/not/exist", &tokenResponse{})
	require.Error(t, err)
}

// ── Tests: saveCredentials + loadCredentials roundtrip ───────────────

func TestCredentialsRoundTrip(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	bamfPath := filepath.Join(home, ".bamf")
	require.NoError(t, os.MkdirAll(bamfPath, 0700))

	original := &tokenResponse{
		SessionToken: "round-trip-token",
		ExpiresAt:    time.Date(2027, 6, 15, 12, 30, 0, 0, time.UTC),
		Email:        "rt@example.com",
		Roles:        []string{"admin"},
		APIURL:       "https://rt.bamf.example.com",
	}

	require.NoError(t, saveCredentials(bamfPath, original))

	loaded, err := loadCredentials()
	require.NoError(t, err)
	require.Equal(t, original.SessionToken, loaded.SessionToken)
	require.Equal(t, original.Email, loaded.Email)
	require.Equal(t, original.Roles, loaded.Roles)
	require.Equal(t, original.APIURL, loaded.APIURL)
	require.Equal(t, original.ExpiresAt, loaded.ExpiresAt)
}

// ── Tests: tokenResponse JSON marshaling ────────────────────────────

func TestTokenResponse_JSONTags(t *testing.T) {
	tr := tokenResponse{
		SessionToken: "abc",
		ExpiresAt:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Email:        "test@example.com",
		Roles:        []string{"admin"},
		APIURL:       "https://bamf.example.com",
	}

	data, err := json.Marshal(tr)
	require.NoError(t, err)

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &raw))

	// Verify field names match JSON tags
	_, ok := raw["session_token"]
	require.True(t, ok, "expected session_token field")

	_, ok = raw["expires_at"]
	require.True(t, ok, "expected expires_at field")

	_, ok = raw["email"]
	require.True(t, ok, "expected email field")

	_, ok = raw["roles"]
	require.True(t, ok, "expected roles field")

	_, ok = raw["api_url"]
	require.True(t, ok, "expected api_url field")
}

func TestTokenResponse_OmitsEmptyAPIURL(t *testing.T) {
	tr := tokenResponse{
		SessionToken: "abc",
		ExpiresAt:    time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Email:        "test@example.com",
	}

	data, err := json.Marshal(tr)
	require.NoError(t, err)

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &raw))

	// api_url has omitempty so it should not be present when empty
	_, ok := raw["api_url"]
	require.False(t, ok, "api_url should be omitted when empty")
}

// ── Tests: handleCallback ───────────────────────────────────────────

func TestHandleCallback_Success(t *testing.T) {
	resultCh := make(chan authResult, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleCallback(w, r, "test-state", resultCh)
	})

	req := httptest.NewRequest("GET", "/callback?code=auth-code-123&state=test-state", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	require.Contains(t, w.Body.String(), "Authentication Successful")

	result := <-resultCh
	require.NoError(t, result.err)
	require.Equal(t, "auth-code-123", result.code)
}

func TestHandleCallback_InvalidState(t *testing.T) {
	resultCh := make(chan authResult, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleCallback(w, r, "expected-state", resultCh)
	})

	req := httptest.NewRequest("GET", "/callback?code=code&state=wrong-state", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)

	result := <-resultCh
	require.Error(t, result.err)
	require.Contains(t, result.err.Error(), "invalid state")
}

func TestHandleCallback_NoCode(t *testing.T) {
	resultCh := make(chan authResult, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleCallback(w, r, "test-state", resultCh)
	})

	req := httptest.NewRequest("GET", "/callback?state=test-state", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)

	result := <-resultCh
	require.Error(t, result.err)
	require.Contains(t, result.err.Error(), "no authorization code")
}

func TestHandleCallback_ErrorFromProvider(t *testing.T) {
	resultCh := make(chan authResult, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleCallback(w, r, "test-state", resultCh)
	})

	req := httptest.NewRequest("GET", "/callback?error=access_denied&error_description=User+cancelled", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusBadRequest, w.Code)

	result := <-resultCh
	require.Error(t, result.err)
	require.Contains(t, result.err.Error(), "access_denied")
	require.Contains(t, result.err.Error(), "User cancelled")
}

func TestHandleCallback_WrongPath(t *testing.T) {
	resultCh := make(chan authResult, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handleCallback(w, r, "test-state", resultCh)
	})

	req := httptest.NewRequest("GET", "/wrong-path?code=abc&state=test-state", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusNotFound, w.Code)

	// Channel should be empty (nothing sent)
	select {
	case <-resultCh:
		t.Fatal("did not expect a result on wrong path")
	default:
	}
}

// ── Tests: exchangeCode ─────────────────────────────────────────────

func TestExchangeCode_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/v1/auth/token", r.URL.Path)
		require.Equal(t, "POST", r.Method)
		require.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		require.NoError(t, r.ParseForm())
		require.Equal(t, "authorization_code", r.Form.Get("grant_type"))
		require.Equal(t, "the-code", r.Form.Get("code"))
		require.Equal(t, "the-verifier", r.Form.Get("code_verifier"))
		require.Equal(t, "http://127.0.0.1:12345/callback", r.Form.Get("redirect_uri"))

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(tokenResponse{
			SessionToken: "new-session",
			ExpiresAt:    time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC),
			Email:        "alice@example.com",
			Roles:        []string{"admin"},
		})
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	tokens, err := exchangeCode(context.Background(), "the-code", "the-verifier", "http://127.0.0.1:12345/callback")
	require.NoError(t, err)
	require.Equal(t, "new-session", tokens.SessionToken)
	require.Equal(t, "alice@example.com", tokens.Email)
	require.Equal(t, []string{"admin"}, tokens.Roles)
}

func TestExchangeCode_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	_, err := exchangeCode(context.Background(), "code", "verifier", "http://localhost/callback")
	require.Error(t, err)
	require.Contains(t, err.Error(), "token exchange failed")
}

func TestExchangeCode_NoAPIURL(t *testing.T) {
	t.Setenv("BAMF_API_URL", "")
	t.Setenv("HOME", t.TempDir())

	oldAPIURL := apiURL
	apiURL = ""
	defer func() { apiURL = oldAPIURL }()

	_, err := exchangeCode(context.Background(), "code", "verifier", "http://localhost/callback")
	require.Error(t, err)
	require.Contains(t, err.Error(), "API URL not configured")
}

// ── Tests: requestConnect edge cases ────────────────────────────────

func TestRequestConnect_RateLimitedExhausted(t *testing.T) {
	// All attempts return 429 — should eventually fail
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	creds := &tokenResponse{SessionToken: "token"}
	_, err := requestConnect(context.Background(), creds, "res", "")
	require.Error(t, err)
	// After maxConnectRetries (3) retries are exhausted, the final 429 falls
	// through to the generic status check which returns "API error: 429 ..."
	require.Contains(t, err.Error(), "429")
	// Should have tried 4 times (initial + 3 retries)
	require.Equal(t, 4, attempts)
}

func TestRequestConnect_ContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Delay long enough for context to be cancelled
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	creds := &tokenResponse{SessionToken: "token"}
	_, err := requestConnect(ctx, creds, "res", "")
	require.Error(t, err)
}

func TestRequestConnect_UnexpectedStatusCode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		fmt.Fprint(w, `{"detail":"upstream error"}`)
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	creds := &tokenResponse{SessionToken: "token"}
	_, err := requestConnect(context.Background(), creds, "res", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "API error")
}

func TestRequestConnect_InvalidResponseJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `not valid json`)
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	creds := &tokenResponse{SessionToken: "token"}
	_, err := requestConnect(context.Background(), creds, "res", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse response")
}

func TestRequestConnect_ServiceUnavailableInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, `not json at all`)
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	creds := &tokenResponse{SessionToken: "token"}
	_, err := requestConnect(context.Background(), creds, "res", "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "service unavailable")
	require.Contains(t, err.Error(), "not json at all")
}

func TestRequestConnect_RateLimitWithRetryAfterHeader(t *testing.T) {
	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		if attempts <= 1 {
			w.Header().Set("Retry-After", "1") // 1 second
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_ = json.NewEncoder(w).Encode(ConnectResponse{SessionID: "success"})
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	creds := &tokenResponse{SessionToken: "token"}
	result, err := requestConnect(context.Background(), creds, "res", "")
	require.NoError(t, err)
	require.Equal(t, "success", result.SessionID)
	require.Equal(t, 2, attempts)
}

// ── Tests: ConnectResponse fields ───────────────────────────────────

func TestConnectResponse_EmptyResourceType(t *testing.T) {
	cr := ConnectResponse{
		SessionID: "test",
	}
	data, err := json.Marshal(cr)
	require.NoError(t, err)

	var decoded ConnectResponse
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Equal(t, "", decoded.ResourceType)
}

func TestConnectResponse_AllResourceTypes(t *testing.T) {
	types := []string{"ssh", "ssh-audit", "postgres", "postgres-audit", "mysql", "mysql-audit", "http", "kubernetes"}

	for _, rt := range types {
		t.Run(rt, func(t *testing.T) {
			cr := ConnectResponse{
				SessionID:    "test-" + rt,
				ResourceType: rt,
			}
			data, err := json.Marshal(cr)
			require.NoError(t, err)

			var decoded ConnectResponse
			require.NoError(t, json.Unmarshal(data, &decoded))
			require.Equal(t, rt, decoded.ResourceType)
		})
	}
}

// ── Tests: revokeServerSession ──────────────────────────────────────

func TestRevokeServerSession_NoAPIURL(t *testing.T) {
	t.Setenv("BAMF_API_URL", "")
	t.Setenv("HOME", t.TempDir())

	oldAPIURL := apiURL
	apiURL = ""
	defer func() { apiURL = oldAPIURL }()

	// Should not panic — just a no-op
	revokeServerSession("some-token")
}

func TestRevokeServerSession_Success(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		require.Equal(t, "/api/v1/auth/logout", r.URL.Path)
		require.Equal(t, "POST", r.Method)
		require.Equal(t, "Bearer test-token", r.Header.Get("Authorization"))
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	revokeServerSession("test-token")
	require.True(t, called)
}

func TestRevokeServerSession_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	t.Setenv("BAMF_API_URL", srv.URL)

	// Should not panic or return error — errors are logged to stderr
	revokeServerSession("test-token")
}
