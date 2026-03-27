package cmd

import (
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGeneratePKCE(t *testing.T) {
	verifier, challenge, err := generatePKCE()
	require.NoError(t, err)

	// Verifier is base64url-encoded 32 bytes = 43 chars
	require.Len(t, verifier, 43)

	// Challenge is SHA256 of verifier, base64url-encoded = 43 chars
	require.Len(t, challenge, 43)

	// Verify challenge = base64url(sha256(verifier))
	h := sha256.Sum256([]byte(verifier))
	expected := base64.RawURLEncoding.EncodeToString(h[:])
	require.Equal(t, expected, challenge)
}

func TestGeneratePKCE_Unique(t *testing.T) {
	v1, _, err := generatePKCE()
	require.NoError(t, err)
	v2, _, err := generatePKCE()
	require.NoError(t, err)
	require.NotEqual(t, v1, v2, "two PKCE verifiers should be different")
}

func TestGenerateState(t *testing.T) {
	state, err := generateState()
	require.NoError(t, err)

	// base64url-encoded 16 bytes = 22 chars
	require.Len(t, state, 22)
}

func TestGenerateState_Unique(t *testing.T) {
	s1, err := generateState()
	require.NoError(t, err)
	s2, err := generateState()
	require.NoError(t, err)
	require.NotEqual(t, s1, s2)
}

func TestBuildAuthURL(t *testing.T) {
	// Set API URL via env var for this test
	t.Setenv("BAMF_API_URL", "https://bamf.example.com")
	// Reset the global flags
	oldProvider := loginProvider
	loginProvider = ""
	defer func() { loginProvider = oldProvider }()

	authURL, err := buildAuthURL("http://127.0.0.1:12345/callback", "test-challenge", "test-state")
	require.NoError(t, err)

	u, err := url.Parse(authURL)
	require.NoError(t, err)

	require.Equal(t, "https", u.Scheme)
	require.Equal(t, "bamf.example.com", u.Host)
	require.Equal(t, "/api/v1/auth/authorize", u.Path)

	q := u.Query()
	require.Equal(t, "http://127.0.0.1:12345/callback", q.Get("redirect_uri"))
	require.Equal(t, "test-challenge", q.Get("code_challenge"))
	require.Equal(t, "S256", q.Get("code_challenge_method"))
	require.Equal(t, "test-state", q.Get("state"))
	require.Equal(t, "code", q.Get("response_type"))
	require.Empty(t, q.Get("provider"))
}

func TestBuildAuthURL_WithProvider(t *testing.T) {
	t.Setenv("BAMF_API_URL", "https://bamf.example.com")
	oldProvider := loginProvider
	loginProvider = "auth0"
	defer func() { loginProvider = oldProvider }()

	authURL, err := buildAuthURL("http://127.0.0.1:12345/callback", "challenge", "state")
	require.NoError(t, err)

	u, err := url.Parse(authURL)
	require.NoError(t, err)
	require.Equal(t, "auth0", u.Query().Get("provider"))
}

func TestBuildAuthURL_MissingAPIURL(t *testing.T) {
	// Unset all API URL sources
	t.Setenv("BAMF_API_URL", "")
	oldAPIURL := apiURL
	apiURL = ""
	defer func() { apiURL = oldAPIURL }()

	// Override HOME to prevent loading credentials
	t.Setenv("HOME", t.TempDir())

	_, err := buildAuthURL("http://localhost/callback", "challenge", "state")
	require.Error(t, err)
	require.Contains(t, err.Error(), "API URL not configured")
}

func TestLoadCredentials_NotFound(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	_, err := loadCredentials()
	require.Error(t, err)
}

func TestLoadCredentials_InvalidJSON(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	bamfDir := home + "/.bamf"
	require.NoError(t, os.MkdirAll(bamfDir, 0700))
	require.NoError(t, os.WriteFile(bamfDir+"/credentials.json", []byte("not json"), 0600))

	_, err := loadCredentials()
	require.Error(t, err)
}

func TestLoadCredentials_Valid(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	bamfDir := home + "/.bamf"
	require.NoError(t, os.MkdirAll(bamfDir, 0700))
	creds := `{"session_token":"abc123","api_url":"https://bamf.example.com","expires_at":"2027-01-01T00:00:00Z"}`
	require.NoError(t, os.WriteFile(bamfDir+"/credentials.json", []byte(creds), 0600))

	resp, err := loadCredentials()
	require.NoError(t, err)
	require.Equal(t, "abc123", resp.SessionToken)
	require.Equal(t, "https://bamf.example.com", resp.APIURL)
}
