package cmd

// CLI reference: docs/reference/cli.md (Authentication section)
// Architecture: docs/architecture/authentication.md

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var (
	loginProvider string
	loginNoBrowser bool
)

var loginCmd = &cobra.Command{
	Use:   "login",
	Short: "Authenticate with the BAMF cluster",
	Long: `Authenticate with the BAMF cluster using SSO or local credentials.

For SSO login, this command starts a local HTTP server, opens your browser
to the identity provider, and waits for the authentication callback.

Examples:
  # Login with default SSO provider
  bamf login

  # Login with a specific provider
  bamf login --provider okta

  # Login without opening browser (prints URL)
  bamf login --no-browser`,
	RunE: runLogin,
}

func init() {
	rootCmd.AddCommand(loginCmd)
	loginCmd.Flags().StringVar(&loginProvider, "provider", "", "SSO provider name (default: cluster default)")
	loginCmd.Flags().BoolVar(&loginNoBrowser, "no-browser", false, "print login URL instead of opening browser")
}

func runLogin(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Ensure .bamf directory exists
	bamfPath, err := ensureBamfDir()
	if err != nil {
		return err
	}

	// Generate PKCE code verifier and challenge
	verifier, challenge, err := generatePKCE()
	if err != nil {
		return fmt.Errorf("failed to generate PKCE: %w", err)
	}

	// Generate state parameter
	state, err := generateState()
	if err != nil {
		return fmt.Errorf("failed to generate state: %w", err)
	}

	// Start local callback server
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("failed to start callback server: %w", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port
	callbackURL := fmt.Sprintf("http://127.0.0.1:%d/callback", port)

	// Build authorization URL
	authURL, err := buildAuthURL(callbackURL, challenge, state)
	if err != nil {
		return err
	}

	// Channel to receive auth result
	resultCh := make(chan authResult, 1)

	// Start callback server
	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handleCallback(w, r, state, resultCh)
		}),
	}

	go func() {
		if err := server.Serve(listener); err != http.ErrServerClosed {
			resultCh <- authResult{err: fmt.Errorf("callback server error: %w", err)}
		}
	}()

	// Open browser or print URL
	if loginNoBrowser {
		fmt.Printf("Open this URL in your browser to login:\n\n%s\n\n", authURL)
	} else {
		fmt.Println("Opening browser for authentication...")
		if err := openBrowser(authURL); err != nil {
			fmt.Printf("Failed to open browser. Please visit:\n\n%s\n\n", authURL)
		}
	}

	fmt.Println("Waiting for authentication...")

	// Wait for callback or timeout
	select {
	case result := <-resultCh:
		server.Shutdown(context.Background())
		if result.err != nil {
			return result.err
		}

		// Exchange authorization code for tokens
		tokens, err := exchangeCode(ctx, result.code, verifier, callbackURL)
		if err != nil {
			return fmt.Errorf("failed to exchange code: %w", err)
		}

		// Persist the API URL used for this login so subsequent commands
		// don't require --api or BAMF_API_URL.
		tokens.APIURL = resolveAPIURL()

		// Save credentials
		if err := saveCredentials(bamfPath, tokens); err != nil {
			return fmt.Errorf("failed to save credentials: %w", err)
		}

		fmt.Printf("Login successful! Logged in as %s\n", tokens.Email)
		if len(tokens.Roles) > 0 {
			fmt.Printf("Roles: %s\n", strings.Join(tokens.Roles, ", "))
		}
		return nil

	case <-ctx.Done():
		server.Shutdown(context.Background())
		return fmt.Errorf("login timed out")
	}
}

type authResult struct {
	code string
	err  error
}

type tokenResponse struct {
	SessionToken string    `json:"session_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	Email        string    `json:"email"`
	Roles        []string  `json:"roles"`
	APIURL       string    `json:"api_url,omitempty"`
}

func generatePKCE() (verifier, challenge string, err error) {
	// Generate 32 random bytes for verifier
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(buf)

	// SHA256 hash for challenge
	h := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(h[:])

	return verifier, challenge, nil
}

func generateState() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// resolveAPIURL returns the API URL from flag, env var, or saved credentials.
func resolveAPIURL() string {
	if apiURL != "" {
		return apiURL
	}
	if v := os.Getenv("BAMF_API_URL"); v != "" {
		return v
	}
	// Fall back to saved credentials
	creds, err := loadCredentials()
	if err == nil && creds.APIURL != "" {
		return creds.APIURL
	}
	return ""
}

func buildAuthURL(callbackURL, challenge, state string) (string, error) {
	api := resolveAPIURL()
	if api == "" {
		return "", fmt.Errorf("API URL not configured. Use --api flag or set BAMF_API_URL")
	}

	u, err := url.Parse(api)
	if err != nil {
		return "", fmt.Errorf("invalid API URL: %w", err)
	}

	u.Path = "/api/v1/auth/authorize"
	q := u.Query()
	q.Set("redirect_uri", callbackURL)
	q.Set("code_challenge", challenge)
	q.Set("code_challenge_method", "S256")
	q.Set("state", state)
	q.Set("response_type", "code")
	if loginProvider != "" {
		q.Set("provider", loginProvider)
	}
	u.RawQuery = q.Encode()

	return u.String(), nil
}

func handleCallback(w http.ResponseWriter, r *http.Request, expectedState string, resultCh chan<- authResult) {
	if r.URL.Path != "/callback" {
		http.NotFound(w, r)
		return
	}

	// Check for error
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		errDesc := r.URL.Query().Get("error_description")
		resultCh <- authResult{err: fmt.Errorf("authentication error: %s - %s", errMsg, errDesc)}
		http.Error(w, "Authentication failed", http.StatusBadRequest)
		return
	}

	// Validate state
	state := r.URL.Query().Get("state")
	if state != expectedState {
		resultCh <- authResult{err: fmt.Errorf("invalid state parameter")}
		http.Error(w, "Invalid state", http.StatusBadRequest)
		return
	}

	// Get authorization code
	code := r.URL.Query().Get("code")
	if code == "" {
		resultCh <- authResult{err: fmt.Errorf("no authorization code received")}
		http.Error(w, "No code received", http.StatusBadRequest)
		return
	}

	// Send success response to browser
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head><title>BAMF Login</title></head>
<body style="font-family: system-ui; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0;">
<div style="text-align: center;">
<h1>Authentication Successful</h1>
<p>You may close this tab and return to the terminal.</p>
</div>
</body>
</html>`)

	resultCh <- authResult{code: code}
}

func exchangeCode(ctx context.Context, code, verifier, callbackURL string) (*tokenResponse, error) {
	api := resolveAPIURL()
	if api == "" {
		return nil, fmt.Errorf("API URL not configured. Use --api flag or set BAMF_API_URL")
	}

	u, err := url.Parse(api)
	if err != nil {
		return nil, err
	}
	u.Path = "/api/v1/auth/token"

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("code_verifier", verifier)
	data.Set("redirect_uri", callbackURL)

	req, err := http.NewRequestWithContext(ctx, "POST", u.String(), strings.NewReader(data.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange failed: %s", resp.Status)
	}

	var tokens tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokens); err != nil {
		return nil, err
	}

	return &tokens, nil
}

func saveCredentials(bamfPath string, tokens *tokenResponse) error {
	credsFile := filepath.Join(bamfPath, "credentials.json")

	data, err := json.MarshalIndent(tokens, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(credsFile, data, 0600)
}

func openBrowser(url string) error {
	var cmd *exec.Cmd

	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "linux":
		cmd = exec.Command("xdg-open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		return fmt.Errorf("unsupported platform")
	}

	return cmd.Start()
}
