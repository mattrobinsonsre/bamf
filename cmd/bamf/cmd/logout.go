package cmd

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"
)

var logoutCmd = &cobra.Command{
	Use:   "logout",
	Short: "Log out and clear local credentials",
	Long: `Revoke the current session on the server and remove local credentials.

This command:
  - Revokes the session on the BAMF server
  - Removes stored session tokens
  - Removes cached certificates`,
	RunE: runLogout,
}

func init() {
	rootCmd.AddCommand(logoutCmd)
}

func runLogout(cmd *cobra.Command, args []string) error {
	bamfPath, err := bamfDir()
	if err != nil {
		return err
	}

	// Try to revoke session server-side
	creds, err := loadCredentials()
	if err == nil && creds.SessionToken != "" {
		revokeServerSession(creds.SessionToken)
	}

	// Remove credentials file
	credsFile := filepath.Join(bamfPath, "credentials.json")
	if err := os.Remove(credsFile); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to remove credentials: %w", err)
	}

	// Remove all keys
	keysDir := filepath.Join(bamfPath, "keys")
	entries, err := os.ReadDir(keysDir)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("failed to read keys directory: %w", err)
	}

	for _, entry := range entries {
		if err := os.Remove(filepath.Join(keysDir, entry.Name())); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to remove %s: %v\n", entry.Name(), err)
		}
	}

	fmt.Println("Logged out successfully.")
	return nil
}

// revokeServerSession calls POST /auth/logout to revoke the session server-side.
// Errors are logged but don't block local cleanup.
func revokeServerSession(sessionToken string) {
	api := resolveAPIURL()
	if api == "" {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	u, err := url.Parse(api)
	if err != nil {
		return
	}
	u.Path = "/api/v1/auth/logout"

	req, err := http.NewRequestWithContext(ctx, "POST", u.String(), nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+sessionToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to revoke server session: %v\n", err)
		return
	}
	resp.Body.Close()
}
