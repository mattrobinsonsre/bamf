package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show current authentication status",
	Long: `Display information about the current authentication state.

Shows:
  - Whether you are logged in
  - Current user identity
  - Token expiration time
  - Connected cluster`,
	RunE: runStatus,
}

func init() {
	rootCmd.AddCommand(statusCmd)
}

func runStatus(cmd *cobra.Command, args []string) error {
	bamfPath, err := bamfDir()
	if err != nil {
		return err
	}

	credsFile := filepath.Join(bamfPath, "credentials.json")
	data, err := os.ReadFile(credsFile)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Println("Not logged in. Run 'bamf login' to authenticate.")
			return nil
		}
		return fmt.Errorf("failed to read credentials: %w", err)
	}

	var creds tokenResponse
	if err := json.Unmarshal(data, &creds); err != nil {
		return fmt.Errorf("invalid credentials file: %w", err)
	}

	if jsonOutput {
		status := map[string]interface{}{
			"logged_in":  true,
			"user":       creds.Email,
			"roles":      creds.Roles,
			"expires_at": creds.ExpiresAt.Format(time.RFC3339),
			"expired":    time.Now().After(creds.ExpiresAt),
		}
		out, _ := json.MarshalIndent(status, "", "  ")
		fmt.Println(string(out))
	} else {
		fmt.Printf("Logged in as: %s\n", creds.Email)
		if len(creds.Roles) > 0 {
			fmt.Printf("Roles: %s\n", strings.Join(creds.Roles, ", "))
		}
		if time.Now().After(creds.ExpiresAt) {
			fmt.Printf("Session expired: %s\n", creds.ExpiresAt.Format(time.RFC3339))
			fmt.Println("Run 'bamf login' to refresh your credentials.")
		} else {
			fmt.Printf("Session expires: %s\n", creds.ExpiresAt.Format(time.RFC3339))
			remaining := time.Until(creds.ExpiresAt).Round(time.Minute)
			fmt.Printf("Time remaining: %s\n", remaining)
		}
	}

	return nil
}
