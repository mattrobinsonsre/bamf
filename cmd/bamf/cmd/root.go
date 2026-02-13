package cmd

// CLI reference: docs/reference/cli.md

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var (
	// Global flags
	cfgFile    string
	apiURL     string
	debug      bool
	jsonOutput bool

	// Version info (set at build time)
	Version   = "dev"
	GitCommit = "unknown"
	BuildTime = "unknown"
)

var rootCmd = &cobra.Command{
	Use:   "bamf",
	Short: "BAMF - Bridge Access Management Fabric",
	Long: `BAMF is an open-source secure infrastructure access platform.

It provides secure access to SSH servers, Kubernetes clusters,
databases, and web applications with short-lived certificates
and centralized audit logging.`,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ~/.bamf/config.yaml)")
	rootCmd.PersistentFlags().StringVar(&apiURL, "api", "", "BAMF API server URL")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "enable debug logging")
	rootCmd.PersistentFlags().BoolVar(&jsonOutput, "json", false, "output in JSON format")
}

func initConfig() {
	if cfgFile != "" {
		return
	}

	// Default config location
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: cannot determine home directory: %v\n", err)
		return
	}

	cfgFile = filepath.Join(home, ".bamf", "config.yaml")
}

// bamfDir returns the path to the .bamf directory
func bamfDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}
	return filepath.Join(home, ".bamf"), nil
}

// ensureBamfDir creates the .bamf directory if it doesn't exist
func ensureBamfDir() (string, error) {
	dir, err := bamfDir()
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", fmt.Errorf("cannot create .bamf directory: %w", err)
	}

	// Also create keys subdirectory
	keysDir := filepath.Join(dir, "keys")
	if err := os.MkdirAll(keysDir, 0700); err != nil {
		return "", fmt.Errorf("cannot create keys directory: %w", err)
	}

	return dir, nil
}
