// BAMF Agent - Deployed alongside target resources
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/mattrobinsonsre/bamf/pkg/agent"
)

func main() {
	// Parse flags
	configFile := flag.String("config", "", "Path to agent config file (overrides $BAMF_CONFIG_FILE)")
	debug := flag.Bool("debug", false, "Enable debug logging")
	flag.Parse()

	// Initialize structured logging
	logLevel := slog.LevelInfo
	if *debug || os.Getenv("BAMF_DEBUG") == "true" {
		logLevel = slog.LevelDebug
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	// Set config file env var if --config flag was provided.
	// This feeds into LoadConfig's YAML file search.
	if *configFile != "" {
		os.Setenv("BAMF_CONFIG_FILE", *configFile)
	}

	// Load configuration (defaults → YAML → env vars)
	cfg, err := agent.LoadConfig()
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Create agent
	ag, err := agent.New(cfg, logger)
	if err != nil {
		slog.Error("failed to create agent", "error", err)
		os.Exit(1)
	}

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Start agent
	errCh := make(chan error, 1)
	go func() {
		slog.Info("starting BAMF agent",
			"name", cfg.AgentName,
			"api_url", cfg.APIServerURL,
			"resources", len(cfg.Resources),
		)
		errCh <- ag.Run(ctx)
	}()

	// Wait for shutdown signal or error
	select {
	case sig := <-sigCh:
		slog.Info("received shutdown signal", "signal", sig)
		cancel()

		if err := ag.Shutdown(context.Background()); err != nil {
			slog.Error("shutdown error", "error", err)
			os.Exit(1)
		}
		slog.Info("agent stopped gracefully")

	case err := <-errCh:
		if err != nil {
			slog.Error("agent error", "error", err)
			os.Exit(1)
		}
	}
}
