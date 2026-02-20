// BAMF Bridge Server - Routes client connections to agents
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/mattrobinsonsre/bamf/pkg/bridge"
)

func main() {
	// Initialize structured logging
	logLevel := slog.LevelInfo
	if os.Getenv("BAMF_DEBUG") == "true" {
		logLevel = slog.LevelDebug
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: logLevel,
	}))
	slog.SetDefault(logger)

	// Load configuration
	cfg, err := bridge.LoadConfig()
	if err != nil {
		slog.Error("failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Create bridge server
	srv, err := bridge.NewServer(cfg, logger)
	if err != nil {
		slog.Error("failed to create bridge server", "error", err)
		os.Exit(1)
	}

	// Context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle shutdown signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Start server
	errCh := make(chan error, 1)
	go func() {
		slog.Info("starting BAMF bridge server",
			"https_addr", cfg.HTTPSAddr,
			"tunnel_addr", cfg.TunnelAddr,
			"health_addr", cfg.HealthAddr,
		)
		errCh <- srv.Run(ctx)
	}()

	// Wait for shutdown signal or error
	select {
	case sig := <-sigCh:
		slog.Info("received shutdown signal", "signal", sig)
		cancel()

		// Graceful shutdown
		if err := srv.Shutdown(context.Background()); err != nil {
			slog.Error("shutdown error", "error", err)
			os.Exit(1)
		}
		slog.Info("bridge server stopped gracefully")

	case err := <-errCh:
		if err != nil {
			slog.Error("bridge server error", "error", err)
			cancel()

			// Graceful shutdown even on error (drain tunnels before exit)
			if shutdownErr := srv.Shutdown(context.Background()); shutdownErr != nil {
				slog.Error("shutdown error", "error", shutdownErr)
			}
			os.Exit(1)
		}
	}
}
