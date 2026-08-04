// BAMF Bridge Server - Routes client connections to agents
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

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

	// Context for graceful shutdown. Set up signal handling first so the
	// bootstrap retry below can be interrupted.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Create the bridge server, retrying bootstrap on transient failure rather
	// than exiting. On a fresh install or rolling restart the API may not be
	// reachable yet; exiting here crashloops the pod. Retry until it comes up.
	var srv *bridge.Server
	for {
		srv, err = bridge.NewServer(cfg, logger)
		if err == nil {
			break
		}
		slog.Warn("failed to create bridge server, retrying", "error", err)
		select {
		case sig := <-sigCh:
			slog.Info("received shutdown signal during bootstrap", "signal", sig)
			os.Exit(0)
		case <-time.After(2 * time.Second):
		}
	}

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
