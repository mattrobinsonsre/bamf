package bridge

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds bridge server configuration
type Config struct {
	// Server addresses
	HTTPSAddr  string // Address for HTTPS/WebSocket (e.g., ":443")
	TunnelAddr string // Address for mTLS tunnel connections (e.g., ":8443")
	HealthAddr string // Address for health/ready endpoints (e.g., ":8080")

	// API server connection
	APIServerURL string // BAMF API server URL

	// TLS configuration
	TLSCertFile string // Path to TLS certificate
	TLSKeyFile  string // Path to TLS private key
	CACertFile  string // Path to CA certificate for mTLS

	// Bootstrap token for initial certificate request
	BootstrapToken string // Token for authenticating bootstrap request

	// Data directory for storing certificates
	DataDir string // Directory for certificate storage

	// Bridge identification
	BridgeID  string // Unique identifier for this bridge instance (e.g., "bamf-bridge-0")
	Ordinal   int    // StatefulSet ordinal extracted from pod name (e.g., 0, 1, 2)
	Hostname  string // Public SNI hostname for this bridge (e.g., "bridge-0.tunnel.bamf.local")

	// Timeouts
	TunnelSetupTimeout time.Duration // Max time to establish tunnel
	IdleTimeout        time.Duration // Idle connection timeout (0 = no timeout)
	ShutdownTimeout    time.Duration // Graceful shutdown timeout

	// Tunnel configuration
	TunnelDomain string // Base domain for SNI routing (e.g., "tunnel.bamf.example.com")
}

// LoadConfig loads configuration from environment variables
func LoadConfig() (*Config, error) {
	cfg := &Config{
		HTTPSAddr:  getEnvOrDefault("BAMF_HTTPS_ADDR", ":443"),
		TunnelAddr: getEnvOrDefault("BAMF_TUNNEL_ADDR", ":8443"),
		HealthAddr: getEnvOrDefault("BAMF_HEALTH_ADDR", ":8080"),

		APIServerURL: getEnvOrDefault("BAMF_API_URL", "http://localhost:8000"),

		TLSCertFile: getEnvOrDefault("BAMF_TLS_CERT", "/etc/bamf/tls/tls.crt"),
		TLSKeyFile:  getEnvOrDefault("BAMF_TLS_KEY", "/etc/bamf/tls/tls.key"),
		CACertFile:  getEnvOrDefault("BAMF_CA_CERT", "/etc/bamf/tls/ca.crt"),

		BridgeID: getEnvOrDefault("BAMF_BRIDGE_ID", ""),
		Hostname: getEnvOrDefault("BAMF_HOSTNAME", ""),

		TunnelSetupTimeout: getDurationEnvOrDefault("BAMF_TUNNEL_SETUP_TIMEOUT", 30*time.Second),
		IdleTimeout:        getDurationEnvOrDefault("BAMF_IDLE_TIMEOUT", 0),
		ShutdownTimeout:    getDurationEnvOrDefault("BAMF_SHUTDOWN_TIMEOUT", 90*time.Second),

		TunnelDomain: getEnvOrDefault("BAMF_TUNNEL_DOMAIN", ""),

		BootstrapToken: getEnvOrDefault("BAMF_BOOTSTRAP_TOKEN", ""),
		DataDir:        getEnvOrDefault("BAMF_DATA_DIR", "/var/lib/bamf/bridge"),
	}

	// Auto-generate bridge ID from hostname if not set
	if cfg.BridgeID == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("failed to get hostname: %w", err)
		}
		cfg.BridgeID = hostname
	}

	// Extract ordinal from pod name (e.g., "bamf-bridge-0" -> 0)
	// StatefulSet pods have names ending in -{ordinal}
	cfg.Ordinal = extractOrdinal(cfg.BridgeID)

	// Validate required fields
	if cfg.TunnelDomain == "" {
		return nil, fmt.Errorf("BAMF_TUNNEL_DOMAIN is required")
	}

	// Generate SNI hostname from ordinal and tunnel domain
	// Format: {ordinal}.bridge.{tunnelDomain} (e.g., "0.bridge.tunnel.bamf.local")
	// The "bridge." subdomain separates bridge SNI from web app hostnames.
	if cfg.Hostname == "" {
		cfg.Hostname = fmt.Sprintf("%d.bridge.%s", cfg.Ordinal, cfg.TunnelDomain)
	}

	return cfg, nil
}

// extractOrdinal extracts the StatefulSet ordinal from a pod name.
// For "bamf-bridge-0" returns 0, for "bamf-bridge-12" returns 12.
// Returns 0 if the name doesn't end with a number.
func extractOrdinal(podName string) int {
	// Find the last hyphen
	lastHyphen := strings.LastIndex(podName, "-")
	if lastHyphen == -1 || lastHyphen == len(podName)-1 {
		return 0
	}

	// Try to parse everything after the last hyphen as a number
	ordinalStr := podName[lastHyphen+1:]
	ordinal, err := strconv.Atoi(ordinalStr)
	if err != nil {
		return 0
	}

	return ordinal
}

func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getDurationEnvOrDefault(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if d, err := time.ParseDuration(value); err == nil {
			return d
		}
		// Try parsing as seconds
		if seconds, err := strconv.Atoi(value); err == nil {
			return time.Duration(seconds) * time.Second
		}
	}
	return defaultValue
}
