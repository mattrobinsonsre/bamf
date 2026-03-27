package bridge

import (
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestExtractOrdinal(t *testing.T) {
	tests := []struct {
		name    string
		podName string
		want    int
	}{
		{name: "standard pod-0", podName: "bamf-bridge-0", want: 0},
		{name: "pod-1", podName: "bamf-bridge-1", want: 1},
		{name: "pod-12", podName: "bamf-bridge-12", want: 12},
		{name: "pod-99", podName: "bamf-bridge-99", want: 99},
		{name: "no hyphen", podName: "bridge", want: 0},
		{name: "no number after hyphen", podName: "bamf-bridge-abc", want: 0},
		{name: "trailing hyphen", podName: "bamf-bridge-", want: 0},
		{name: "empty string", podName: "", want: 0},
		{name: "single number", podName: "0", want: 0},       // no hyphen
		{name: "hyphen-0", podName: "-0", want: 0},            // ordinal = 0
		{name: "custom prefix-5", podName: "my-app-bridge-5", want: 5},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractOrdinal(tt.podName)
			require.Equal(t, tt.want, got)
		})
	}
}

// setEnv is a helper that sets an env var and returns a cleanup function.
func setEnv(t *testing.T, key, value string) {
	t.Helper()
	t.Setenv(key, value)
}

func clearBridgeEnvs(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"BAMF_HTTPS_ADDR", "BAMF_TUNNEL_ADDR", "BAMF_HEALTH_ADDR",
		"BAMF_API_URL", "BAMF_TLS_CERT", "BAMF_TLS_KEY", "BAMF_CA_CERT",
		"BAMF_BRIDGE_ID", "BAMF_HOSTNAME", "BAMF_TUNNEL_SETUP_TIMEOUT",
		"BAMF_IDLE_TIMEOUT", "BAMF_SHUTDOWN_TIMEOUT", "BAMF_TUNNEL_DOMAIN",
		"BAMF_TLS_MIN_VERSION", "BAMF_BOOTSTRAP_TOKEN", "BAMF_DATA_DIR",
	} {
		os.Unsetenv(key)
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	clearBridgeEnvs(t)
	setEnv(t, "BAMF_TUNNEL_DOMAIN", "tunnel.bamf.local")
	setEnv(t, "BAMF_BRIDGE_ID", "bamf-bridge-3")

	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Equal(t, ":443", cfg.HTTPSAddr)
	require.Equal(t, ":8443", cfg.TunnelAddr)
	require.Equal(t, ":8080", cfg.HealthAddr)
	require.Equal(t, "bamf-bridge-3", cfg.BridgeID)
	require.Equal(t, 3, cfg.Ordinal)
	require.Equal(t, "3.bridge.tunnel.bamf.local", cfg.Hostname)
	require.Equal(t, 30*time.Second, cfg.TunnelSetupTimeout)
	require.Equal(t, time.Duration(0), cfg.IdleTimeout)
	require.Equal(t, 90*time.Second, cfg.ShutdownTimeout)
	require.Equal(t, "1.3", cfg.TLSMinVersion)
}

func TestLoadConfig_CustomValues(t *testing.T) {
	clearBridgeEnvs(t)
	setEnv(t, "BAMF_TUNNEL_DOMAIN", "tunnel.example.com")
	setEnv(t, "BAMF_BRIDGE_ID", "my-bridge-7")
	setEnv(t, "BAMF_HTTPS_ADDR", ":8443")
	setEnv(t, "BAMF_API_URL", "http://api:9000")
	setEnv(t, "BAMF_TUNNEL_SETUP_TIMEOUT", "60s")

	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Equal(t, ":8443", cfg.HTTPSAddr)
	require.Equal(t, "http://api:9000", cfg.APIServerURL)
	require.Equal(t, 60*time.Second, cfg.TunnelSetupTimeout)
	require.Equal(t, "7.bridge.tunnel.example.com", cfg.Hostname)
}

func TestLoadConfig_MissingTunnelDomain(t *testing.T) {
	clearBridgeEnvs(t)
	setEnv(t, "BAMF_BRIDGE_ID", "bamf-bridge-0")
	// No BAMF_TUNNEL_DOMAIN

	_, err := LoadConfig()
	require.Error(t, err)
	require.Contains(t, err.Error(), "BAMF_TUNNEL_DOMAIN")
}

func TestLoadConfig_ExplicitHostname(t *testing.T) {
	clearBridgeEnvs(t)
	setEnv(t, "BAMF_TUNNEL_DOMAIN", "tunnel.bamf.local")
	setEnv(t, "BAMF_BRIDGE_ID", "bamf-bridge-0")
	setEnv(t, "BAMF_HOSTNAME", "custom.bridge.example.com")

	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Equal(t, "custom.bridge.example.com", cfg.Hostname)
}

func TestGetDurationEnvOrDefault(t *testing.T) {
	tests := []struct {
		name     string
		envVal   string
		fallback time.Duration
		want     time.Duration
	}{
		{name: "duration string", envVal: "5s", fallback: 0, want: 5 * time.Second},
		{name: "plain seconds", envVal: "30", fallback: 0, want: 30 * time.Second},
		{name: "minutes", envVal: "2m", fallback: 0, want: 2 * time.Minute},
		{name: "empty uses default", envVal: "", fallback: 10 * time.Second, want: 10 * time.Second},
		{name: "invalid uses default", envVal: "abc", fallback: 10 * time.Second, want: 10 * time.Second},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := "TEST_DURATION_" + tt.name
			if tt.envVal != "" {
				t.Setenv(key, tt.envVal)
			}
			got := getDurationEnvOrDefault(key, tt.fallback)
			require.Equal(t, tt.want, got)
		})
	}
}
