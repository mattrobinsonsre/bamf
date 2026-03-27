package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// ── Tests: parseResources edge cases ─────────────────────────────────

func TestParseResources_EmptyString(t *testing.T) {
	resources, err := parseResources("")
	require.NoError(t, err)
	// Empty string produces one entry with "" split, but it has < 4 parts so it's skipped
	require.Empty(t, resources)
}

func TestParseResources_TooFewParts(t *testing.T) {
	// Entries with fewer than 4 colon-separated parts are silently skipped
	resources, err := parseResources("name:type:host")
	require.NoError(t, err)
	require.Empty(t, resources)
}

func TestParseResources_MixedValidInvalid(t *testing.T) {
	// Valid entry followed by an entry with too few parts
	resources, err := parseResources("db:postgres:localhost:5432,incomplete:ssh:host")
	require.NoError(t, err)
	require.Len(t, resources, 1)
	require.Equal(t, "db", resources[0].Name)
}

func TestParseResources_SingleResource(t *testing.T) {
	resources, err := parseResources("web:ssh:host.internal:22")
	require.NoError(t, err)
	require.Len(t, resources, 1)
	require.Equal(t, "web", resources[0].Name)
	require.Equal(t, "ssh", resources[0].ResourceType)
	require.Equal(t, "host.internal", resources[0].Hostname)
	require.Equal(t, 22, resources[0].Port)
	require.NotNil(t, resources[0].Labels, "labels should be initialized")
}

func TestParseResources_LabelsInitialized(t *testing.T) {
	resources, err := parseResources("db:postgres:localhost:5432")
	require.NoError(t, err)
	require.Len(t, resources, 1)
	require.NotNil(t, resources[0].Labels)
	require.Empty(t, resources[0].Labels)
}

// ── Tests: parseDuration edge cases ──────────────────────────────────

func TestParseDuration_EmptyString(t *testing.T) {
	fallback := 42 * time.Second
	result := parseDuration("", fallback)
	require.Equal(t, fallback, result)
}

func TestParseDuration_GoFormat(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected time.Duration
	}{
		{"seconds", "10s", 10 * time.Second},
		{"minutes", "5m", 5 * time.Minute},
		{"hours", "2h", 2 * time.Hour},
		{"complex", "1h30m", 90 * time.Minute},
		{"milliseconds", "500ms", 500 * time.Millisecond},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseDuration(tt.input, time.Hour)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestParseDuration_PlainInteger(t *testing.T) {
	// Plain integer is interpreted as seconds
	result := parseDuration("60", time.Hour)
	require.Equal(t, 60*time.Second, result)
}

func TestParseDuration_Zero(t *testing.T) {
	result := parseDuration("0", time.Hour)
	require.Equal(t, time.Duration(0), result)
}

func TestParseDuration_InvalidFallback(t *testing.T) {
	fallback := 99 * time.Second
	result := parseDuration("not-a-duration-or-number", fallback)
	require.Equal(t, fallback, result)
}

// ── Tests: parseLabels edge cases ────────────────────────────────────

func TestParseLabels_MalformedPairs(t *testing.T) {
	// Entries without '=' are skipped
	result := parseLabels("noequals,valid=yes,alsonoequals")
	require.Len(t, result, 1)
	require.Equal(t, "yes", result["valid"])
}

func TestParseLabels_EmptyValues(t *testing.T) {
	result := parseLabels("key=")
	require.Len(t, result, 1)
	require.Equal(t, "", result["key"])
}

func TestParseLabels_ValueWithEquals(t *testing.T) {
	// SplitN with n=2 preserves = in the value
	result := parseLabels("key=val=ue")
	require.Len(t, result, 1)
	require.Equal(t, "val=ue", result["key"])
}

func TestParseLabels_DuplicateKeys(t *testing.T) {
	// Last value wins
	result := parseLabels("env=dev,env=prod")
	require.Len(t, result, 1)
	require.Equal(t, "prod", result["env"])
}

// ── Tests: resourceConfigFromYAML — all resource types ───────────────

func TestResourceConfigFromYAML_AllTypes(t *testing.T) {
	tests := []struct {
		resourceType    string
		expectedPort    int
		expectTunnelDNS bool // HTTP types auto-set tunnel_hostname
	}{
		{"ssh", 22, false},
		{"ssh-audit", 22, false},
		{"postgres", 5432, false},
		{"postgres-audit", 5432, false},
		{"mysql", 3306, false},
		{"mysql-audit", 3306, false},
		{"kubernetes", 6443, false},
		{"http", 80, true},
		{"http-audit", 80, true},
		{"https", 443, true},
	}

	for _, tt := range tests {
		t.Run(tt.resourceType, func(t *testing.T) {
			res := yamlResource{
				Name:     "test-resource",
				Hostname: "target.internal",
			}
			rc := resourceConfigFromYAML(tt.resourceType, res)

			require.Equal(t, tt.resourceType, rc.ResourceType)
			require.Equal(t, tt.expectedPort, rc.Port, "default port for %s", tt.resourceType)
			require.Equal(t, "test-resource", rc.Name)
			require.Equal(t, "target.internal", rc.Hostname)
			require.NotNil(t, rc.Labels)

			if tt.expectTunnelDNS {
				require.Equal(t, "test-resource", rc.TunnelHostname,
					"HTTP types should default tunnel_hostname to resource name")
			} else {
				require.Empty(t, rc.TunnelHostname,
					"non-HTTP types should not auto-set tunnel_hostname")
			}
		})
	}
}

func TestResourceConfigFromYAML_ExplicitTunnelHostname(t *testing.T) {
	res := yamlResource{
		Name:           "grafana",
		Hostname:       "grafana.internal",
		Port:           3000,
		TunnelHostname: "custom-tunnel",
	}
	rc := resourceConfigFromYAML("http", res)
	require.Equal(t, "custom-tunnel", rc.TunnelHostname)
}

func TestResourceConfigFromYAML_HostFallback(t *testing.T) {
	// "host" field is used when "hostname" is empty
	res := yamlResource{
		Name: "mydb",
		Host: "db-host.internal",
		Port: 5432,
	}
	rc := resourceConfigFromYAML("postgres", res)
	require.Equal(t, "db-host.internal", rc.Hostname)
}

func TestResourceConfigFromYAML_HostnameOverridesHost(t *testing.T) {
	// "hostname" takes precedence over "host"
	res := yamlResource{
		Name:     "mydb",
		Hostname: "hostname-value",
		Host:     "host-value",
	}
	rc := resourceConfigFromYAML("postgres", res)
	require.Equal(t, "hostname-value", rc.Hostname)
}

func TestResourceConfigFromYAML_NameDefaultsToHostname(t *testing.T) {
	res := yamlResource{
		Hostname: "web-server.internal",
	}
	rc := resourceConfigFromYAML("ssh", res)
	require.Equal(t, "web-server.internal", rc.Name)
}

func TestResourceConfigFromYAML_UnknownTypeNoDefaultPort(t *testing.T) {
	res := yamlResource{
		Name:     "custom",
		Hostname: "custom.internal",
	}
	rc := resourceConfigFromYAML("custom-type", res)
	require.Equal(t, 0, rc.Port, "unknown type should have 0 default port")
}

func TestResourceConfigFromYAML_ExplicitPortOverridesDefault(t *testing.T) {
	res := yamlResource{
		Name:     "custom-ssh",
		Hostname: "host.internal",
		Port:     2222,
	}
	rc := resourceConfigFromYAML("ssh", res)
	require.Equal(t, 2222, rc.Port, "explicit port should override default")
}

func TestResourceConfigFromYAML_Webhooks(t *testing.T) {
	res := yamlResource{
		Name:     "jenkins",
		Hostname: "jenkins.internal",
		Port:     8080,
		Webhooks: []yamlWebhook{
			{
				Path:    "/github-webhook/",
				Methods: []string{"POST"},
			},
			{
				Path:        "/api/trigger",
				Methods:     []string{"POST", "PUT"},
				SourceCIDRs: []string{"10.0.0.0/8"},
			},
		},
	}
	rc := resourceConfigFromYAML("http", res)

	require.Len(t, rc.Webhooks, 2)
	require.Equal(t, "/github-webhook/", rc.Webhooks[0].Path)
	require.Equal(t, []string{"POST"}, rc.Webhooks[0].Methods)
	require.Empty(t, rc.Webhooks[0].SourceCIDRs)
	require.Equal(t, "/api/trigger", rc.Webhooks[1].Path)
	require.Equal(t, []string{"POST", "PUT"}, rc.Webhooks[1].Methods)
	require.Equal(t, []string{"10.0.0.0/8"}, rc.Webhooks[1].SourceCIDRs)
}

func TestResourceConfigFromYAML_NoWebhooks(t *testing.T) {
	res := yamlResource{
		Name:     "app",
		Hostname: "app.internal",
	}
	rc := resourceConfigFromYAML("http", res)
	require.Nil(t, rc.Webhooks)
}

// ── Tests: findYAMLFile ──────────────────────────────────────────────

func TestFindYAMLFile_ExplicitEnvVar(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "custom-agent.yaml")
	require.NoError(t, os.WriteFile(configFile, []byte("agent_name: test"), 0644))

	setEnv(t, "BAMF_CONFIG_FILE", configFile)

	result := findYAMLFile()
	require.Equal(t, configFile, result)
}

func TestFindYAMLFile_ExplicitEnvVarMissing(t *testing.T) {
	setEnv(t, "BAMF_CONFIG_FILE", "/nonexistent/path/agent.yaml")

	result := findYAMLFile()
	require.Empty(t, result)
}

func TestFindYAMLFile_NoEnvVar(t *testing.T) {
	clearEnvs(t, "BAMF_CONFIG_FILE")

	// Default search paths (/etc/bamf/agent.yaml, ./agent.yaml) likely don't exist
	// in the test environment, so findYAMLFile should return ""
	result := findYAMLFile()
	// We can't assert much here since default paths might or might not exist
	// Just verify it doesn't panic
	_ = result
}

// ── Tests: LoadConfig with cluster_internal ──────────────────────────

func TestLoadConfig_ClusterInternal_YAML(t *testing.T) {
	clearEnvs(t,
		"BAMF_CONFIG_FILE", "BAMF_PLATFORM_URL", "BAMF_API_URL",
		"BAMF_JOIN_TOKEN", "BAMF_AGENT_NAME", "BAMF_DATA_DIR",
		"BAMF_LABELS", "BAMF_RESOURCES", "BAMF_CLUSTER_INTERNAL",
	)

	dir := t.TempDir()
	configFile := filepath.Join(dir, "agent.yaml")
	yamlContent := `
agent_name: cluster-agent
cluster_internal: true
`
	require.NoError(t, os.WriteFile(configFile, []byte(yamlContent), 0644))
	setEnv(t, "BAMF_CONFIG_FILE", configFile)

	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.True(t, cfg.ClusterInternal)
}

func TestLoadConfig_ClusterInternal_EnvOverride(t *testing.T) {
	clearEnvs(t,
		"BAMF_CONFIG_FILE", "BAMF_PLATFORM_URL", "BAMF_API_URL",
		"BAMF_JOIN_TOKEN", "BAMF_AGENT_NAME", "BAMF_DATA_DIR",
		"BAMF_LABELS", "BAMF_RESOURCES", "BAMF_CLUSTER_INTERNAL",
	)

	dir := t.TempDir()
	configFile := filepath.Join(dir, "agent.yaml")
	yamlContent := `
agent_name: cluster-agent
cluster_internal: false
`
	require.NoError(t, os.WriteFile(configFile, []byte(yamlContent), 0644))
	setEnv(t, "BAMF_CONFIG_FILE", configFile)
	setEnv(t, "BAMF_CLUSTER_INTERNAL", "true")

	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.True(t, cfg.ClusterInternal, "env var should override YAML")
}

func TestLoadConfig_ClusterInternal_EnvFalse(t *testing.T) {
	clearEnvs(t,
		"BAMF_CONFIG_FILE", "BAMF_PLATFORM_URL", "BAMF_API_URL",
		"BAMF_JOIN_TOKEN", "BAMF_AGENT_NAME", "BAMF_DATA_DIR",
		"BAMF_LABELS", "BAMF_RESOURCES", "BAMF_CLUSTER_INTERNAL",
	)
	setEnv(t, "BAMF_CONFIG_FILE", "/nonexistent/agent.yaml")
	setEnv(t, "BAMF_CLUSTER_INTERNAL", "false")

	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.False(t, cfg.ClusterInternal)
}

func TestLoadConfig_ClusterInternal_Env1(t *testing.T) {
	clearEnvs(t,
		"BAMF_CONFIG_FILE", "BAMF_PLATFORM_URL", "BAMF_API_URL",
		"BAMF_JOIN_TOKEN", "BAMF_AGENT_NAME", "BAMF_DATA_DIR",
		"BAMF_LABELS", "BAMF_RESOURCES", "BAMF_CLUSTER_INTERNAL",
	)
	setEnv(t, "BAMF_CONFIG_FILE", "/nonexistent/agent.yaml")
	setEnv(t, "BAMF_CLUSTER_INTERNAL", "1")

	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.True(t, cfg.ClusterInternal, "'1' should be treated as true")
}

// ── Tests: LoadConfig connection tuning env vars ─────────────────────

func TestLoadConfig_ConnectionTuning_EnvVars(t *testing.T) {
	clearEnvs(t,
		"BAMF_CONFIG_FILE", "BAMF_PLATFORM_URL", "BAMF_API_URL",
		"BAMF_JOIN_TOKEN", "BAMF_AGENT_NAME", "BAMF_DATA_DIR",
		"BAMF_LABELS", "BAMF_RESOURCES", "BAMF_CLUSTER_INTERNAL",
		"BAMF_HEARTBEAT_INTERVAL", "BAMF_RECONNECT_BASE_DELAY", "BAMF_RECONNECT_MAX_DELAY",
	)
	setEnv(t, "BAMF_CONFIG_FILE", "/nonexistent/agent.yaml")
	setEnv(t, "BAMF_HEARTBEAT_INTERVAL", "30s")
	setEnv(t, "BAMF_RECONNECT_BASE_DELAY", "2s")
	setEnv(t, "BAMF_RECONNECT_MAX_DELAY", "10m")

	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Equal(t, 30*time.Second, cfg.HeartbeatInterval)
	require.Equal(t, 2*time.Second, cfg.ReconnectBaseDelay)
	require.Equal(t, 10*time.Minute, cfg.ReconnectMaxDelay)
}

func TestLoadConfig_ConnectionTuning_PlainSeconds(t *testing.T) {
	clearEnvs(t,
		"BAMF_CONFIG_FILE", "BAMF_PLATFORM_URL", "BAMF_API_URL",
		"BAMF_JOIN_TOKEN", "BAMF_AGENT_NAME", "BAMF_DATA_DIR",
		"BAMF_LABELS", "BAMF_RESOURCES", "BAMF_CLUSTER_INTERNAL",
		"BAMF_HEARTBEAT_INTERVAL", "BAMF_RECONNECT_BASE_DELAY", "BAMF_RECONNECT_MAX_DELAY",
	)
	setEnv(t, "BAMF_CONFIG_FILE", "/nonexistent/agent.yaml")
	setEnv(t, "BAMF_HEARTBEAT_INTERVAL", "45")

	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Equal(t, 45*time.Second, cfg.HeartbeatInterval)
}

// ── Tests: LoadConfig resource env override ──────────────────────────

func TestLoadConfig_ResourcesFromEnv(t *testing.T) {
	clearEnvs(t,
		"BAMF_CONFIG_FILE", "BAMF_PLATFORM_URL", "BAMF_API_URL",
		"BAMF_JOIN_TOKEN", "BAMF_AGENT_NAME", "BAMF_DATA_DIR",
		"BAMF_LABELS", "BAMF_RESOURCES", "BAMF_CLUSTER_INTERNAL",
		"BAMF_HEARTBEAT_INTERVAL", "BAMF_RECONNECT_BASE_DELAY", "BAMF_RECONNECT_MAX_DELAY",
	)
	setEnv(t, "BAMF_CONFIG_FILE", "/nonexistent/agent.yaml")
	setEnv(t, "BAMF_RESOURCES", "mydb:postgres:db.internal:5432,web:ssh:web.internal:22")

	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Len(t, cfg.Resources, 2)
	require.Equal(t, "mydb", cfg.Resources[0].Name)
	require.Equal(t, "postgres", cfg.Resources[0].ResourceType)
	require.Equal(t, "web", cfg.Resources[1].Name)
	require.Equal(t, "ssh", cfg.Resources[1].ResourceType)
}

func TestLoadConfig_ResourcesFromEnv_OverridesYAML(t *testing.T) {
	clearEnvs(t,
		"BAMF_CONFIG_FILE", "BAMF_PLATFORM_URL", "BAMF_API_URL",
		"BAMF_JOIN_TOKEN", "BAMF_AGENT_NAME", "BAMF_DATA_DIR",
		"BAMF_LABELS", "BAMF_RESOURCES", "BAMF_CLUSTER_INTERNAL",
		"BAMF_HEARTBEAT_INTERVAL", "BAMF_RECONNECT_BASE_DELAY", "BAMF_RECONNECT_MAX_DELAY",
	)

	dir := t.TempDir()
	configFile := filepath.Join(dir, "agent.yaml")
	yamlContent := `
agent_name: test
resources:
  - name: yaml-resource
    type: ssh
    hostname: yaml-host
`
	require.NoError(t, os.WriteFile(configFile, []byte(yamlContent), 0644))
	setEnv(t, "BAMF_CONFIG_FILE", configFile)
	setEnv(t, "BAMF_RESOURCES", "env-resource:postgres:env-host:5432")

	cfg, err := LoadConfig()
	require.NoError(t, err)
	// Env replaces YAML resources entirely
	require.Len(t, cfg.Resources, 1)
	require.Equal(t, "env-resource", cfg.Resources[0].Name)
}

// ── Tests: LoadConfig data dir and cert paths ────────────────────────

func TestLoadConfig_CertPaths(t *testing.T) {
	clearEnvs(t,
		"BAMF_CONFIG_FILE", "BAMF_PLATFORM_URL", "BAMF_API_URL",
		"BAMF_JOIN_TOKEN", "BAMF_AGENT_NAME", "BAMF_DATA_DIR",
		"BAMF_LABELS", "BAMF_RESOURCES",
	)
	setEnv(t, "BAMF_CONFIG_FILE", "/nonexistent/agent.yaml")
	setEnv(t, "BAMF_DATA_DIR", "/custom/data")

	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Equal(t, "/custom/data", cfg.DataDir)
	require.Equal(t, "/custom/data/agent.crt", cfg.CertFile)
	require.Equal(t, "/custom/data/agent.key", cfg.KeyFile)
	require.Equal(t, "/custom/data/ca.crt", cfg.CAFile)
}

// ── Tests: LoadConfig YAML with no resources ─────────────────────────

func TestLoadConfig_YAMLNoResources(t *testing.T) {
	clearEnvs(t,
		"BAMF_CONFIG_FILE", "BAMF_PLATFORM_URL", "BAMF_API_URL",
		"BAMF_JOIN_TOKEN", "BAMF_AGENT_NAME", "BAMF_DATA_DIR",
		"BAMF_LABELS", "BAMF_RESOURCES",
	)

	dir := t.TempDir()
	configFile := filepath.Join(dir, "agent.yaml")
	yamlContent := `
agent_name: no-resources-agent
platform_url: https://bamf.example.com
`
	require.NoError(t, os.WriteFile(configFile, []byte(yamlContent), 0644))
	setEnv(t, "BAMF_CONFIG_FILE", configFile)

	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Empty(t, cfg.Resources)
	require.Equal(t, "no-resources-agent", cfg.AgentName)
}

// ── Tests: defaultPorts map ──────────────────────────────────────────

func TestDefaultPorts(t *testing.T) {
	expected := map[string]int{
		"ssh":            22,
		"ssh-audit":      22,
		"postgres":       5432,
		"postgres-audit": 5432,
		"mysql":          3306,
		"mysql-audit":    3306,
		"kubernetes":     6443,
		"http":           80,
		"http-audit":     80,
		"https":          443,
	}

	for resType, port := range expected {
		t.Run(resType, func(t *testing.T) {
			require.Equal(t, port, defaultPorts[resType])
		})
	}
}
