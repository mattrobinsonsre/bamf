package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// setEnv sets an environment variable and registers cleanup.
func setEnv(t *testing.T, key, value string) {
	t.Helper()
	old, existed := os.LookupEnv(key)
	t.Cleanup(func() {
		if existed {
			os.Setenv(key, old)
		} else {
			os.Unsetenv(key)
		}
	})
	os.Setenv(key, value)
}

// clearEnvs unsets multiple environment variables and registers cleanup.
func clearEnvs(t *testing.T, keys ...string) {
	t.Helper()
	for _, key := range keys {
		old, existed := os.LookupEnv(key)
		t.Cleanup(func() {
			if existed {
				os.Setenv(key, old)
			} else {
				os.Unsetenv(key)
			}
		})
		os.Unsetenv(key)
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	// Clear all env vars that might affect config
	clearEnvs(t,
		"BAMF_CONFIG_FILE", "BAMF_PLATFORM_URL", "BAMF_API_URL",
		"BAMF_JOIN_TOKEN", "BAMF_AGENT_NAME", "BAMF_DATA_DIR",
		"BAMF_LABELS", "BAMF_RESOURCES",
		"BAMF_HEARTBEAT_INTERVAL", "BAMF_RECONNECT_BASE_DELAY", "BAMF_RECONNECT_MAX_DELAY",
	)
	// Point config file to a nonexistent path to prevent loading any YAML
	setEnv(t, "BAMF_CONFIG_FILE", "/nonexistent/agent.yaml")

	cfg, err := LoadConfig()
	require.NoError(t, err)

	require.Equal(t, "https://api.bamf.example.com", cfg.APIServerURL)
	require.Equal(t, "/var/lib/bamf-agent", cfg.DataDir)
	require.Equal(t, 60*time.Second, cfg.HeartbeatInterval)
	require.Equal(t, 1*time.Second, cfg.ReconnectBaseDelay)
	require.Equal(t, 5*time.Minute, cfg.ReconnectMaxDelay)
	require.NotEmpty(t, cfg.AgentName) // auto-generated from hostname
}

func TestLoadConfig_YAMLFile(t *testing.T) {
	clearEnvs(t,
		"BAMF_CONFIG_FILE", "BAMF_PLATFORM_URL", "BAMF_API_URL",
		"BAMF_JOIN_TOKEN", "BAMF_AGENT_NAME", "BAMF_DATA_DIR",
		"BAMF_LABELS", "BAMF_RESOURCES",
	)

	dir := t.TempDir()
	configFile := filepath.Join(dir, "agent.yaml")

	yamlContent := `
platform_url: https://bamf.myorg.com
join_token: test-token-123
agent_name: test-agent
data_dir: /tmp/bamf-test
labels:
  env: prod
  team: platform
resources:
  - name: web-prod-01
    type: ssh
    hostname: web-prod-01.internal
    labels:
      env: prod
  - name: orders-db
    type: postgres
    host: localhost
    port: 5432
    labels:
      env: prod
`
	require.NoError(t, os.WriteFile(configFile, []byte(yamlContent), 0644))
	setEnv(t, "BAMF_CONFIG_FILE", configFile)

	cfg, err := LoadConfig()
	require.NoError(t, err)

	require.Equal(t, "https://bamf.myorg.com", cfg.APIServerURL)
	require.Equal(t, "test-token-123", cfg.JoinToken)
	require.Equal(t, "test-agent", cfg.AgentName)
	require.Equal(t, "/tmp/bamf-test", cfg.DataDir)

	// Labels
	require.Equal(t, "prod", cfg.Labels["env"])
	require.Equal(t, "platform", cfg.Labels["team"])

	// Resources
	require.Len(t, cfg.Resources, 2)

	resourcesByName := make(map[string]ResourceConfig)
	for _, r := range cfg.Resources {
		resourcesByName[r.Name] = r
	}

	ssh := resourcesByName["web-prod-01"]
	require.Equal(t, "ssh", ssh.ResourceType)
	require.Equal(t, "web-prod-01.internal", ssh.Hostname)
	require.Equal(t, 22, ssh.Port) // default SSH port
	require.Equal(t, "prod", ssh.Labels["env"])

	pg := resourcesByName["orders-db"]
	require.Equal(t, "postgres", pg.ResourceType)
	require.Equal(t, "localhost", pg.Hostname)
	require.Equal(t, 5432, pg.Port)
}

func TestLoadConfig_YAMLFile_LegacyMapFormat(t *testing.T) {
	clearEnvs(t,
		"BAMF_CONFIG_FILE", "BAMF_PLATFORM_URL", "BAMF_API_URL",
		"BAMF_JOIN_TOKEN", "BAMF_AGENT_NAME", "BAMF_DATA_DIR",
		"BAMF_LABELS", "BAMF_RESOURCES",
	)

	dir := t.TempDir()
	configFile := filepath.Join(dir, "agent.yaml")

	// Legacy map format — still supported for backward compatibility
	yamlContent := `
platform_url: https://bamf.myorg.com
agent_name: legacy-agent
resources:
  ssh:
    hostname: web-prod-01.internal
  postgres:
    name: orders-db
    host: localhost
    port: 5432
`
	require.NoError(t, os.WriteFile(configFile, []byte(yamlContent), 0644))
	setEnv(t, "BAMF_CONFIG_FILE", configFile)

	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Len(t, cfg.Resources, 2)

	resourcesByName := make(map[string]ResourceConfig)
	for _, r := range cfg.Resources {
		resourcesByName[r.Name] = r
	}

	ssh := resourcesByName["web-prod-01.internal"]
	require.Equal(t, "ssh", ssh.ResourceType)
	require.Equal(t, 22, ssh.Port)

	pg := resourcesByName["orders-db"]
	require.Equal(t, "postgres", pg.ResourceType)
	require.Equal(t, 5432, pg.Port)
}

func TestLoadConfig_MultipleResourcesSameType(t *testing.T) {
	clearEnvs(t,
		"BAMF_CONFIG_FILE", "BAMF_PLATFORM_URL", "BAMF_API_URL",
		"BAMF_JOIN_TOKEN", "BAMF_AGENT_NAME", "BAMF_DATA_DIR",
		"BAMF_LABELS", "BAMF_RESOURCES",
	)

	dir := t.TempDir()
	configFile := filepath.Join(dir, "agent.yaml")

	yamlContent := `
agent_name: multi-http-agent
resources:
  - name: grafana
    type: http
    hostname: grafana.internal
    port: 3000
    tunnel_hostname: grafana
  - name: jenkins
    type: http
    hostname: jenkins.internal
    port: 8080
    tunnel_hostname: jenkins
  - name: prod-ssh
    type: ssh
    hostname: prod-01.internal
  - name: prod-ssh-audit
    type: ssh-audit
    hostname: prod-01.internal
`
	require.NoError(t, os.WriteFile(configFile, []byte(yamlContent), 0644))
	setEnv(t, "BAMF_CONFIG_FILE", configFile)

	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Len(t, cfg.Resources, 4)

	resourcesByName := make(map[string]ResourceConfig)
	for _, r := range cfg.Resources {
		resourcesByName[r.Name] = r
	}

	grafana := resourcesByName["grafana"]
	require.Equal(t, "http", grafana.ResourceType)
	require.Equal(t, 3000, grafana.Port)
	require.Equal(t, "grafana", grafana.TunnelHostname)

	jenkins := resourcesByName["jenkins"]
	require.Equal(t, "http", jenkins.ResourceType)
	require.Equal(t, 8080, jenkins.Port)
	require.Equal(t, "jenkins", jenkins.TunnelHostname)

	sshRes := resourcesByName["prod-ssh"]
	require.Equal(t, "ssh", sshRes.ResourceType)
	require.Equal(t, 22, sshRes.Port)

	sshAudit := resourcesByName["prod-ssh-audit"]
	require.Equal(t, "ssh-audit", sshAudit.ResourceType)
	require.Equal(t, 22, sshAudit.Port) // ssh-audit defaults to port 22
}

func TestLoadConfig_EnvOverridesYAML(t *testing.T) {
	clearEnvs(t,
		"BAMF_CONFIG_FILE", "BAMF_PLATFORM_URL", "BAMF_API_URL",
		"BAMF_JOIN_TOKEN", "BAMF_AGENT_NAME", "BAMF_DATA_DIR",
		"BAMF_LABELS", "BAMF_RESOURCES",
	)

	dir := t.TempDir()
	configFile := filepath.Join(dir, "agent.yaml")

	yaml := `
platform_url: https://yaml.example.com
join_token: yaml-token
agent_name: yaml-agent
labels:
  env: staging
  from: yaml
`
	require.NoError(t, os.WriteFile(configFile, []byte(yaml), 0644))
	setEnv(t, "BAMF_CONFIG_FILE", configFile)

	// Env vars override YAML
	setEnv(t, "BAMF_PLATFORM_URL", "https://env.example.com")
	setEnv(t, "BAMF_JOIN_TOKEN", "env-token")
	setEnv(t, "BAMF_AGENT_NAME", "env-agent")
	setEnv(t, "BAMF_LABELS", "env=prod,extra=yes")

	cfg, err := LoadConfig()
	require.NoError(t, err)

	// Env wins over YAML
	require.Equal(t, "https://env.example.com", cfg.APIServerURL)
	require.Equal(t, "env-token", cfg.JoinToken)
	require.Equal(t, "env-agent", cfg.AgentName)

	// Labels: env overrides yaml per-key, yaml-only keys preserved
	require.Equal(t, "prod", cfg.Labels["env"])   // env overrides yaml "staging"
	require.Equal(t, "yaml", cfg.Labels["from"])   // yaml-only key preserved
	require.Equal(t, "yes", cfg.Labels["extra"])   // env-only key added
}

func TestLoadConfig_PlatformURLPrecedence(t *testing.T) {
	clearEnvs(t,
		"BAMF_CONFIG_FILE", "BAMF_PLATFORM_URL", "BAMF_API_URL",
		"BAMF_JOIN_TOKEN", "BAMF_AGENT_NAME", "BAMF_DATA_DIR",
		"BAMF_LABELS", "BAMF_RESOURCES",
	)
	setEnv(t, "BAMF_CONFIG_FILE", "/nonexistent/agent.yaml")

	// BAMF_PLATFORM_URL takes precedence over BAMF_API_URL
	setEnv(t, "BAMF_API_URL", "https://api.example.com")
	setEnv(t, "BAMF_PLATFORM_URL", "https://platform.example.com")

	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Equal(t, "https://platform.example.com", cfg.APIServerURL)
}

func TestLoadConfig_APIURLFallback(t *testing.T) {
	clearEnvs(t,
		"BAMF_CONFIG_FILE", "BAMF_PLATFORM_URL", "BAMF_API_URL",
		"BAMF_JOIN_TOKEN", "BAMF_AGENT_NAME", "BAMF_DATA_DIR",
		"BAMF_LABELS", "BAMF_RESOURCES",
	)
	setEnv(t, "BAMF_CONFIG_FILE", "/nonexistent/agent.yaml")

	// Only BAMF_API_URL set — should be used
	setEnv(t, "BAMF_API_URL", "https://api.example.com")

	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Equal(t, "https://api.example.com", cfg.APIServerURL)
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	clearEnvs(t,
		"BAMF_CONFIG_FILE", "BAMF_PLATFORM_URL", "BAMF_API_URL",
		"BAMF_JOIN_TOKEN", "BAMF_AGENT_NAME", "BAMF_DATA_DIR",
		"BAMF_LABELS", "BAMF_RESOURCES",
	)

	dir := t.TempDir()
	configFile := filepath.Join(dir, "agent.yaml")

	require.NoError(t, os.WriteFile(configFile, []byte("{{invalid yaml"), 0644))
	setEnv(t, "BAMF_CONFIG_FILE", configFile)

	_, err := LoadConfig()
	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to parse config file")
}

func TestLoadConfig_MissingYAMLFileOK(t *testing.T) {
	clearEnvs(t,
		"BAMF_CONFIG_FILE", "BAMF_PLATFORM_URL", "BAMF_API_URL",
		"BAMF_JOIN_TOKEN", "BAMF_AGENT_NAME", "BAMF_DATA_DIR",
		"BAMF_LABELS", "BAMF_RESOURCES",
	)
	// Point to nonexistent file — should not error, just use defaults
	setEnv(t, "BAMF_CONFIG_FILE", "/nonexistent/agent.yaml")

	cfg, err := LoadConfig()
	require.NoError(t, err)
	require.Equal(t, "https://api.bamf.example.com", cfg.APIServerURL)
}

func TestResourceConfigFromYAML_SSHDefaults(t *testing.T) {
	res := yamlResource{
		Hostname: "web-01.internal",
		Labels:   map[string]string{"env": "prod"},
	}

	rc := resourceConfigFromYAML("ssh", res)

	require.Equal(t, "ssh", rc.ResourceType)
	require.Equal(t, "web-01.internal", rc.Hostname)
	require.Equal(t, "web-01.internal", rc.Name) // derived from hostname
	require.Equal(t, 22, rc.Port)                 // default SSH port
	require.Equal(t, "prod", rc.Labels["env"])
}

func TestResourceConfigFromYAML_PostgresExplicit(t *testing.T) {
	res := yamlResource{
		Name: "orders-db",
		Host: "db.internal",
		Port: 5433,
	}

	rc := resourceConfigFromYAML("postgres", res)

	require.Equal(t, "postgres", rc.ResourceType)
	require.Equal(t, "orders-db", rc.Name)
	require.Equal(t, "db.internal", rc.Hostname)
	require.Equal(t, 5433, rc.Port) // explicit port, not default
}

func TestResourceConfigFromYAML_NilLabels(t *testing.T) {
	res := yamlResource{Hostname: "test"}
	rc := resourceConfigFromYAML("ssh", res)
	require.NotNil(t, rc.Labels) // should be initialized even if YAML has none
}

func TestParseLabels(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect map[string]string
	}{
		{"empty", "", map[string]string{}},
		{"single", "env=prod", map[string]string{"env": "prod"}},
		{"multiple", "env=prod,team=platform", map[string]string{"env": "prod", "team": "platform"}},
		{"spaces", " env = prod , team = platform ", map[string]string{"env": "prod", "team": "platform"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseLabels(tt.input)
			require.Equal(t, tt.expect, result)
		})
	}
}

func TestParseResources(t *testing.T) {
	resources, err := parseResources("mydb:postgres:localhost:5432,web:ssh:host.internal:22")
	require.NoError(t, err)
	require.Len(t, resources, 2)

	require.Equal(t, "mydb", resources[0].Name)
	require.Equal(t, "postgres", resources[0].ResourceType)
	require.Equal(t, "localhost", resources[0].Hostname)
	require.Equal(t, 5432, resources[0].Port)

	require.Equal(t, "web", resources[1].Name)
	require.Equal(t, "ssh", resources[1].ResourceType)
}

func TestParseResources_InvalidPort(t *testing.T) {
	_, err := parseResources("mydb:postgres:localhost:notaport")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid port")
}

func TestParseDuration(t *testing.T) {
	require.Equal(t, 5*time.Second, parseDuration("5s", time.Minute))
	require.Equal(t, 30*time.Second, parseDuration("30", time.Minute))  // plain integer = seconds
	require.Equal(t, time.Minute, parseDuration("invalid", time.Minute)) // fallback
}
