package agent

// Agent config reference: docs/reference/agent-config.md
// Guide: docs/guides/agents.md

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config holds agent configuration.
//
// Configuration is layered: defaults → YAML file → environment variables.
// Environment variables always override YAML values.
type Config struct {
	// Agent identification
	AgentName string            // Unique name for this agent
	Labels    map[string]string // Labels for resource matching

	// API server connection
	APIServerURL string // BAMF API server URL
	JoinToken    string // Join token for initial registration

	// Certificate storage
	DataDir  string // Directory for certificates and state
	CertFile string // Path to agent certificate
	KeyFile  string // Path to agent private key
	CAFile   string // Path to CA certificate

	// Resources
	Resources []ResourceConfig // Resources exposed by this agent

	// Cluster-internal flag: when true, the API sends in-cluster service
	// hostnames for bridge connections instead of external DNS names.
	ClusterInternal bool

	// Connection settings
	HeartbeatInterval    time.Duration
	ReconnectBaseDelay   time.Duration
	ReconnectMaxDelay    time.Duration
	ReconnectJitterRatio float64
}

// ResourceConfig defines a resource exposed by the agent.
//
// Go contract: maps to HeartbeatResource in services/bamf/api/routers/agents.py.
// The agent sends resources on every heartbeat.
type ResourceConfig struct {
	Name           string            // Resource name
	ResourceType   string            // ssh, ssh-audit, kubernetes, postgres, mysql, http, http-audit
	Hostname       string            // Target hostname
	Port           int               // Target port
	Labels         map[string]string // Resource labels
	TunnelHostname string            // Tunnel hostname for HTTP proxy (e.g., "grafana" → grafana.tunnel.domain)
}

// yamlConfig is the YAML file structure for agent configuration.
// See CLAUDE.md "Agent Architecture" for the canonical format.
//
// Resources can be specified as either a list (preferred) or a map keyed
// by resource type (legacy, deprecated). The list format supports multiple
// resources of the same type.
type yamlConfig struct {
	PlatformURL     string            `yaml:"platform_url"`
	JoinToken       string            `yaml:"join_token"`
	AgentName       string            `yaml:"agent_name"`
	DataDir         string            `yaml:"data_dir"`
	ClusterInternal *bool             `yaml:"cluster_internal"`
	Labels          map[string]string `yaml:"labels"`
	// Resources is parsed manually in loadYAML to support both list and map formats.
	Resources yaml.Node `yaml:"resources"`
}

// yamlResource represents a resource in YAML config.
type yamlResource struct {
	Name           string            `yaml:"name"`
	Type           string            `yaml:"type"`
	Hostname       string            `yaml:"hostname"`
	Host           string            `yaml:"host"`
	Port           int               `yaml:"port"`
	Labels         map[string]string `yaml:"labels"`
	TunnelHostname string            `yaml:"tunnel_hostname"`
}

// yamlResourceLegacy is used for the deprecated map format where the map
// key is the resource type (e.g., resources: { ssh: {hostname: ...} }).
type yamlResourceLegacy struct {
	Name           string            `yaml:"name"`
	Hostname       string            `yaml:"hostname"`
	Host           string            `yaml:"host"`
	Port           int               `yaml:"port"`
	Labels         map[string]string `yaml:"labels"`
	TunnelHostname string            `yaml:"tunnel_hostname"`
}

// Default ports by resource type.
var defaultPorts = map[string]int{
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

// YAML file search paths (checked in order).
var yamlSearchPaths = []string{
	"/etc/bamf/agent.yaml",
	"./agent.yaml",
}

// LoadConfig loads configuration using layered sources:
// defaults → YAML file → environment variables.
//
// YAML file locations (checked in order):
//  1. $BAMF_CONFIG_FILE (explicit path)
//  2. /etc/bamf/agent.yaml
//  3. ./agent.yaml
//
// Environment variable overrides:
//   - BAMF_PLATFORM_URL / BAMF_API_URL → APIServerURL
//   - BAMF_JOIN_TOKEN → JoinToken
//   - BAMF_AGENT_NAME → AgentName
//   - BAMF_DATA_DIR → DataDir
//   - BAMF_LABELS → Labels (key1=value1,key2=value2)
//   - BAMF_RESOURCES → Resources (name:type:host:port,...)
func LoadConfig() (*Config, error) {
	// Start with defaults
	cfg := &Config{
		APIServerURL:         "https://api.bamf.example.com",
		DataDir:              "/var/lib/bamf-agent",
		Labels:               make(map[string]string),
		HeartbeatInterval:    60 * time.Second,
		ReconnectBaseDelay:   1 * time.Second,
		ReconnectMaxDelay:    5 * time.Minute,
		ReconnectJitterRatio: 0.2,
	}

	// Layer 2: YAML file
	if err := cfg.loadYAML(); err != nil {
		return nil, err
	}

	// Layer 3: Environment variable overrides
	cfg.applyEnvOverrides()

	// Auto-generate agent name from hostname if not set
	if cfg.AgentName == "" {
		hostname, err := os.Hostname()
		if err != nil {
			return nil, fmt.Errorf("failed to get hostname: %w", err)
		}
		cfg.AgentName = hostname
	}

	// Set certificate paths relative to data dir
	cfg.CertFile = filepath.Join(cfg.DataDir, "agent.crt")
	cfg.KeyFile = filepath.Join(cfg.DataDir, "agent.key")
	cfg.CAFile = filepath.Join(cfg.DataDir, "ca.crt")

	return cfg, nil
}

// loadYAML finds and loads the YAML config file.
func (cfg *Config) loadYAML() error {
	path := findYAMLFile()
	if path == "" {
		return nil // No YAML file found — that's fine, env vars will provide config.
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read config file %s: %w", path, err)
	}

	var yc yamlConfig
	if err := yaml.Unmarshal(data, &yc); err != nil {
		return fmt.Errorf("failed to parse config file %s: %w", path, err)
	}

	// Apply YAML values
	if yc.PlatformURL != "" {
		cfg.APIServerURL = yc.PlatformURL
	}
	if yc.JoinToken != "" {
		cfg.JoinToken = yc.JoinToken
	}
	if yc.AgentName != "" {
		cfg.AgentName = yc.AgentName
	}
	if yc.DataDir != "" {
		cfg.DataDir = yc.DataDir
	}

	if yc.ClusterInternal != nil {
		cfg.ClusterInternal = *yc.ClusterInternal
	}

	// Merge labels (YAML labels are base; env vars can override later)
	for k, v := range yc.Labels {
		cfg.Labels[k] = v
	}

	// Parse resources — supports both list format (preferred) and legacy map format.
	switch yc.Resources.Kind {
	case yaml.SequenceNode:
		// List format: [{name: ..., type: ..., hostname: ...}, ...]
		var resources []yamlResource
		if err := yc.Resources.Decode(&resources); err != nil {
			return fmt.Errorf("failed to parse resources list: %w", err)
		}
		for _, res := range resources {
			rc := resourceConfigFromYAML(res.Type, res)
			cfg.Resources = append(cfg.Resources, rc)
		}
	case yaml.MappingNode:
		// Legacy map format: {ssh: {hostname: ...}, postgres: {name: ...}}
		// Deprecated — only supports one resource per type.
		var resources map[string]yamlResourceLegacy
		if err := yc.Resources.Decode(&resources); err != nil {
			return fmt.Errorf("failed to parse resources map: %w", err)
		}
		for resourceType, res := range resources {
			rc := resourceConfigFromYAML(resourceType, yamlResource{
				Name:           res.Name,
				Type:           resourceType,
				Hostname:       res.Hostname,
				Host:           res.Host,
				Port:           res.Port,
				Labels:         res.Labels,
				TunnelHostname: res.TunnelHostname,
			})
			cfg.Resources = append(cfg.Resources, rc)
		}
	}

	return nil
}

// findYAMLFile returns the path to the first YAML config file found.
func findYAMLFile() string {
	// Check explicit env var first
	if path := os.Getenv("BAMF_CONFIG_FILE"); path != "" {
		if _, err := os.Stat(path); err == nil {
			return path
		}
		return "" // Explicit path set but file doesn't exist
	}

	// Search default locations
	for _, path := range yamlSearchPaths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

// resourceConfigFromYAML converts a yamlResource to a ResourceConfig.
//
// resourceType is either from the list entry's "type" field or the legacy
// map key. SSH default port 22. Resource name = hostname when not specified.
func resourceConfigFromYAML(resourceType string, res yamlResource) ResourceConfig {
	rc := ResourceConfig{
		ResourceType:   resourceType,
		Labels:         res.Labels,
		TunnelHostname: res.TunnelHostname,
	}

	if rc.Labels == nil {
		rc.Labels = make(map[string]string)
	}

	// Hostname: prefer "hostname" field, fall back to "host"
	rc.Hostname = res.Hostname
	if rc.Hostname == "" {
		rc.Hostname = res.Host
	}

	// Port: use explicit value, or default for the resource type
	rc.Port = res.Port
	if rc.Port == 0 {
		rc.Port = defaultPorts[resourceType]
	}

	// Name: use explicit value, or derive from hostname
	rc.Name = res.Name
	if rc.Name == "" {
		rc.Name = rc.Hostname
	}

	// For HTTP resources, default tunnel_hostname to the resource name
	if rc.TunnelHostname == "" && (resourceType == "http" || resourceType == "http-audit" || resourceType == "https") {
		rc.TunnelHostname = rc.Name
	}

	return rc
}

// applyEnvOverrides applies environment variable overrides to the config.
// Env vars always take precedence over YAML values.
func (cfg *Config) applyEnvOverrides() {
	// BAMF_PLATFORM_URL takes precedence over BAMF_API_URL
	if url := os.Getenv("BAMF_PLATFORM_URL"); url != "" {
		cfg.APIServerURL = url
	} else if url := os.Getenv("BAMF_API_URL"); url != "" {
		cfg.APIServerURL = url
	}

	if token := os.Getenv("BAMF_JOIN_TOKEN"); token != "" {
		cfg.JoinToken = token
	}
	if name := os.Getenv("BAMF_AGENT_NAME"); name != "" {
		cfg.AgentName = name
	}
	if dir := os.Getenv("BAMF_DATA_DIR"); dir != "" {
		cfg.DataDir = dir
	}

	if v := os.Getenv("BAMF_CLUSTER_INTERNAL"); v != "" {
		cfg.ClusterInternal = v == "true" || v == "1"
	}

	// Merge env labels into existing labels (env overrides YAML per-key)
	if labelsEnv := os.Getenv("BAMF_LABELS"); labelsEnv != "" {
		for k, v := range parseLabels(labelsEnv) {
			cfg.Labels[k] = v
		}
	}

	// Parse resources from env (replaces YAML resources if set)
	if resourcesEnv := os.Getenv("BAMF_RESOURCES"); resourcesEnv != "" {
		resources, err := parseResources(resourcesEnv)
		if err == nil && len(resources) > 0 {
			cfg.Resources = resources
		}
	}

	// Connection tuning env vars
	if v := os.Getenv("BAMF_HEARTBEAT_INTERVAL"); v != "" {
		cfg.HeartbeatInterval = parseDuration(v, cfg.HeartbeatInterval)
	}
	if v := os.Getenv("BAMF_RECONNECT_BASE_DELAY"); v != "" {
		cfg.ReconnectBaseDelay = parseDuration(v, cfg.ReconnectBaseDelay)
	}
	if v := os.Getenv("BAMF_RECONNECT_MAX_DELAY"); v != "" {
		cfg.ReconnectMaxDelay = parseDuration(v, cfg.ReconnectMaxDelay)
	}
}

func parseDuration(s string, fallback time.Duration) time.Duration {
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	if seconds, err := strconv.Atoi(s); err == nil {
		return time.Duration(seconds) * time.Second
	}
	return fallback
}

func parseLabels(s string) map[string]string {
	labels := make(map[string]string)
	if s == "" {
		return labels
	}
	for _, pair := range strings.Split(s, ",") {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) == 2 {
			labels[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return labels
}

func parseResources(s string) ([]ResourceConfig, error) {
	// Simple format: name:type:host:port,name2:type2:host2:port2
	var resources []ResourceConfig

	for _, entry := range strings.Split(s, ",") {
		parts := strings.Split(entry, ":")
		if len(parts) < 4 {
			continue
		}

		port, err := strconv.Atoi(parts[3])
		if err != nil {
			return nil, fmt.Errorf("invalid port for resource %s: %w", parts[0], err)
		}

		resources = append(resources, ResourceConfig{
			Name:         parts[0],
			ResourceType: parts[1],
			Hostname:     parts[2],
			Port:         port,
			Labels:       make(map[string]string),
		})
	}

	return resources, nil
}
