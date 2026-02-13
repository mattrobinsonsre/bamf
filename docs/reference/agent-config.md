# Agent Configuration Reference

## Config File

Default location: `/etc/bamf/agent.yaml`

```yaml
# BAMF API server URL (required)
platform_url: https://bamf.example.com

# Join token for initial registration (required for first run, optional after)
join_token: ${BAMF_JOIN_TOKEN}

# Agent name (optional — auto-generated from hostname if omitted)
# name: my-agent

# Data directory for certificates and state
# data_dir: /var/lib/bamf-agent

# Resource definitions
resources:
  # SSH resource
  ssh:
    hostname: web-prod-01.internal   # SSH target hostname
    labels:
      env: prod
      team: platform

  # PostgreSQL database
  postgres:
    name: orders-db                  # Unique resource name
    host: localhost                   # Database host (from agent's perspective)
    port: 5432                       # Database port
    labels:
      env: prod

  # MySQL database
  mysql:
    name: app-mysql
    host: mysql.internal
    port: 3306
    labels:
      env: staging

  # HTTP web application
  http:
    name: grafana
    tunnel_hostname: grafana         # Becomes grafana.tunnel.bamf.example.com
    host: grafana.internal.corp      # Internal target hostname
    port: 3000                       # Internal target port
    protocol: http                   # http or https (agent → target)
    labels:
      env: prod

  # Kubernetes API
  kubernetes:
    name: prod-cluster
    host: kubernetes.default.svc     # K8s API address
    port: 6443
    labels:
      env: prod

  # Generic TCP service
  redis:
    name: cache-redis
    host: redis.internal
    port: 6379
    labels:
      env: prod
```

## Resource Fields

### Common Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes* | Unique resource name. *SSH resources use `hostname` instead. |
| `labels` | No | Key-value pairs for RBAC matching |

### SSH Resources

| Field | Required | Description |
|-------|----------|-------------|
| `hostname` | Yes | SSH target hostname |

### TCP Resources (Database, Generic)

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Unique resource name |
| `host` | Yes | Target hostname (from agent's network) |
| `port` | Yes | Target port |

### HTTP Resources (Web Apps)

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Unique resource name |
| `tunnel_hostname` | Yes | Subdomain for `*.tunnel.domain` |
| `host` | Yes | Internal target hostname |
| `port` | Yes | Internal target port |
| `protocol` | Yes | `http` or `https` |

### Kubernetes Resources

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Unique resource name |
| `host` | Yes | K8s API address |
| `port` | Yes | K8s API port (usually 6443) |

## Labels

Labels are key-value pairs used in RBAC rules:

```yaml
labels:
  env: prod
  team: platform
  region: us-east-1
```

**Reserved label**: `access: everyone` — makes the resource accessible to all
authenticated users.

### Naming Rules

- Keys and values: lowercase alphanumeric and hyphens `[a-z0-9-]+`
- Keys must start with a letter
- Maximum 63 characters per key and value

## Environment Variables

| Variable | Description |
|----------|-------------|
| `BAMF_JOIN_TOKEN` | Join token for registration |
| `BAMF_PLATFORM_URL` | API server URL (overrides config) |
| `BAMF_AGENT_NAME` | Agent name (overrides config) |
| `BAMF_DATA_DIR` | Data directory (overrides config) |
| `BAMF_LOG_LEVEL` | Log level: debug, info, warn, error |

## Certificate Storage

### Filesystem (VM/Bare Metal)

```
/var/lib/bamf-agent/
├── agent.crt      # Agent identity certificate
├── agent.key      # Agent private key
└── ca.crt         # BAMF CA public certificate
```

File permissions: `0600` for key, `0644` for certificates.

### Kubernetes Secret

When running in Kubernetes, certificates are stored in a K8s Secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: bamf-agent-certs
type: Opaque
data:
  agent.crt: <base64>
  agent.key: <base64>
  ca.crt: <base64>
```

The agent auto-detects its environment at startup.

## Heartbeat Behavior

- **Interval**: Every 60 seconds
- **Offline threshold**: 3 missed heartbeats (3 minutes)
- **Content**: Agent status, resource catalog, connection details
- **Reconnection**: Exponential backoff (1s → 5min max) with jitter

## systemd Unit

```ini
# /etc/systemd/system/bamf-agent.service
[Unit]
Description=BAMF Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/bamf-agent --config /etc/bamf/agent.yaml
Restart=always
RestartSec=5
User=bamf-agent
Group=bamf-agent

[Install]
WantedBy=multi-user.target
```
