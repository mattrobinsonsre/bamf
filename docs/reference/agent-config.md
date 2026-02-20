# Agent Configuration Reference

## Config File

Default location: `/etc/bamf/agent.yaml`

```yaml
# BAMF API server URL (required)
platform_url: https://bamf.example.com

# Join token for initial registration (required for first run, optional after)
join_token: ${BAMF_JOIN_TOKEN}

# Agent name (optional — auto-generated from hostname if omitted)
# agent_name: my-agent

# Data directory for certificates and state
# data_dir: /var/lib/bamf-agent

# Agent-level labels (applied to all resources)
# labels:
#   region: us-east-1

# Resource definitions (list format — preferred)
resources:
  # SSH resource
  - name: web-prod-01
    type: ssh
    hostname: web-prod-01.internal   # SSH target hostname
    labels:
      env: prod
      team: platform

  # SSH with session recording
  - name: bastion-prod
    type: ssh-audit
    hostname: bastion.internal
    labels:
      env: prod

  # PostgreSQL database
  - name: orders-db
    type: postgres
    host: localhost                   # Database host (from agent's perspective)
    port: 5432                       # Database port
    labels:
      env: prod

  # PostgreSQL with query audit
  - name: prod-db
    type: postgres-audit
    host: prod-db.internal
    port: 5432
    labels:
      env: prod

  # MySQL database
  - name: app-mysql
    type: mysql
    host: mysql.internal
    port: 3306
    labels:
      env: staging

  # HTTP web application
  - name: grafana
    type: http
    tunnel_hostname: grafana         # Becomes grafana.tunnel.bamf.example.com
    host: grafana.internal.corp      # Internal target hostname
    port: 3000                       # Internal target port
    labels:
      env: prod

  # HTTP web application with full request/response recording
  - name: admin-panel
    type: http-audit
    tunnel_hostname: admin-panel
    host: admin.internal.corp
    port: 8080
    labels:
      env: prod

  # HTTPS target (agent connects to target over HTTPS)
  - name: vault-ui
    type: https
    tunnel_hostname: vault
    host: vault.internal.corp
    port: 8200
    labels:
      env: prod

  # Kubernetes API
  - name: prod-cluster
    type: kubernetes
    host: kubernetes.default.svc     # K8s API address
    port: 6443
    labels:
      env: prod
```

### Legacy Map Format (Deprecated)

The map format is still supported for backward compatibility but is deprecated.
It keys resources by type, which limits you to one resource per type:

```yaml
# DEPRECATED — use list format above
resources:
  ssh:
    hostname: web-prod-01.internal
    labels:
      env: prod
  postgres:
    name: orders-db
    host: localhost
    port: 5432
```

## Supported Resource Types

| Type | Default Port | Description |
|------|-------------|-------------|
| `ssh` | 22 | SSH access (byte-splice tunnel) |
| `ssh-audit` | 22 | SSH with terminal session recording (asciicast v2) |
| `postgres` | 5432 | PostgreSQL database access |
| `postgres-audit` | 5432 | PostgreSQL with query audit logging |
| `mysql` | 3306 | MySQL database access |
| `mysql-audit` | 3306 | MySQL with query audit logging |
| `http` | 80 | HTTP web application proxy |
| `http-audit` | 80 | HTTP with full request/response recording |
| `https` | 443 | HTTPS web application proxy (agent → target over TLS) |
| `kubernetes` | 6443 | Kubernetes API proxy with impersonation |

## Resource Fields

### Common Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Unique resource name |
| `type` | Yes* | Resource type (see table above). *Not needed in legacy map format. |
| `labels` | No | Key-value pairs for RBAC matching |

### SSH Resources (`ssh`, `ssh-audit`)

| Field | Required | Description |
|-------|----------|-------------|
| `hostname` | Yes | SSH target hostname |

### TCP Resources (`postgres`, `postgres-audit`, `mysql`, `mysql-audit`)

| Field | Required | Description |
|-------|----------|-------------|
| `host` | Yes | Target hostname (from agent's network) |
| `port` | No | Target port (defaults per type — see table above) |

### HTTP Resources (`http`, `http-audit`, `https`)

| Field | Required | Description |
|-------|----------|-------------|
| `tunnel_hostname` | Yes | Subdomain for `*.tunnel.domain` |
| `host` | Yes | Internal target hostname |
| `port` | No | Internal target port (defaults: 80 for http/http-audit, 443 for https) |

### Kubernetes Resources

| Field | Required | Description |
|-------|----------|-------------|
| `host` | Yes | K8s API address |
| `port` | No | K8s API port (default: 6443) |

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
| `BAMF_PLATFORM_URL` | API server URL (overrides config) |
| `BAMF_API_URL` | API server URL (alias, `BAMF_PLATFORM_URL` takes precedence) |
| `BAMF_JOIN_TOKEN` | Join token for registration |
| `BAMF_AGENT_NAME` | Agent name (overrides config) |
| `BAMF_DATA_DIR` | Data directory (overrides config) |
| `BAMF_CLUSTER_INTERNAL` | Use in-cluster bridge hostnames (`true`/`false`) |
| `BAMF_LABELS` | Agent labels (key=value,key=value) |
| `BAMF_RESOURCES` | Resource definitions (JSON) |
| `BAMF_HEARTBEAT_INTERVAL` | Heartbeat interval (e.g., `60s`) |
| `BAMF_RECONNECT_BASE_DELAY` | Reconnect base delay (e.g., `1s`) |
| `BAMF_RECONNECT_MAX_DELAY` | Reconnect max delay (e.g., `5m`) |

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
