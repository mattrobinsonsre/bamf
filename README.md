# BAMF — Bridge Access Management Fabric

Secure infrastructure access with short-lived certificates, centralized audit,
and zero-trust tunnels. An open-source alternative to Teleport that builds in
minutes with standard toolchains.

BAMF gives your team secure, audited access to SSH servers, databases, Kubernetes
clusters, and internal web applications — all through a single platform with SSO
integration, role-based access control, and session recording.

![Resources](docs/images/ui-resources.png)

## Features

- **SSH access** with short-lived certificates — no static keys, no TOFU prompts.
  Wraps native `ssh`/`scp`/`sftp` so all flags and config work unchanged.
  [Guide](docs/guides/ssh.md)

- **TCP tunnels** for any TCP service — databases, Redis, message brokers,
  custom protocols. Convenience aliases for `bamf psql` and `bamf mysql`;
  `bamf tcp --exec` for everything else. [Guide](docs/guides/databases.md)

- **Kubernetes access** via standard `kubectl` with a kubeconfig entry pointing
  at BAMF. Uses Kubernetes impersonation — works with Helm, k9s, Lens, Terraform.
  [Guide](docs/guides/kubernetes.md)

- **HTTP proxy** for internal web apps and APIs — browser-based (Grafana,
  Jenkins, ArgoCD) and non-browser (curl, scripts, CI/CD). Per-request auth,
  RBAC, header rewriting, and audit logging. [Guide](docs/guides/web-apps.md)

- **SSO integration** with Auth0, Okta, Google, Azure AD, Keycloak (OIDC), and
  any SAML 2.0 identity provider. MFA is delegated to the IdP.
  [Configuration](docs/admin/sso.md)

- **Role-based access control** with allow/deny rules, resource labels, and
  claims-to-roles mapping from identity providers.
  [RBAC guide](docs/admin/rbac.md)

- **Audit logging** of all authentication, authorization, and session events.
  Exportable via REST API for SIEM integration.

- **Session recording** in asciicast v2 format with web-based playback.

- **Certificate-based trust model** — BAMF CA issues short-lived x509 and SSH
  certificates. No long-lived secrets. Session certs encode the authorization
  decision directly, so the bridge relay has zero runtime dependencies.

- **Modern web UI** with real-time resource discovery, session management, and
  role administration.

![Login](docs/images/ui-login.png)

## Architecture

```
                         Public Internet
                                │
               ┌────────────────┴────────────────┐
               │                                 │
               ▼                                 ▼
    ┌──────────────────────────────────────────────────────┐
    │              Istio Gateway (single LB)               │
    │   HTTPRoute (API, Web UI, proxy)  │  TLSRoute (SNI) │
    └──────────┬────────────────────────┴────────┬─────────┘
               │                                 │
               ▼                                 ▼
      ┌──────────────────┐              ┌──────────────────┐
      │   API Server     │              │  Bridge (Go)     │
      │  Python/FastAPI  │◀────────────▶│  StatefulSet     │
      │  CA · RBAC · SSO │              │  tunnel relay    │
      │  HTTP proxy      │              └────────┬─────────┘
      └──────────────────┘                       │
               │                        ┌────────▼─────────┐
      ┌────────▼─────────┐              │   Agents (Go)    │
      │   Web UI (SPA)   │              │   K8s or VM      │
      │   Next.js/React  │              └────────┬─────────┘
      └──────────────────┘                       │
                                         Target Resources
┌──────────────┐                      (servers, databases,
│  CLI (Go)    │                       web apps, K8s clusters)
│  `bamf`      │
└──────┬───────┘
       ├── SSO login ──────▶ API
       └── tunnels ────────▶ Bridge (mTLS)
```

**Go** handles the data path (CLI, bridge, agent) — portable static binaries
with no CGo. **Python** handles the control plane (API, CA, RBAC, SSO, proxy)
where development velocity matters. **Next.js** provides the web UI.

## Quick Start

### Install the CLI

Download the latest release for your platform:

```zsh
# macOS (Apple Silicon)
curl -L https://github.com/mattrobinsonsre/bamf/releases/latest/download/bamf-darwin-arm64 \
  -o /usr/local/bin/bamf && chmod +x /usr/local/bin/bamf

# macOS (Intel)
curl -L https://github.com/mattrobinsonsre/bamf/releases/latest/download/bamf-darwin-amd64 \
  -o /usr/local/bin/bamf && chmod +x /usr/local/bin/bamf

# Linux (amd64)
curl -L https://github.com/mattrobinsonsre/bamf/releases/latest/download/bamf-linux-amd64 \
  -o /usr/local/bin/bamf && chmod +x /usr/local/bin/bamf
```

### Deploy the Platform

```zsh
helm install bamf oci://ghcr.io/mattrobinsonsre/bamf/charts/bamf \
  --namespace bamf --create-namespace \
  --set gateway.hostname=bamf.example.com \
  --set gateway.tunnelDomain=tunnel.bamf.example.com \
  --set postgresql.bundled.enabled=true \
  --set redis.bundled.enabled=true
```

See [Deployment Guide](docs/admin/deployment.md) for production configuration.

### Deploy an Agent

```zsh
# Create a join token
bamf tokens create --name prod-agents --expires-in 24

# Deploy the agent (Kubernetes)
helm install bamf-agent oci://ghcr.io/mattrobinsonsre/bamf/charts/bamf \
  --set mode=agent \
  --set agent.platform_url=https://bamf.example.com \
  --set agent.join_token=${TOKEN}

# Or deploy on a VM
curl -L https://github.com/mattrobinsonsre/bamf/releases/latest/download/bamf-agent-linux-amd64 \
  -o /usr/local/bin/bamf-agent && chmod +x /usr/local/bin/bamf-agent
bamf-agent --platform-url https://bamf.example.com --join-token ${TOKEN}
```

See [Agent Guide](docs/guides/agents.md) for configuration and resource setup.

### Connect

```zsh
# Login
bamf login --api https://bamf.example.com

# SSH
bamf ssh user@web-server

# Database
bamf psql orders-db -U admin -d mydb

# Kubernetes
bamf kube login prod-cluster
kubectl --context prod-cluster get pods

# Web apps — just open in browser
# https://grafana.tunnel.bamf.example.com
```

## Documentation

| Guide | Description |
|-------|-------------|
| [Getting Started](docs/getting-started.md) | 10-minute first deployment |
| **Access Guides** | |
| [SSH](docs/guides/ssh.md) | SSH, SCP, SFTP |
| [TCP Tunnels](docs/guides/databases.md) | Databases, Redis, HTTP APIs, any TCP |
| [Kubernetes](docs/guides/kubernetes.md) | kubectl through BAMF |
| [HTTP Apps](docs/guides/web-apps.md) | Web apps and HTTP APIs (browser + CLI) |
| [Agents](docs/guides/agents.md) | Deploying and managing agents |
| **Administration** | |
| [Deployment](docs/admin/deployment.md) | Production Helm deployment |
| [RBAC](docs/admin/rbac.md) | Roles, rules, labels |
| [SSO](docs/admin/sso.md) | OIDC and SAML configuration |
| [Users](docs/admin/users.md) | User and session management |
| [Certificates](docs/admin/certificates.md) | CA management, cert lifecycle |
| **Operations** | |
| [Backup & Restore](docs/operations/backup-restore.md) | PostgreSQL backup, DR |
| [Scaling](docs/operations/scaling.md) | HPA, bridge scaling |
| [Monitoring](docs/operations/monitoring.md) | Prometheus, structured logging |
| [Upgrading](docs/operations/upgrading.md) | Helm upgrade procedures |
| **Architecture** | |
| [Overview](docs/architecture/overview.md) | System design |
| [Tunnels](docs/architecture/tunnels.md) | Tunnel protocol, reliable streams |
| [Authentication](docs/architecture/authentication.md) | Auth flows, connectors, sessions |
| [Security](docs/architecture/security.md) | Certificate model, trust bootstrap |
| **Reference** | |
| [CLI](docs/reference/cli.md) | Complete CLI reference |
| [API](docs/reference/api.md) | REST API endpoints |
| [Helm Values](docs/reference/helm-values.md) | All Helm values documented |
| [Agent Config](docs/reference/agent-config.md) | Agent YAML config reference |
| [Development](docs/development.md) | Building from source |

## Building from Source

```zsh
# Prerequisites: Go 1.23+, Python 3.13+, Node.js 20+, Docker

# Build Go binaries (local platform)
gmake build-local

# Build Docker images
gmake images

# Run tests
gmake test

# Run linters
gmake lint

# Local development (requires Rancher Desktop + Tilt)
gmake dev
```

See [Development Guide](docs/development.md) for the full setup.

## License

BAMF is licensed under the [GNU General Public License v3.0](LICENSE).
