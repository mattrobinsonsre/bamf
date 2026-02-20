# Getting Started

Get BAMF running in 10 minutes. This guide covers deploying the platform,
registering an agent, and connecting to your first resource.

## Prerequisites

- Kubernetes cluster (1.27+) with **Traefik v3** or **Istio** as the ingress
  controller (see note below)
- `helm` 3.12+
- `kubectl` configured for your cluster
- A domain name with DNS control (for `bamf.example.com` and `*.tunnel.bamf.example.com`)

> **Ingress requirement:** BAMF uses SNI-based TLS passthrough to route TCP
> tunnel traffic directly to individual bridge pods. This requires either
> Traefik v3 IngressRouteTCP or Gateway API TLSRoute (Istio) — capabilities
> that go beyond standard Kubernetes Ingress resources. Clusters running k3s
> or Rancher Desktop ship with Traefik v3 and work out of the box. For Istio,
> you also need Gateway API CRDs (experimental channel) for TLSRoute support.
> See the [Deployment Guide](admin/deployment.md#gateway-configuration) for
> details.

## 1. Install the Platform

```zsh
# Create namespace
kubectl create namespace bamf

# Install with bundled PostgreSQL and Redis (evaluation only — not for production)
helm install bamf oci://ghcr.io/mattrobinsonsre/bamf/charts/bamf \
  --namespace bamf \
  --set gateway.hostname=bamf.example.com \
  --set gateway.tunnelDomain=tunnel.bamf.example.com \
  --set auth.local.enabled=true \
  --set postgresql.bundled.enabled=true \
  --set redis.bundled.enabled=true
```

> **Note:** Bundled PostgreSQL and Redis are single-replica with no replication
> or automated backups. For production, use managed services like AWS RDS and
> ElastiCache. See the [Deployment Guide](admin/deployment.md#postgresql) for
> production database configuration.

Wait for all pods to be ready:

```zsh
kubectl -n bamf get pods -w
```

## 2. Configure DNS

Point your domain to your ingress controller's external IP:

```zsh
# Get the external IP (Traefik — typically in kube-system or traefik namespace)
kubectl get svc -A -l app.kubernetes.io/name=traefik -o jsonpath='{.items[0].status.loadBalancer.ingress[0].ip}'

# Or for Istio
# kubectl -n istio-system get svc istio-ingressgateway -o jsonpath='{.status.loadBalancer.ingress[0].ip}'
```

Create DNS records:
- `bamf.example.com` → Gateway IP (A record)
- `*.tunnel.bamf.example.com` → Gateway IP (A record or CNAME)

## 3. Log In

Open `https://bamf.example.com` in your browser. If local auth is enabled, the
bootstrap job creates a default admin account:

- **Email**: `admin`
- **Password**: `admin`

Change the password immediately after first login.

## 4. Install the CLI

```zsh
# macOS (Apple Silicon)
curl -L https://github.com/mattrobinsonsre/bamf/releases/latest/download/bamf-darwin-arm64 \
  -o /usr/local/bin/bamf && chmod +x /usr/local/bin/bamf

# Verify
bamf version
```

Log in from the CLI:

```zsh
bamf login --api https://bamf.example.com
```

This opens your browser for authentication. After login, BAMF stores your
certificate in `~/.bamf/keys/`.

## 5. Deploy an Agent

Agents run alongside your target resources and register with the platform.

### Create a Join Token

In the web UI, navigate to **Tokens** and click **Create Token**. Or via CLI:

```zsh
bamf tokens create --name my-first-agent --ttl 24h
```

Save the token — it's shown only once.

### Deploy on Kubernetes

```zsh
helm install bamf-agent oci://ghcr.io/mattrobinsonsre/bamf/charts/bamf \
  --namespace bamf \
  --set mode=agent \
  --set agent.name=my-agent \
  --set agent.platform_url=https://bamf.example.com \
  --set agent.join_token=${TOKEN}
```

### Deploy on a VM

```zsh
curl -L https://github.com/mattrobinsonsre/bamf/releases/latest/download/bamf-agent-linux-amd64 \
  -o /usr/local/bin/bamf-agent && chmod +x /usr/local/bin/bamf-agent

cat > /etc/bamf/agent.yaml << 'EOF'
platform_url: https://bamf.example.com
join_token: YOUR_TOKEN_HERE
resources:
  ssh:
    hostname: $(hostname)
    labels:
      env: prod
EOF

# Start the agent
bamf-agent --config /etc/bamf/agent.yaml
```

## 6. Connect to a Resource

Once the agent registers and its resources appear in the web UI:

```zsh
# List available resources
bamf resources

# SSH
bamf ssh user@my-server

# PostgreSQL
bamf psql my-database -U admin -d mydb
```

## Next Steps

- [SSH Guide](guides/ssh.md) — SSH, SCP, SFTP access
- [TCP Tunnels](guides/databases.md) — Databases, Redis, HTTP APIs, any TCP
- [RBAC Guide](admin/rbac.md) — Configure roles and access policies
- [SSO Guide](admin/sso.md) — Set up Auth0, Okta, or other identity providers
- [Deployment Guide](admin/deployment.md) — Production Helm configuration
