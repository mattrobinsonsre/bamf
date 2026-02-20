# Production Deployment

Deploy BAMF to a production Kubernetes cluster using Helm.

## Prerequisites

- Kubernetes 1.27+ with **Traefik v3** or **Istio** ingress controller (see
  [Ingress Requirements](#ingress-requirements) below)
- `helm` 3.12+
- cert-manager (for TLS certificates)
- A domain with DNS control
- Wildcard DNS for `*.tunnel.your-domain.com` (A record or CNAME)
- External PostgreSQL (RDS, Aurora, Cloud SQL, etc.) recommended for production
- External Redis (ElastiCache, Memorystore, etc.) recommended for production

### Ingress Requirements

BAMF's tunnel architecture requires **SNI-based TLS passthrough** — the
ability to route raw TCP connections to specific backend pods based on the TLS
Server Name Indication (SNI) hostname, without terminating TLS. This is used
to route CLI and agent tunnel connections to individual bridge pods
(`0.bridge.tunnel.example.com` → `bamf-bridge-0`,
`1.bridge.tunnel.example.com` → `bamf-bridge-1`, etc.).

Standard Kubernetes `Ingress` resources only support HTTP(S) routing and
cannot express SNI-based TCP passthrough. BAMF requires one of:

| Provider | CRD | K8s Feature | Notes |
|----------|-----|-------------|-------|
| **Traefik v3** (default) | `IngressRouteTCP` | Stable CRD since Traefik v3.0 | Ships with k3s, Rancher Desktop. Zero additional setup on these clusters. |
| **Istio** | `TLSRoute` (Gateway API) | Experimental channel | Requires `istioctl install` + Gateway API CRDs from the experimental channel (`TLSRoute` is not yet GA in the Gateway API spec). |

**BAMF cannot run with:**
- Kubernetes `Ingress` resources alone (no TCP/SNI routing)
- nginx-ingress-controller (no native SNI passthrough for arbitrary TCP)
- Cloud provider HTTP load balancers (ALB, Cloud Load Balancing) without an
  additional L4/TCP load balancer for tunnel traffic
- Non-Kubernetes environments without equivalent custom infrastructure

If your cluster already has Traefik v3 (common with k3s, Rancher, RKE2), BAMF
works with no additional ingress setup. For clusters with Istio, set
`gateway.provider: istio` in values — see
[Gateway Configuration](#gateway-configuration) below.

## Helm Installation

```zsh
helm install bamf oci://ghcr.io/mattrobinsonsre/bamf \
  --namespace bamf --create-namespace \
  --values production-values.yaml
```

### Minimal Production Values

```yaml
# production-values.yaml
gateway:
  hostname: bamf.example.com
  tunnelDomain: tunnel.bamf.example.com

postgresql:
  bundled:
    enabled: false
  external:
    enabled: true
    host: bamf-db.cluster-xxx.us-east-1.rds.amazonaws.com
    port: 5432
    database: bamf
    username: bamf
    sslmode: require
    existingSecret: bamf-database-credentials
    existingSecretKey: password

redis:
  bundled:
    enabled: false
  external:
    enabled: true
    host: bamf-redis.xxx.cache.amazonaws.com
    port: 6379

auth:
  local:
    enabled: false
  sso:
    defaultProvider: auth0
    oidc:
      auth0:
        enabled: true
        issuerUrl: https://myorg.us.auth0.com/
        existingSecret: bamf-auth0-credentials
        existingSecretKey: client_secret
```

## Component Configuration

### API Server

```yaml
api:
  replicas: 2
  resources:
    requests: { cpu: 250m, memory: 512Mi }
    limits: { cpu: "1", memory: 1Gi }
  autoscaling:
    enabled: true
    minReplicas: 2
    maxReplicas: 10
  config:
    log_level: info
    certificates:
      user_ttl_hours: 12               # User cert lifetime
      agent_ttl_hours: 8760            # Agent cert lifetime (1 year)
      bridge_ttl_hours: 24             # Bridge cert lifetime
    audit:
      retention_days: 90
```

### Bridge

```yaml
bridge:
  replicas: 2
  maxReplicas: 20
  resources:
    requests: { cpu: 250m, memory: 256Mi }
    limits: { cpu: "2", memory: 1Gi }
  autoscaling:
    enabled: true
    minReplicas: 2
    maxReplicas: 20
```

The bridge is deployed as a StatefulSet with per-pod Services for SNI routing.
`maxReplicas` controls how many Services and TLSRoutes are pre-created.

### Web UI

```yaml
web:
  standalone:
    enabled: true
  replicas: 2
  resources:
    requests: { cpu: 50m, memory: 64Mi }
    limits: { cpu: 200m, memory: 128Mi }
```

## PostgreSQL

BAMF stores all durable state in PostgreSQL: user accounts, RBAC roles, agent
registrations, audit logs, session recordings, and a backup copy of the CA
keypair. For production, use a managed database service with automated backups,
replication, and failover.

### Bundled (Dev/Staging Only)

The bundled option deploys a single-replica PostgreSQL via the bitnami subchart.
**Do not use this in production** — it has no replication, no automated backups,
and data lives on a single PVC.

```yaml
postgresql:
  bundled:
    enabled: true
    auth:
      database: bamf
      username: bamf
    primary:
      persistence:
        size: 20Gi
```

### External (Production)

Use a managed PostgreSQL service with Multi-AZ or multi-replica configuration
for high availability:

| Provider | Service | Documentation |
|----------|---------|---------------|
| AWS | RDS for PostgreSQL or Aurora PostgreSQL | [RDS User Guide](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/CHAP_PostgreSQL.html), [Aurora PostgreSQL Guide](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/Aurora.AuroraPostgreSQL.html) |
| GCP | Cloud SQL for PostgreSQL | [Cloud SQL Docs](https://cloud.google.com/sql/docs/postgres) |
| Azure | Azure Database for PostgreSQL Flexible Server | [Azure PostgreSQL Docs](https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/overview) |
| Self-hosted | Patroni, Crunchy PGO, or CloudNativePG | [CloudNativePG](https://cloudnative-pg.io/documentation/) |

**Recommended configuration:**

- **PostgreSQL 16+** (BAMF is tested against 16)
- **Multi-AZ / high availability** enabled for automatic failover
- **Automated backups** with point-in-time recovery (PITR) — see
  [Backup & Restore](../operations/backup-restore.md)
- **Encryption in transit** (`sslmode: require` or `verify-full`)
- **Encryption at rest** enabled (default on all major providers)
- **Instance sizing**: Start with 2 vCPU / 4 GB RAM (e.g., AWS `db.t4g.medium`,
  GCP `db-custom-2-4096`). Scale based on audit log volume and concurrent
  sessions. BAMF's database load is modest — most hot-path operations use Redis.
- **Storage**: 20 GB minimum. Audit logs and session recordings are the primary
  storage consumers; size based on your retention policy (default 90 days).
- **Read replica** (optional): Configure `postgresql.external.readReplica` to
  offload read-heavy queries (audit log, session listing) from the primary.

**Credential options** (pick one):

```yaml
# Option 1: Existing K8s Secret (recommended for GitOps)
postgresql:
  external:
    enabled: true
    host: bamf-db.cluster-xxx.us-east-1.rds.amazonaws.com
    port: 5432
    database: bamf
    username: bamf
    sslmode: require
    existingSecret: bamf-database-credentials
    existingSecretKey: password

# Option 2: ExternalSecrets operator (syncs from cloud secret manager)
postgresql:
  external:
    enabled: true
    host: bamf-db.cluster-xxx.us-east-1.rds.amazonaws.com
    port: 5432
    database: bamf
    username: bamf
    sslmode: require
    externalSecret:
      enabled: true
      secretStoreRef:
        name: aws-secrets-manager
        kind: ClusterSecretStore
      remoteRef:
        key: production/bamf/database
        property: password

# Option 3: Inline password (avoid in GitOps — stored in values file)
postgresql:
  external:
    enabled: true
    host: bamf-db.cluster-xxx.us-east-1.rds.amazonaws.com
    port: 5432
    database: bamf
    username: bamf
    sslmode: require
    password: "secret"
```

## Redis

BAMF uses Redis for session cache, agent heartbeat tracking, resource catalog,
bridge registration, and real-time pub/sub. Redis data is ephemeral by design —
a Redis restart causes temporary disruption (agents re-register, users re-login)
but no permanent data loss. Despite this, production deployments should use a
resilient Redis cluster to avoid unnecessary disruption.

### Bundled (Dev/Staging Only)

The bundled option deploys a single-replica Redis via the bitnami subchart.
**Do not use this in production.**

```yaml
redis:
  bundled:
    enabled: true
```

### External (Production)

Use a managed Redis service with replication and automatic failover:

| Provider | Service | Documentation |
|----------|---------|---------------|
| AWS | Amazon ElastiCache for Redis (cluster mode) | [ElastiCache User Guide](https://docs.aws.amazon.com/AmazonElastiCache/latest/red-ug/WhatIs.html) |
| AWS | Amazon MemoryDB for Redis | [MemoryDB Guide](https://docs.aws.amazon.com/memorydb/latest/devguide/what-is-memorydb-for-redis.html) |
| GCP | Memorystore for Redis | [Memorystore Docs](https://cloud.google.com/memorystore/docs/redis) |
| Azure | Azure Cache for Redis | [Azure Cache Docs](https://learn.microsoft.com/en-us/azure/azure-cache-for-redis/cache-overview) |
| Self-hosted | Redis Sentinel or Redis Cluster | [Redis Sentinel Docs](https://redis.io/docs/latest/operate/oss_and_stack/management/sentinel/) |

**Recommended configuration:**

- **Redis 7+**
- **Replication enabled** with at least one replica for automatic failover
  (e.g., ElastiCache Multi-AZ with auto-failover, Memorystore Standard Tier)
- **Encryption in transit** (TLS) — configure via `redis.external.tls: true`
  if your provider requires it
- **Encryption at rest** enabled (default on most providers)
- **Instance sizing**: Start with 1-2 GB memory (e.g., AWS `cache.t4g.small`,
  GCP `M1` 1 GB). BAMF's Redis usage is lightweight — mostly small keys for
  sessions, heartbeats, and resource metadata. Scale based on concurrent
  agent and session count.
- **Eviction policy**: `noeviction` (default). BAMF relies on TTL-based expiry;
  eviction would cause unexpected session or heartbeat loss.
- **Persistence**: Optional. Redis data is recoverable (agents re-register,
  users re-login), so AOF/RDB persistence adds latency without meaningful
  benefit. Disable persistence if your provider allows it.

**Helm configuration:**

```yaml
redis:
  bundled:
    enabled: false
  external:
    enabled: true
    host: bamf-redis.xxx.cache.amazonaws.com
    port: 6379
    # If authentication is required:
    existingSecret: bamf-redis-credentials
    existingSecretKey: password
```

**ElastiCache cluster mode note:** If using ElastiCache with cluster mode
enabled, use the configuration endpoint as the `host` value. BAMF uses simple
key/value operations and pub/sub — no multi-key transactions — so cluster mode
works without issues.

## TLS Certificates

### cert-manager (Recommended)

```yaml
tls:
  certManager:
    enabled: true
    issuerRef:
      name: letsencrypt-prod
      kind: ClusterIssuer
```

This creates Certificate resources for both `bamf.example.com` and
`*.tunnel.bamf.example.com`. The wildcard cert requires DNS-01 challenge.

### Existing Secrets

```yaml
tls:
  certManager:
    enabled: false
  existingSecret: bamf-tls
  existingTunnelSecret: bamf-tunnel-wildcard-tls
```

## Internal CA

Three options for the BAMF internal CA (used for tunnel authentication):

```yaml
# Option 1: Helm-generated (default)
ca:
  provider: helm

# Option 2: cert-manager managed
ca:
  provider: cert-manager

# Option 3: Bring your own CA
ca:
  provider: existing
  existing:
    secretName: my-corporate-ca
    certKey: tls.crt
    keyKey: tls.key
```

See [Certificate Management](certificates.md) for details.

## DNS Setup

Create these DNS records pointing to your ingress controller's external IP:

| Record | Type | Value |
|--------|------|-------|
| `bamf.example.com` | A | Ingress controller external IP |
| `*.tunnel.bamf.example.com` | A | Ingress controller external IP |
| `*.bridge.tunnel.bamf.example.com` | A | Ingress controller external IP |

## Gateway Configuration

BAMF supports two ingress routing providers, selectable via `gateway.provider`:

### Traefik (Default)

Uses Traefik v3 native CRDs (IngressRoute / IngressRouteTCP). Zero additional
setup on clusters that already have Traefik (e.g., Rancher Desktop, k3s).

```yaml
gateway:
  enabled: true
  provider: traefik
  hostname: bamf.example.com
  tunnelDomain: tunnel.bamf.example.com
  traefik:
    entryPoint: websecure
```

The chart creates:
- IngressRoute for API and Web UI (`bamf.example.com`)
- IngressRoute for web app proxy (`*.tunnel.bamf.example.com`)
- IngressRouteTCP per bridge pod for tunnel traffic (SNI passthrough)

### Alternative: Istio Gateway API

Uses Gateway API resources (Gateway, HTTPRoute, TLSRoute) with the Istio
controller. Requires Istio and Gateway API CRDs (experimental channel for
TLSRoute support).

```yaml
gateway:
  enabled: true
  provider: istio
  className: istio
  hostname: bamf.example.com
  tunnelDomain: tunnel.bamf.example.com
```

The chart creates:
- Istio Gateway with HTTPS and TLS-passthrough listeners
- HTTPRoute for API and Web UI (`bamf.example.com`)
- HTTPRoute for web app proxy (`*.tunnel.bamf.example.com`)
- TLSRoute per bridge pod for tunnel traffic (SNI passthrough)

## Database Migrations

Migrations run automatically as a Helm pre-install/pre-upgrade hook (for
external PostgreSQL). For bundled PostgreSQL, the migration job includes an
init container that waits for PostgreSQL to be ready.

## Subchart Usage

BAMF can be used as a dependency in a parent chart:

```yaml
# parent-chart/Chart.yaml
dependencies:
  - name: bamf
    version: "1.x.x"
    repository: "oci://ghcr.io/mattrobinsonsre"

# parent-chart/values.yaml
bamf:
  fullnameOverride: "myapp-bamf"
  serviceAccount:
    create: false
    name: "myapp-shared-sa"
```

## Verification

After deployment:

```zsh
# Check pods
kubectl -n bamf get pods

# Check routing resources (Traefik)
kubectl -n bamf get ingressroute,ingressroutetcp

# Or check routing resources (Istio)
kubectl -n bamf get gateway,httproute,tlsroute

# Test API health
curl https://bamf.example.com/health

# Test readiness
curl https://bamf.example.com/ready
```
