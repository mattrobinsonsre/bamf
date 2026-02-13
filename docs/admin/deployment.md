# Production Deployment

Deploy BAMF to a production Kubernetes cluster using Helm.

## Prerequisites

- Kubernetes 1.27+ with Istio installed
- `helm` 3.12+
- cert-manager (for TLS certificates)
- A domain with DNS control
- External PostgreSQL (RDS, Aurora, Cloud SQL, etc.) recommended for production
- External Redis (ElastiCache, Memorystore, etc.) recommended for production

## Helm Installation

```zsh
helm install bamf oci://ghcr.io/mattrobinsonsre/bamf/charts/bamf \
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
    default_provider: auth0
    oidc:
      auth0:
        issuer_url: https://myorg.us.auth0.com/
        existingSecret: bamf-auth0-credentials
        clientIdKey: client-id
        clientSecretKey: client-secret
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
    certificate_ttl_hours: 12          # User cert lifetime
    service_certificate_ttl_hours: 24  # Agent/bridge cert lifetime
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

### Bundled (Dev/Staging)

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

Three credential options:

```yaml
# Option 1: Existing K8s Secret
postgresql:
  external:
    enabled: true
    host: bamf-db.example.com
    existingSecret: bamf-database-credentials
    existingSecretKey: password

# Option 2: ExternalSecrets operator
postgresql:
  external:
    enabled: true
    host: bamf-db.example.com
    externalSecret:
      enabled: true
      secretStoreRef:
        name: aws-secrets-manager
        kind: ClusterSecretStore
      remoteRef:
        key: production/bamf/database
        property: password

# Option 3: Inline (avoid in GitOps)
postgresql:
  external:
    enabled: true
    host: bamf-db.example.com
    password: "secret"
```

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

Create these DNS records pointing to your Istio Gateway's external IP:

| Record | Type | Value |
|--------|------|-------|
| `bamf.example.com` | A | Gateway external IP |
| `*.tunnel.bamf.example.com` | A | Gateway external IP |

## Gateway Configuration

```yaml
gateway:
  enabled: true
  className: istio
  hostname: bamf.example.com
  tunnelDomain: tunnel.bamf.example.com
  httpsPort: 443
```

The chart creates:
- Istio Gateway with HTTP, tunnel-HTTPS, and TLS-passthrough listeners
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
    repository: "oci://ghcr.io/mattrobinsonsre/bamf/charts"

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

# Check Gateway
kubectl -n bamf get gateway

# Test API health
curl https://bamf.example.com/health

# Test readiness
curl https://bamf.example.com/ready
```
