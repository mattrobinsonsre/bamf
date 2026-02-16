# Helm Values Reference

Complete reference for BAMF Helm chart values.

## Gateway

```yaml
gateway:
  enabled: true                    # Create ingress routing resources
  provider: traefik                # traefik (default) or istio
  className: istio                 # GatewayClass name (only used when provider=istio)
  hostname: bamf.example.com       # API + Web UI hostname
  tunnelDomain: tunnel.bamf.example.com  # *.tunnel.domain for bridges + proxy
  ports:
    https: 443                     # HTTPS listener port
  traefik:
    entryPoint: websecure          # Traefik entrypoint name (only used when provider=traefik)
```

When `provider: traefik`, the chart creates Traefik IngressRoute and
IngressRouteTCP CRDs. When `provider: istio`, it creates Gateway API resources
(Gateway, HTTPRoute, TLSRoute) for the Istio controller.

## API Server

```yaml
api:
  replicas: 2
  image:
    repository: ghcr.io/mattrobinsonsre/bamf-api
    tag: ""                        # Defaults to Chart appVersion
  resources:
    requests: { cpu: 250m, memory: 512Mi }
    limits: { cpu: "1", memory: 1Gi }
  autoscaling:
    enabled: true
    minReplicas: 2
    maxReplicas: 10
    targetCPUUtilizationPercentage: 70
    targetMemoryUtilizationPercentage: 80
  podDisruptionBudget:
    enabled: true
    minAvailable: 1
  terminationGracePeriodSeconds: 120
  preStopSleep: 15                 # Seconds to sleep before SIGTERM
  config:
    log_level: info                # error, warning, info, debug
    certificate_ttl_hours: 12      # User certificate lifetime
    agent_certificate_ttl_hours: 8760  # Agent cert lifetime (1 year)
    service_certificate_ttl_hours: 24  # Bridge cert lifetime
    audit:
      retention_days: 90           # Audit log retention
```

## Bridge

```yaml
bridge:
  replicas: 2                      # Initial replicas
  maxReplicas: 20                  # HPA max; controls pre-created Services/TLSRoutes
  image:
    repository: ghcr.io/mattrobinsonsre/bamf-bridge
    tag: ""
  resources:
    requests: { cpu: 250m, memory: 256Mi }
    limits: { cpu: "2", memory: 1Gi }
  tunnelPort: 8443                 # Single port for all tunnel protocols
  autoscaling:
    enabled: true
    minReplicas: 2
    maxReplicas: 20
    targetCPUUtilizationPercentage: 70
  podDisruptionBudget:
    enabled: true
    minAvailable: 1
  terminationGracePeriodSeconds: 120
  bootstrap:
    enabled: true                  # Token-based cert bootstrap
```

## Web UI

```yaml
web:
  standalone:
    enabled: false                 # Enable separate web deployment
  replicas: 2
  image:
    repository: ghcr.io/mattrobinsonsre/bamf-web
    tag: ""
  resources:
    requests: { cpu: 50m, memory: 64Mi }
    limits: { cpu: 200m, memory: 128Mi }
```

## Agent

```yaml
agent:
  enabled: false                   # Enable agent deployment
  replicas: 1
  image:
    repository: ghcr.io/mattrobinsonsre/bamf-agent
    tag: ""
  resources:
    requests: { cpu: 50m, memory: 64Mi }
    limits: { cpu: 200m, memory: 128Mi }
  name: ""                         # Agent name (required)
  platform_url: ""                 # BAMF API URL
  join_token: ""                   # Join token for registration
  labels: {}                       # Agent labels (key: value)
  resources_config: []             # Resource definitions
  clusterInternal:
    enabled: false                 # Use in-cluster API URL
  impersonation:
    enabled: false                 # Create K8s impersonation RBAC
  dataDir: /var/lib/bamf-agent     # Certificate storage directory
```

## PostgreSQL

```yaml
postgresql:
  # Option A: Bundled (dev/staging)
  bundled:
    enabled: false
    image: postgres:16-alpine
    auth:
      database: bamf
      username: bamf
    primary:
      persistence:
        size: 20Gi
        storageClass: ""

  # Option B: External (production)
  external:
    enabled: true
    host: ""
    port: 5432
    database: bamf
    username: bamf
    sslmode: require
    # Credential options (pick one):
    password: ""                   # Inline (avoid in GitOps)
    existingSecret: ""             # Pre-existing K8s Secret name
    existingSecretKey: password    # Key within the Secret
    externalSecret:                # ExternalSecrets operator
      enabled: false
      secretStoreRef:
        name: ""
        kind: ClusterSecretStore
      remoteRef:
        key: ""
        property: ""
    readReplica:                   # Optional read replica
      host: ""
      port: 5432
```

## Redis

```yaml
redis:
  # Option A: Bundled (dev/staging)
  bundled:
    enabled: false
    image: redis:7-alpine
    auth:
      enabled: false
    persistence:
      size: 8Gi

  # Option B: External (production)
  external:
    enabled: true
    host: ""
    port: 6379
    existingSecret: ""
    existingSecretKey: password
```

## Internal CA

```yaml
ca:
  provider: helm                   # helm, cert-manager, or existing
  duration: 87600h                 # 10 years (helm provider)
  certManager:
    issuerKind: ClusterIssuer
    issuerName: ""                 # Empty = chart creates self-signed
    duration: 87600h
    renewBefore: 720h
  existing:
    secretName: ""
    certKey: tls.crt
    keyKey: tls.key
```

## Authentication

```yaml
auth:
  local:
    enabled: true                  # Enable local password auth
  sso:
    default_provider: local
    oidc:
      auth0:
        enabled: false
        issuer_url: ""
        client_id: ""             # From env var (K8s Secret)
        client_secret: ""         # From env var (K8s Secret)
        existingSecret: ""
        clientIdKey: client-id
        clientSecretKey: client-secret
        scopes: [openid, profile, email]
        claims_to_roles: []
```

## TLS

```yaml
tls:
  certManager:
    enabled: true
    issuerRef:
      name: letsencrypt-prod
      kind: ClusterIssuer
  existingSecret: ""               # Override: existing TLS secret
  existingTunnelSecret: ""         # Override: existing wildcard TLS secret
```

## Migrations

```yaml
migrations:
  enabled: true                    # Run Alembic migrations on install/upgrade
```

## Metrics

```yaml
metrics:
  enabled: true
  serviceMonitor:
    enabled: false                 # Create Prometheus ServiceMonitor
```

## Service Account

```yaml
serviceAccount:
  create: true
  name: ""                         # Auto-generated if empty
  annotations: {}
```

## Subchart Usage

When used as a dependency in a parent chart:

```yaml
bamf:
  fullnameOverride: "myapp-bamf"   # Override resource naming
  serviceAccount:
    create: false
    name: "myapp-shared-sa"
```
