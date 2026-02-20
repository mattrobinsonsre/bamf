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
  pdb:
    enabled: true
    minAvailable: 1
  terminationGracePeriodSeconds: 120
  preStopSleepSeconds: 15          # Seconds to sleep before SIGTERM
  config:
    log_level: info                # error, warning, info, debug
    certificates:
      user_ttl_hours: 12           # User certificate lifetime
      agent_ttl_hours: 8760        # Agent cert lifetime (1 year)
      bridge_ttl_hours: 24         # Bridge cert lifetime
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
    targetTunnelsPerPod: 50          # Custom metric scaling (requires prometheus-adapter)
    nonMigratableOversubscribeFactor: 1.5  # Oversubscription for ssh-audit sessions
  pdb:
    enabled: true
    minAvailable: 1
  terminationGracePeriodSeconds: 1800  # 30 min for non-migratable sessions; lower for spot (120)
  bootstrap:
    enabled: true                  # Token-based cert bootstrap
```

## Web UI

```yaml
web:
  standalone: false                  # Enable separate web deployment
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
  config:
    name: ""                       # Agent name (required when enabled)
    labels: {}                     # Agent labels (key: value)
    resources: []                  # Resource definitions (list)
  platformUrl: ""                  # BAMF API URL
  joinToken: ""                    # Join token for registration
  clusterInternal: false           # Use in-cluster API URL
  kubernetes:
    impersonation:
      enabled: false               # Create K8s impersonation RBAC
  dataDir: /var/lib/bamf-agent     # Certificate storage directory
```

## PostgreSQL

```yaml
postgresql:
  # Option A: Bundled (dev/staging)
  bundled:
    enabled: false
    image:
      repository: public.ecr.aws/docker/library/postgres
      tag: "16-alpine"
    auth:
      database: bamf
      username: bamf
      password: ""               # Required when bundled
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
        property: password
    readReplica:                   # Optional read replica
      enabled: false
      host: ""                     # Required when enabled
      port: ""                     # Inherits from external.port if empty
      database: ""                 # Inherits from external.database if empty
      username: ""                 # Inherits from external.username if empty
      sslmode: ""                  # Inherits from external.sslmode if empty
      existingSecret: ""
      existingSecretKey: password
```

## Redis

```yaml
redis:
  # Option A: Bundled (dev/staging)
  bundled:
    enabled: false
    image:
      repository: public.ecr.aws/docker/library/redis
      tag: "7-alpine"
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

The internal CA is generated automatically at first install and stored in a
Kubernetes Secret. See [Certificate Management](../admin/certificates.md) for
CA options (Helm-generated, cert-manager, or existing).

## Authentication

```yaml
auth:
  local:
    enabled: true                  # Enable local password auth
  sso:
    defaultProvider: ""            # Default provider for login (e.g., "auth0")
    oidc: {}                       # Map of OIDC providers keyed by name
    # Example:
    #   oidc:
    #     auth0:
    #       enabled: true
    #       displayName: "Corporate SSO"
    #       issuerUrl: https://myorg.us.auth0.com/
    #       clientId: YOUR_CLIENT_ID
    #       audience: https://bamf.example.com/api
    #       scopes: [openid, profile, email]
    #       groupsClaim: groups
    #       existingSecret: bamf-auth0
    #       existingSecretKey: client_secret
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
