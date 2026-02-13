# Scaling

BAMF components scale independently based on their workload characteristics.

## Component Scaling

### API Server

The API server is stateless — any pod handles any request. Scale on request
volume:

```yaml
api:
  autoscaling:
    enabled: true
    minReplicas: 2
    maxReplicas: 10
    targetCPUUtilizationPercentage: 70
    targetMemoryUtilizationPercentage: 80
```

The API handles both management API requests and HTTP proxy traffic (web apps,
Kubernetes access). If proxy traffic is heavy, increase `maxReplicas`.

### Bridge

Bridges are stateful — they hold gRPC streams to agents. Scale on tunnel count:

```yaml
bridge:
  replicas: 2
  maxReplicas: 20
  autoscaling:
    enabled: true
    minReplicas: 2
    maxReplicas: 20
    targetCPUUtilizationPercentage: 70
```

**Important:** `maxReplicas` controls how many per-pod Services and TLSRoutes
are pre-created. Scaling beyond `maxReplicas` requires a Helm upgrade.

Bridge scaling creates new StatefulSet pods. Each pod gets a pre-created Service
and TLSRoute, so routing works immediately on scale-up.

### Web UI

The web UI serves static assets. Minimal resource requirements:

```yaml
web:
  replicas: 2
  resources:
    requests: { cpu: 50m, memory: 64Mi }
```

### Agents

Agents are not horizontally scaled in the traditional sense. Each agent
represents a deployment location (a server, a cluster). One agent per location
is typical.

## Pod Disruption Budgets

Both API and bridge have PDBs enabled by default:

```yaml
api:
  podDisruptionBudget:
    enabled: true
    minAvailable: 1

bridge:
  podDisruptionBudget:
    enabled: true
    minAvailable: 1
```

## Graceful Shutdown

All pods use `terminationGracePeriodSeconds: 120` for graceful shutdown:

- **API pods**: 15s preStop sleep (drain load balancer) + finish in-flight
  requests
- **Bridge pods**: Notify API, wait for tunnel migration to other bridges
- **Web UI pods**: 5s preStop sleep

Bridge tunnel migration typically completes in seconds. Active tunnels are
transparently moved to other bridge pods before the draining pod exits.

## Database Scaling

### PostgreSQL

- Use read replicas for audit log queries
- Connection pooling with PgBouncer for high connection counts
- Consider RDS/Aurora with automated scaling for production

### Redis

- Redis Cluster for horizontal scaling
- Separate Redis instances for sessions vs pub/sub if needed
- ElastiCache/Memorystore for managed scaling

## Capacity Planning

| Component | Scale Factor | Typical Range |
|-----------|-------------|---------------|
| API | Request volume (management + proxy) | 2-10 pods |
| Bridge | Active tunnel count | 2-20 pods |
| Web UI | Concurrent browser sessions | 2 pods |
| PostgreSQL | Data volume + query load | Single instance + read replicas |
| Redis | Session count + pub/sub channels | Single instance |
