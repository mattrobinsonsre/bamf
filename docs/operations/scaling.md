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

Each component has its own shutdown budget:

- **API pods** (`terminationGracePeriodSeconds: 120`): 15s preStop sleep (drain
  load balancer) + finish in-flight requests
- **Bridge pods** (`terminationGracePeriodSeconds: 1800`): Notify API, migrate
  tunnels, wait for non-migratable sessions, upload recordings. The 30-minute
  budget allows interactive `ssh-audit` and web terminal sessions to finish
  naturally before being force-closed.
- **Web UI pods**: 5s preStop sleep, stateless

### Bridge shutdown phases

When a bridge pod receives SIGTERM:

1. **Notify API** — marks this bridge as draining (other bridges take new tunnels)
2. **Migrate tunnels** — API moves migratable tunnels (SSH, database, TCP) to
   other bridges transparently. Typically completes in seconds.
3. **Drain non-migratable sessions** — `ssh-audit`, `web-ssh`, and `web-db`
   sessions cannot be migrated (encryption state lives in the bridge process).
   The bridge sends escalating warnings and waits for them to close naturally.
4. **Upload recordings** — any session recordings from the final sessions are
   uploaded to the API.
5. **Exit**

The shutdown timeout (`terminationGracePeriodSeconds - 5s` buffer) is split
between drain and upload phases. The upload phase gets up to 2 minutes but
never more than 1/3 of the total budget, ensuring drain always has the
majority of the time.

### Tuning the grace period

The default of 1800s (30 minutes) is conservative. If you don't use
`ssh-audit` or web terminal features (all tunnels are migratable), you can
safely lower it:

```yaml
bridge:
  terminationGracePeriodSeconds: 120  # sufficient for migration-only workloads
```

See [Spot Instances](#spot-instances) for recommendations when running on
preemptible compute.

## Spot Instances

All BAMF components are designed for preemptible compute (AWS Spot, GCP
Preemptible, Azure Spot). The key constraint is the 2-minute termination
warning on AWS Spot.

### Recommended configuration

```yaml
api:
  # API is stateless — handles spot termination gracefully with its existing
  # preStop sleep (15s) + in-flight request drain.
  terminationGracePeriodSeconds: 120

bridge:
  # Set to 120s for spot instances. This gives the bridge 115s (120 - 5s
  # buffer) to migrate tunnels and upload any recordings. Migratable tunnel
  # migration typically completes in seconds. Non-migratable sessions
  # (ssh-audit, web-terminal) will be force-closed after ~75s of drain time.
  terminationGracePeriodSeconds: 120

web:
  # Stateless — immediate termination is fine.
  terminationGracePeriodSeconds: 30
```

### What happens on spot termination

**API pods**: Kubernetes sends SIGTERM. The 15s preStop sleep allows the load
balancer to deregister the pod. In-flight requests complete. Other API pods
continue serving. Fully transparent.

**Bridge pods**: Kubernetes sends SIGTERM. The bridge:

1. Notifies the API it's draining — new tunnels go to other bridges
2. Migrates standard tunnels (SSH, database, TCP) to other bridges. The
   reliable stream protocol ensures zero data loss — CLI and agent reconnect
   through the new bridge automatically. Application sessions (psql, ssh)
   see a brief stall (1-2 seconds), not a disconnect.
3. Force-closes non-migratable sessions (`ssh-audit`, `web-ssh`, `web-db`)
   after the drain budget expires. These sessions cannot survive bridge
   failure by design — encryption state lives in the bridge process.
4. Uploads any pending session recordings.

**Trade-off**: With `terminationGracePeriodSeconds: 120`, non-migratable
sessions get approximately 75 seconds to finish before being force-closed
(vs 30 minutes with the default). If you rely heavily on `ssh-audit`
recording, consider running bridge pods on on-demand instances or accepting
that recorded sessions may be interrupted.

**Web UI pods**: Stateless static file server. Immediate termination is fine.

### Node affinity for mixed fleets

If you want bridges on on-demand instances while API pods use spot:

```yaml
api:
  affinity:
    nodeAffinity:
      preferredDuringSchedulingIgnoredDuringExecution:
        - weight: 90
          preference:
            matchExpressions:
              - key: karpenter.sh/capacity-type  # or node.kubernetes.io/instance-type
                operator: In
                values: [spot]

bridge:
  affinity:
    nodeAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
          - matchExpressions:
              - key: karpenter.sh/capacity-type
                operator: In
                values: [on-demand]
```

Or for a fully spot-compatible bridge fleet, just set the lower grace period
and accept that non-migratable sessions may be interrupted.

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
