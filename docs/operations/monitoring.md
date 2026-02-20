# Monitoring

## Prometheus Metrics

### Bridge Metrics

The bridge exposes Prometheus metrics at `:8080/metrics` with the `bamf_bridge_`
prefix. Enable ServiceMonitor creation in the Helm values:

```yaml
metrics:
  enabled: true
  serviceMonitor:
    enabled: true    # Requires Prometheus Operator
```

| Metric | Type | Description |
|--------|------|-------------|
| `bamf_bridge_active_tunnels` | Gauge | Total active tunnels on this bridge pod |
| `bamf_bridge_active_tunnels_by_protocol` | Gauge | Active tunnels by protocol type (label: `protocol`) |
| `bamf_bridge_active_relays` | Gauge | Active HTTP relay connections to agents |
| `bamf_bridge_bytes_sent_total` | Counter | Bytes sent through tunnels (client to agent) |
| `bamf_bridge_bytes_received_total` | Counter | Bytes received through tunnels (agent to client) |
| `bamf_bridge_draining` | Gauge | Whether pod is draining (1=draining, 0=normal) |
| `bamf_bridge_non_migratable_tunnels` | Gauge | Active non-migratable tunnels (ssh-audit, web-ssh, web-db) |

The bridge HPA can scale on `bamf_bridge_active_tunnels` via the Prometheus
adapter (see [Scaling](scaling.md)).

### API Metrics

The API server does not currently expose Prometheus metrics. Monitor the API
via structured logging, health endpoints, and Kubernetes resource metrics
(CPU, memory, request counts from the ingress controller).

## Structured Logging

All components use structured JSON logging in production:

```json
{
  "level": "info",
  "timestamp": "2026-02-13T10:08:10.232Z",
  "app": "bamf-api",
  "logger_name": "bamf.api.routers.auth",
  "event": "login_success",
  "email": "alice@example.com",
  "provider": "auth0",
  "request_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

### Log Levels

| Level | Usage |
|-------|-------|
| `error` | Unexpected failures requiring attention |
| `warning` | Degraded operation, approaching limits |
| `info` | Normal operations: logins, session events, admin actions |
| `debug` | Detailed debugging (disabled in production) |

Configure via Helm:

```yaml
api:
  config:
    log_level: info  # error, warning, info, debug
```

### Request Tracing

Every API request is assigned a request ID (UUID). If the client sends an
`X-Request-ID` header, it is preserved; otherwise, the API generates one. The
request ID is included in structured log entries and returned in the response
`X-Request-ID` header for correlation across components.

## Health Checks

### API Server

| Endpoint | Type | Checks |
|----------|------|--------|
| `/health` | Liveness | API process is running |
| `/ready` | Readiness | Database and Redis are connected |

### Bridge

| Endpoint | Type | Checks |
|----------|------|--------|
| `:8080/health` | Liveness | Bridge process is running |
| `:8080/ready` | Readiness | Registered with API, accepting tunnels |

## Alerting Recommendations

| Alert | Condition | Severity |
|-------|-----------|----------|
| API unhealthy | `/ready` returns non-200 for >1 min | Critical |
| Bridge unhealthy | `/ready` returns non-200 for >1 min | Critical |
| Agent offline | Agent heartbeat missed for >5 min | Warning |
| High error rate | >5% of API requests return 5xx | Warning |
| Certificate expiry | CA cert expires in <30 days | Warning |
| Disk usage | PostgreSQL disk >80% | Warning |

## Audit Log

The audit log records all security and admin events. Query via the API:

```zsh
# Recent events
curl "https://bamf.example.com/api/v1/audit?limit=50" \
  -H "Authorization: Bearer ${TOKEN}"

# Filter by event type
curl "https://bamf.example.com/api/v1/audit?event_type=auth&action=login" \
  -H "Authorization: Bearer ${TOKEN}"

# Filter by time range
curl "https://bamf.example.com/api/v1/audit?since=2026-02-12T00:00:00Z&until=2026-02-13T00:00:00Z" \
  -H "Authorization: Bearer ${TOKEN}"
```

### Event Categories

**Security events**: login, certificate issuance, resource access, session events
**Admin actions**: user/role/token CRUD, configuration changes

### SIEM Integration

Poll the audit API from your SIEM tool using cursor-based pagination:

```zsh
# First page
curl "https://bamf.example.com/api/v1/audit?limit=100"

# Next page
curl "https://bamf.example.com/api/v1/audit?limit=100&cursor=${NEXT_CURSOR}"
```

Audit log retention is configurable (default: 90 days). Older entries are
automatically purged via time-based table partitioning.
