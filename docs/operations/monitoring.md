# Monitoring

## Prometheus Metrics

BAMF exposes Prometheus metrics with the `bamf_` prefix. Enable ServiceMonitor
creation in the Helm values:

```yaml
metrics:
  enabled: true
  serviceMonitor:
    enabled: true
```

### Key Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `bamf_http_requests_total` | Counter | Total HTTP requests by method, path, status |
| `bamf_http_request_duration_seconds` | Histogram | Request latency |
| `bamf_active_sessions` | Gauge | Currently active tunnel sessions |
| `bamf_active_tunnels` | Gauge | Currently active tunnels per bridge |
| `bamf_agents_online` | Gauge | Number of online agents |
| `bamf_certificate_issued_total` | Counter | Certificates issued by type |
| `bamf_auth_login_total` | Counter | Login attempts by provider and result |

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

A request ID (UUID) is generated at the edge and propagated via
`X-Request-ID` header through all components. Use it to correlate logs
across API → bridge → agent for a single request.

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
