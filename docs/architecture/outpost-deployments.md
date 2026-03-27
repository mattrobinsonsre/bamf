# Outpost Proxy+Bridge Deployments

BAMF supports deploying regional proxy+bridge clusters (outposts) to minimize
latency for users in different geographic regions. The central API remains the
single source of truth for auth, RBAC, and state management.

**Core principle: every proxy+bridge combination is an outpost**, including
the one co-located with the API. There is no special "central" proxy/bridge —
the co-located deployment is just an outpost that happens to share a cluster
with the API.

## Architecture

```
                         ┌─────────────────────┐
                         │    Central Region    │
                         │  (API + DB + Redis)  │
                         │                      │
                         │  API Server (Python)  │
                         │  PostgreSQL           │
                         │  Redis               │
                         │  Web UI              │
                         └──────────┬───────────┘
                                    │
                    Internal HTTP (authorize, audit, recording)
                                    │
                ┌───────────────────┼───────────────────┐
                │                   │                   │
                ▼                   ▼                   ▼
   ┌────────────────────┐ ┌─────────────────┐ ┌────────────────────┐
   │  Outpost "eu"      │ │ Outpost          │ │  Outpost "apac"    │
   │                    │ │ "us-east"        │ │                    │
   │  Proxy Service     │ │ (co-located)     │ │  Proxy Service     │
   │  Bridge StatefulSet│ │  Proxy + Bridge  │ │  Bridge StatefulSet│
   │                    │ │                  │ │                    │
   │  Agents ←──relay───┤ │  Agents ←─relay──┤ │  Agents ←──relay───┤
   └────────────────────┘ └──────────────────┘ └────────────────────┘
```

## DNS Architecture

Each outpost gets a short DNS-safe name (e.g., `eu`, `us-east`, `apac`)
used as a subdomain prefix for routing.

### Hostnames

**Proxy (web app) hostnames:**
```
*.{outpost_name}.tunnel.{base_domain}
```
Example: `grafana.eu.tunnel.bamf.example.com`

**Bridge (TCP tunnel) hostnames:**
```
{ordinal}.bridge.{outpost_name}.tunnel.{base_domain}
```
Example: `2.bridge.eu.tunnel.bamf.example.com`

### Full Example

```
API deployment (central, one location):
  bamf.example.com                              → API + Web UI

Outpost "us-east" (co-located with API):
  *.us-east.tunnel.bamf.example.com             → US-East proxy
  *.bridge.us-east.tunnel.bamf.example.com      → US-East bridges

Outpost "eu":
  *.eu.tunnel.bamf.example.com                  → EU proxy
  *.bridge.eu.tunnel.bamf.example.com           → EU bridges

Outpost "apac":
  *.apac.tunnel.bamf.example.com                → APAC proxy
  *.bridge.apac.tunnel.bamf.example.com         → APAC bridges

Optional GeoDNS (all outposts):
  *.tunnel.bamf.example.com                     → GeoDNS → nearest proxy
```

### DNS Records Required Per Outpost

**Always required (standard DNS):**

| Record | Type | Value |
|--------|------|-------|
| `*.{name}.tunnel.bamf.example.com` | A/AAAA | Outpost ingress IP |
| `*.bridge.{name}.tunnel.bamf.example.com` | A/AAAA | Outpost ingress IP |

**Optional GeoDNS:**

| Record | Type | Value |
|--------|------|-------|
| `*.tunnel.bamf.example.com` | GeoDNS A/AAAA | Nearest outpost ingress IP |

### Naming Rules

Outpost names follow DNS label rules: `[a-z][a-z0-9-]*`, max 63 characters.
Examples: `eu`, `us-east`, `apac-tokyo`.

## Outpost Registration

### Join Token Flow

Outpost registration mirrors the agent join token pattern:

1. Admin creates an outpost token:
   ```
   POST /api/v1/outpost-tokens
   { "name": "eu-prod-token", "outpost_name": "eu",
     "region": "EU West (Ireland)", "expires_in_hours": 24 }
   → { "token": "bamf_out_abc123...", "id": "...", "name": "eu-prod-token" }
   ```

2. Outpost Helm install includes the token. A pre-install job calls:
   ```
   POST /api/v1/outposts/join
   { "join_token": "bamf_out_abc123..." }
   ```

3. API validates token (hash lookup, expiry, revocation, use count), then
   creates or updates the outpost record and generates two tokens:
   - `internal_token` — proxy authenticates to API internal endpoints
   - `bridge_bootstrap_token` — bridge authenticates for bootstrap

4. Join job stores both tokens as Kubernetes Secrets. Proxy and bridge
   Deployments/StatefulSets mount these secrets.

### Token Formats

| Token | Format | Purpose |
|-------|--------|---------|
| Outpost join token | `bamf_out_{32 hex}` | One-time registration |
| Internal token | `out_int_{32 hex}` | Proxy → API auth |
| Bridge bootstrap token | `out_brg_{32 hex}` | Bridge → API auth |

### Re-join Behavior

Re-joining with the same outpost name regenerates both tokens (invalidating
old ones) and updates the outpost record. Existing proxy and bridge pods
will fail auth and need restart — intentional to prevent two deployments
claiming the same name.

## Multi-Outpost Agent Relay

**Agents maintain relay connections to bridges in every outpost.** This is
the key enabler for "any outpost can serve any resource."

### How It Works

1. Agent starts, connects to API via SSE
2. API sends the agent relay assignments per outpost:
   `{outpost: "eu", bridge: "bridge-0"}, {outpost: "us-east", bridge: "bridge-2"}`
3. Agent dials each assigned bridge and establishes a gRPC relay stream
4. When an outpost's bridge pool changes, API sends updated assignments via SSE
5. Each outpost's bridges now have relay access to the agent

### Redis Tracking

Per-agent relay state per outpost:
```
agent:{id}:relay:{outpost_name} → bridge_id  (TTL = relay health interval)
```

The authorize endpoint reads this key to find which bridge in the proxy's
outpost has the relay to the target agent.

### Connection Count

With S outposts and A agents: S×A relay connections total, distributed across
all bridges. For 3 outposts with 2 bridges each and 100 agents: 300 relay
connections total, ~50 per bridge. Relay connections are lightweight idle gRPC
streams.

## Routing

### HTTP Proxy (Web Apps)

1. Browser hits `grafana.eu.tunnel.bamf.example.com`
2. EU outpost proxy calls API `POST /internal/proxy/authorize` with its
   `outpost_name`
3. API reads `agent:{id}:relay:eu` to find which bridge in the EU outpost
   has the relay to the agent
4. Proxy forwards to the local bridge → agent relay → target

### TCP Tunnels (SSH, DB)

1. CLI calls API `POST /api/v1/connect` with resource name
2. API determines nearest outpost to the CLI client (GeoIP)
3. API selects a bridge in the chosen outpost
4. API issues session certs, sends dial command to agent
5. CLI connects to `N.bridge.{outpost}.tunnel.{domain}` via mTLS

### GeoIP Outpost Selection

For TCP tunnels, the API picks the outpost nearest to the CLI client:

1. MaxMind GeoLite2-City database maps source IP → lat/lon
2. Haversine distance to each outpost's coordinates
3. Nearest outpost is selected

**Fallback chain:**
1. Resource has `outpost` pinned → use that outpost (no GeoIP needed)
2. GeoIP lookup succeeds → nearest outpost by distance
3. GeoIP lookup fails (private IP, unknown) → use configured default outpost
4. No outposts available → error

## Resource Region Pinning

Resources can be pinned to a specific outpost when they depend on a
consistent hostname (OAuth redirects, CORS, CSP policies):

```yaml
resources:
  - name: grafana
    type: http
    hostname: grafana.internal
    port: 3000
    outpost: eu              # Pin to EU outpost only
```

When `outpost` is set:
- HTTP proxy: requests from other outposts get `redirect_outpost`
  response, proxy returns 302 to the pinned hostname
- TCP tunnels: API selects a bridge in the pinned outpost only
- The resource URL is always `grafana.eu.tunnel.bamf.example.com`

When `outpost` is NOT set (default):
- Resource is accessible through any outpost
- GeoDNS (if configured) routes to the nearest one

## GeoDNS (Optional)

GeoDNS is **not required** for outpost deployments. The outpost-specific
hostnames (`*.{outpost}.tunnel.{domain}`) are the primary access method.

GeoDNS adds a convenience layer: `*.tunnel.{domain}` resolves to the nearest
outpost automatically.

**Supported DNS providers:** AWS Route 53 (geolocation/latency-based routing),
Cloudflare (Geo Steering), Google Cloud DNS (geolocation routing), NS1
(filter chains with geofence).

**Configuration:**
```yaml
outpost:
  geodns:
    enabled: false           # Default: off
```

When enabled, the proxy accepts requests on both `*.{outpost}.tunnel.{domain}`
and `*.tunnel.{domain}`.

## Helm Deployment

### Full Platform (API + co-located outpost)

```yaml
core:
  api:
    enabled: true
  web:
    enabled: true
  postgresql:
    bundled:
      enabled: true
  redis:
    bundled:
      enabled: true
outpost:
  enabled: true
  name: "us-east"        # Required when outpost.enabled=true
```

### Remote Outpost (proxy+bridge only)

```yaml
core:
  api:
    enabled: false
  web:
    enabled: false
  postgresql:
    bundled:
      enabled: false
    external:
      enabled: false
  redis:
    bundled:
      enabled: false
    external:
      enabled: false
outpost:
  enabled: true
  name: "eu"
  joinToken: "bamf_out_..."
  apiUrl: "https://bamf.example.com"
```

When `outpost.enabled: true` and `core.api.enabled: false`, the chart deploys:
- Proxy Deployment + Service + ConfigMap + HPA + PDB
- Bridge StatefulSet + Headless Service + Per-Pod Services + HPA + PDB
- Outpost Join Job (pre-install hook)
- ServiceAccount + Role for join job
- Ingress routes for `*.{outpost-name}.tunnel.domain` and
  `*.bridge.{outpost-name}.tunnel.domain`
- cert-manager Certificate for the outpost's wildcard domains

### Validation

- `outpost.enabled` requires `outpost.name` to be non-empty
- `outpost.enabled` with `core.api.enabled: false` requires `outpost.joinToken`
  and `outpost.apiUrl`
- `outpost.name` must match `[a-z][a-z0-9-]*` (DNS label)

## API Endpoints

### Outpost Token Management

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/api/v1/outpost-tokens` | POST | Admin | Create outpost token |
| `/api/v1/outpost-tokens` | GET | Admin/Audit | List outpost tokens |
| `/api/v1/outpost-tokens/{id}` | DELETE | Admin | Revoke token by ID |
| `/api/v1/outpost-tokens/{name}/revoke` | POST | Admin | Revoke by name |

### Outpost Management

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/api/v1/outposts/join` | POST | None (token in body) | Register outpost |
| `/api/v1/outposts` | GET | Admin/Audit | List outposts |
| `/api/v1/outposts/{id}` | DELETE | Admin | Deactivate outpost |

## Security

- **Per-outpost tokens**: Each outpost has unique internal and bootstrap
  tokens. Revoking an outpost invalidates both.
- **Token rotation**: Re-joining regenerates both tokens. Requires coordinated
  restart of proxy and bridge pods.
- **Outpost deactivation**: `is_active=false` rejects all proxy authorize
  calls and bridge bootstrap attempts.
- **Network isolation**: Outpost proxies only need to reach the central API
  (HTTPS). Bridges accept agent relay connections (mTLS) and proxy forwarding.
- **TLS**: `outpost.apiUrl` must be HTTPS. Bridge relay uses BAMF CA mTLS.
- **CA distribution**: Join response includes the CA cert. If CA rotates,
  outposts must re-join.

See [Security Model](security.md#outpost-trust-boundary) for threat analysis.
