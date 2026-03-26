# Satellite Proxy+Bridge Deployments

BAMF supports deploying regional proxy+bridge clusters (satellites) to minimize
latency for users in different geographic regions. The central API remains the
single source of truth for auth, RBAC, and state management.

**Core principle: every proxy+bridge combination is a satellite**, including
the one co-located with the API. There is no special "central" proxy/bridge —
the co-located deployment is just a satellite that happens to share a cluster
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
   │  Satellite "eu"    │ │ Satellite        │ │  Satellite "apac"  │
   │                    │ │ "us-east"        │ │                    │
   │  Proxy Service     │ │ (co-located)     │ │  Proxy Service     │
   │  Bridge StatefulSet│ │  Proxy + Bridge  │ │  Bridge StatefulSet│
   │                    │ │                  │ │                    │
   │  Agents ←──relay───┤ │  Agents ←─relay──┤ │  Agents ←──relay───┤
   └────────────────────┘ └──────────────────┘ └────────────────────┘
```

## DNS Architecture

Each satellite gets a short DNS-safe name (e.g., `eu`, `us-east`, `apac`)
used as a subdomain prefix for routing.

### Hostnames

**Proxy (web app) hostnames:**
```
*.{satellite_name}.tunnel.{base_domain}
```
Example: `grafana.eu.tunnel.bamf.example.com`

**Bridge (TCP tunnel) hostnames:**
```
{ordinal}.bridge.{satellite_name}.tunnel.{base_domain}
```
Example: `2.bridge.eu.tunnel.bamf.example.com`

### Full Example

```
API deployment (central, one location):
  bamf.example.com                              → API + Web UI

Satellite "us-east" (co-located with API):
  *.us-east.tunnel.bamf.example.com             → US-East proxy
  *.bridge.us-east.tunnel.bamf.example.com      → US-East bridges

Satellite "eu":
  *.eu.tunnel.bamf.example.com                  → EU proxy
  *.bridge.eu.tunnel.bamf.example.com           → EU bridges

Satellite "apac":
  *.apac.tunnel.bamf.example.com                → APAC proxy
  *.bridge.apac.tunnel.bamf.example.com         → APAC bridges

Optional GeoDNS (all satellites):
  *.tunnel.bamf.example.com                     → GeoDNS → nearest proxy
```

### DNS Records Required Per Satellite

**Always required (standard DNS):**

| Record | Type | Value |
|--------|------|-------|
| `*.{name}.tunnel.bamf.example.com` | A/AAAA | Satellite ingress IP |
| `*.bridge.{name}.tunnel.bamf.example.com` | A/AAAA | Satellite ingress IP |

**Optional GeoDNS:**

| Record | Type | Value |
|--------|------|-------|
| `*.tunnel.bamf.example.com` | GeoDNS A/AAAA | Nearest satellite ingress IP |

### Naming Rules

Satellite names follow DNS label rules: `[a-z][a-z0-9-]*`, max 63 characters.
Examples: `eu`, `us-east`, `apac-tokyo`.

## Satellite Registration

### Join Token Flow

Satellite registration mirrors the agent join token pattern:

1. Admin creates a satellite token:
   ```
   POST /api/v1/satellite-tokens
   { "name": "eu-prod-token", "satellite_name": "eu",
     "region": "EU West (Ireland)", "expires_in_hours": 24 }
   → { "token": "bamf_sat_abc123...", "id": "...", "name": "eu-prod-token" }
   ```

2. Satellite Helm install includes the token. A pre-install job calls:
   ```
   POST /api/v1/satellites/join
   { "join_token": "bamf_sat_abc123..." }
   ```

3. API validates token (hash lookup, expiry, revocation, use count), then
   creates or updates the satellite record and generates two tokens:
   - `internal_token` — proxy authenticates to API internal endpoints
   - `bridge_bootstrap_token` — bridge authenticates for bootstrap

4. Join job stores both tokens as Kubernetes Secrets. Proxy and bridge
   Deployments/StatefulSets mount these secrets.

### Token Formats

| Token | Format | Purpose |
|-------|--------|---------|
| Satellite join token | `bamf_sat_{32 hex}` | One-time registration |
| Internal token | `sat_int_{32 hex}` | Proxy → API auth |
| Bridge bootstrap token | `sat_brg_{32 hex}` | Bridge → API auth |

### Re-join Behavior

Re-joining with the same satellite name regenerates both tokens (invalidating
old ones) and updates the satellite record. Existing proxy and bridge pods
will fail auth and need restart — intentional to prevent two deployments
claiming the same name.

## Multi-Satellite Agent Relay

**Agents maintain relay connections to bridges in every satellite.** This is
the key enabler for "any satellite can serve any resource."

### How It Works

1. Agent starts, connects to API via SSE
2. API sends the agent relay assignments per satellite:
   `{satellite: "eu", bridge: "bridge-0"}, {satellite: "us-east", bridge: "bridge-2"}`
3. Agent dials each assigned bridge and establishes a gRPC relay stream
4. When a satellite's bridge pool changes, API sends updated assignments via SSE
5. Each satellite's bridges now have relay access to the agent

### Redis Tracking

Per-agent relay state per satellite:
```
agent:{id}:relay:{satellite_name} → bridge_id  (TTL = relay health interval)
```

The authorize endpoint reads this key to find which bridge in the proxy's
satellite has the relay to the target agent.

### Connection Count

With S satellites and A agents: S×A relay connections total, distributed across
all bridges. For 3 satellites with 2 bridges each and 100 agents: 300 relay
connections total, ~50 per bridge. Relay connections are lightweight idle gRPC
streams.

## Routing

### HTTP Proxy (Web Apps)

1. Browser hits `grafana.eu.tunnel.bamf.example.com`
2. EU satellite proxy calls API `POST /internal/proxy/authorize` with its
   `satellite_name`
3. API reads `agent:{id}:relay:eu` to find which bridge in the EU satellite
   has the relay to the agent
4. Proxy forwards to the local bridge → agent relay → target

### TCP Tunnels (SSH, DB)

1. CLI calls API `POST /api/v1/connect` with resource name
2. API determines nearest satellite to the CLI client (GeoIP)
3. API selects a bridge in the chosen satellite
4. API issues session certs, sends dial command to agent
5. CLI connects to `N.bridge.{satellite}.tunnel.{domain}` via mTLS

### GeoIP Satellite Selection

For TCP tunnels, the API picks the satellite nearest to the CLI client:

1. MaxMind GeoLite2-City database maps source IP → lat/lon
2. Haversine distance to each satellite's coordinates
3. Nearest satellite is selected

**Fallback chain:**
1. Resource has `satellite` pinned → use that satellite (no GeoIP needed)
2. GeoIP lookup succeeds → nearest satellite by distance
3. GeoIP lookup fails (private IP, unknown) → use configured default satellite
4. No satellites available → error

## Resource Region Pinning

Resources can be pinned to a specific satellite when they depend on a
consistent hostname (OAuth redirects, CORS, CSP policies):

```yaml
resources:
  - name: grafana
    type: http
    hostname: grafana.internal
    port: 3000
    satellite: eu              # Pin to EU satellite only
```

When `satellite` is set:
- HTTP proxy: requests from other satellites get `redirect_satellite`
  response, proxy returns 302 to the pinned hostname
- TCP tunnels: API selects a bridge in the pinned satellite only
- The resource URL is always `grafana.eu.tunnel.bamf.example.com`

When `satellite` is NOT set (default):
- Resource is accessible through any satellite
- GeoDNS (if configured) routes to the nearest one

## GeoDNS (Optional)

GeoDNS is **not required** for satellite deployments. The satellite-specific
hostnames (`*.{sat}.tunnel.{domain}`) are the primary access method.

GeoDNS adds a convenience layer: `*.tunnel.{domain}` resolves to the nearest
satellite automatically.

**Supported DNS providers:** AWS Route 53 (geolocation/latency-based routing),
Cloudflare (Geo Steering), Google Cloud DNS (geolocation routing), NS1
(filter chains with geofence).

**Configuration:**
```yaml
satellite:
  geodns:
    enabled: false           # Default: off
```

When enabled, the proxy accepts requests on both `*.{sat}.tunnel.{domain}`
and `*.tunnel.{domain}`.

## Helm Deployment

### Full Platform (API + co-located satellite)

```yaml
api:
  enabled: true
web:
  enabled: true
satellite:
  enabled: true
  name: "us-east"        # Required when satellite.enabled=true
postgresql:
  bundled:
    enabled: true
redis:
  bundled:
    enabled: true
```

### Remote Satellite (proxy+bridge only)

```yaml
api:
  enabled: false
web:
  enabled: false
satellite:
  enabled: true
  name: "eu"
  joinToken: "bamf_sat_..."
  apiUrl: "https://bamf.example.com"
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
```

When `satellite.enabled: true` and `api.enabled: false`, the chart deploys:
- Proxy Deployment + Service + ConfigMap + HPA + PDB
- Bridge StatefulSet + Headless Service + Per-Pod Services + HPA + PDB
- Satellite Join Job (pre-install hook)
- ServiceAccount + Role for join job
- Ingress routes for `*.{sat-name}.tunnel.domain` and
  `*.bridge.{sat-name}.tunnel.domain`
- cert-manager Certificate for the satellite's wildcard domains

### Validation

- `satellite.enabled` requires `satellite.name` to be non-empty
- `satellite.enabled` with `api.enabled: false` requires `satellite.joinToken`
  and `satellite.apiUrl`
- `satellite.name` must match `[a-z][a-z0-9-]*` (DNS label)

## API Endpoints

### Satellite Token Management

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/api/v1/satellite-tokens` | POST | Admin | Create satellite token |
| `/api/v1/satellite-tokens` | GET | Admin/Audit | List satellite tokens |
| `/api/v1/satellite-tokens/{id}` | DELETE | Admin | Revoke token by ID |
| `/api/v1/satellite-tokens/{name}/revoke` | POST | Admin | Revoke by name |

### Satellite Management

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/api/v1/satellites/join` | POST | None (token in body) | Register satellite |
| `/api/v1/satellites` | GET | Admin/Audit | List satellites |
| `/api/v1/satellites/{id}` | DELETE | Admin | Deactivate satellite |

## Security

- **Per-satellite tokens**: Each satellite has unique internal and bootstrap
  tokens. Revoking a satellite invalidates both.
- **Token rotation**: Re-joining regenerates both tokens. Requires coordinated
  restart of proxy and bridge pods.
- **Satellite deactivation**: `is_active=false` rejects all proxy authorize
  calls and bridge bootstrap attempts.
- **Network isolation**: Satellite proxies only need to reach the central API
  (HTTPS). Bridges accept agent relay connections (mTLS) and proxy forwarding.
- **TLS**: `satellite.apiUrl` must be HTTPS. Bridge relay uses BAMF CA mTLS.
- **CA distribution**: Join response includes the CA cert. If CA rotates,
  satellites must re-join.

See [Security Model](security.md#satellite-trust-boundary) for threat analysis.
