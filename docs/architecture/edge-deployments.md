# Edge Proxy+Bridge Deployments

BAMF supports deploying regional proxy+bridge clusters (edges) to minimize
latency for users in different geographic regions. The central API remains the
single source of truth for auth, RBAC, and state management.

**Core principle: every proxy+bridge combination is an edge**, including
the one co-located with the API. There is no special "central" proxy/bridge —
the co-located deployment is just an edge that happens to share a cluster
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
   │  Edge "eu"      │ │ Edge          │ │  Edge "apac"    │
   │                    │ │ "us-east"        │ │                    │
   │  Proxy Service     │ │ (co-located)     │ │  Proxy Service     │
   │  Bridge StatefulSet│ │  Proxy + Bridge  │ │  Bridge StatefulSet│
   │                    │ │                  │ │                    │
   │  Agents ←──relay───┤ │  Agents ←─relay──┤ │  Agents ←──relay───┤
   └────────────────────┘ └──────────────────┘ └────────────────────┘
```

## DNS Architecture

Each edge gets a short DNS-safe name (e.g., `eu`, `us-east`, `apac`)
used as a subdomain prefix for routing.

### Hostnames

**Proxy (web app) hostnames:**
```
*.{edge_name}.tunnel.{base_domain}
```
Example: `grafana.eu.tunnel.bamf.example.com`

**Bridge (TCP tunnel) hostnames:**
```
{ordinal}.bridge.{edge_name}.tunnel.{base_domain}
```
Example: `2.bridge.eu.tunnel.bamf.example.com`

### Full Example

```
API deployment (central, one location):
  bamf.example.com                              → API + Web UI

Edge "us-east" (co-located with API):
  *.us-east.tunnel.bamf.example.com             → US-East proxy
  *.bridge.us-east.tunnel.bamf.example.com      → US-East bridges

Edge "eu":
  *.eu.tunnel.bamf.example.com                  → EU proxy
  *.bridge.eu.tunnel.bamf.example.com           → EU bridges

Edge "apac":
  *.apac.tunnel.bamf.example.com                → APAC proxy
  *.bridge.apac.tunnel.bamf.example.com         → APAC bridges

Optional GeoDNS (all edges):
  *.tunnel.bamf.example.com                     → GeoDNS → nearest proxy
```

### DNS Records Required Per Edge

**Always required (standard DNS):**

| Record | Type | Value |
|--------|------|-------|
| `*.{name}.tunnel.bamf.example.com` | A/AAAA | Edge ingress IP |
| `*.bridge.{name}.tunnel.bamf.example.com` | A/AAAA | Edge ingress IP |

**Optional GeoDNS:**

| Record | Type | Value |
|--------|------|-------|
| `*.tunnel.bamf.example.com` | GeoDNS A/AAAA | Nearest edge ingress IP |

### Naming Rules

Edge names follow DNS label rules: `[a-z][a-z0-9-]*`, max 63 characters.
Examples: `eu`, `us-east`, `apac-tokyo`.

## Edge Registration

### Join Token Flow

Edge registration mirrors the agent join token pattern:

1. Admin creates an edge token:
   ```
   POST /api/v1/edge-tokens
   { "name": "eu-prod-token", "edge_name": "eu",
     "region": "EU West (Ireland)", "expires_in_hours": 24 }
   → { "token": "bamf_edge_abc123...", "id": "...", "name": "eu-prod-token" }
   ```

2. Edge Helm install includes the token. A pre-install job calls:
   ```
   POST /api/v1/edges/join
   { "join_token": "bamf_edge_abc123..." }
   ```

3. API validates token (hash lookup, expiry, revocation, use count), then
   creates or updates the edge record and generates two tokens:
   - `internal_token` — proxy authenticates to API internal endpoints
   - `bridge_bootstrap_token` — bridge authenticates for bootstrap

4. Join job stores both tokens as Kubernetes Secrets. Proxy and bridge
   Deployments/StatefulSets mount these secrets.

### Token Formats

| Token | Format | Purpose |
|-------|--------|---------|
| Edge join token | `bamf_edge_{32 hex}` | One-time registration |
| Internal token | `edge_int_{32 hex}` | Proxy → API auth |
| Bridge bootstrap token | `edge_brg_{32 hex}` | Bridge → API auth |

### Re-join Behavior

Re-joining with the same edge name regenerates both tokens (invalidating
old ones) and updates the edge record. Existing proxy and bridge pods
will fail auth and need restart — intentional to prevent two deployments
claiming the same name.

## Multi-Edge Agent Relay

**Agents maintain relay connections to bridges in every edge.** This is
the key enabler for "any edge can serve any resource."

### How It Works

1. Agent starts, connects to API via SSE
2. API sends the agent relay assignments per edge:
   `{edge: "eu", bridge: "bridge-0"}, {edge: "us-east", bridge: "bridge-2"}`
3. Agent dials each assigned bridge and establishes an mTLS relay connection
4. When an edge's bridge pool changes, API sends updated assignments via SSE
5. Each edge's bridges now have relay access to the agent

### Redis Tracking

Per-agent relay state per edge:
```
agent:{id}:relay:{edge_name} → bridge_id  (TTL = relay health interval)
```

The authorize endpoint reads this key to find which bridge in the proxy's
edge has the relay to the target agent.

### Connection Count

With S edges and A agents: S×A relay connections total, distributed across
all bridges. For 3 edges with 2 bridges each and 100 agents: 300 relay
connections total, ~50 per bridge. Relay connections are lightweight idle mTLS
streams.

## Routing

### HTTP Proxy (Web Apps)

1. Browser hits `grafana.eu.tunnel.bamf.example.com`
2. EU edge proxy calls API `POST /internal/proxy/authorize` with its
   `edge_name`
3. API reads `agent:{id}:relay:eu` to find which bridge in the EU edge
   has the relay to the agent
4. Proxy forwards to the local bridge → agent relay → target

### TCP Tunnels (SSH, DB)

1. CLI calls API `POST /api/v1/connect` with resource name
2. API determines the edge for the resource (see Edge Selection below)
3. API selects a bridge in the chosen edge
4. API issues session certs, sends dial command to agent
5. CLI connects to `N.bridge.{edge}.tunnel.{domain}` via mTLS

### Edge Selection

A tunnel is a rendezvous: `client → edge → agent → target`. The agent→target
leg is fixed, so the edge that minimizes latency is the one with the shortest
detour — `argmin_E [ RTT(client, E) + RTT(E, agent) ]` — not simply the edge
nearest either end. Because internet latency is non-Euclidean (it violates the
triangle inequality), both legs are **measured**, never inferred from geography.

For TCP tunnels the API chooses the edge as follows:

1. Resource has `edge` pinned → use that edge.
2. Otherwise → the edge **nearest the agent** (lowest measured agent-leg RTT)
   that has bridge capacity. The agent-leg is measured for free from the
   relay each agent already holds to every edge (its `tls.Dial` handshake
   latency), reported on heartbeats and cached in Redis.
3. Fallback → the configured default edge, when the agent has no measurements
   yet or no measured edge has capacity.

Step 2 is the **optimistic-connect guess**: the tunnel opens immediately on the
agent-nearest edge with zero added setup latency. The remaining pieces of the
edge flagship ([#119](https://github.com/mattrobinsonsre/bamf/issues/119)) —
the client-leg probe (so the choice becomes the true client+agent rendezvous)
and a seamless single hop to a better edge discovered in the background — build
on this without ever blocking connection setup. This measured approach replaces
the earlier, never-active GeoIP heuristic (geographic distance is a lossy proxy
for network latency and hard to test).

## Resource Region Pinning

Resources can be pinned to a specific edge when they depend on a
consistent hostname (OAuth redirects, CORS, CSP policies):

```yaml
resources:
  - name: grafana
    type: http
    hostname: grafana.internal
    port: 3000
    edge: eu              # Pin to EU edge only
```

When `edge` is set:
- HTTP proxy: requests from other edges get `redirect_edge`
  response, proxy returns 302 to the pinned hostname
- TCP tunnels: API selects a bridge in the pinned edge only
- The resource URL is always `grafana.eu.tunnel.bamf.example.com`

When `edge` is NOT set (default):
- Resource is accessible through any edge
- GeoDNS (if configured) routes to the nearest one

## GeoDNS (Optional)

GeoDNS is **not required** for edge deployments. The edge-specific
hostnames (`*.{edge}.tunnel.{domain}`) are the primary access method.

GeoDNS adds a convenience layer: `*.tunnel.{domain}` resolves to the nearest
edge automatically.

**Supported DNS providers:** AWS Route 53 (geolocation/latency-based routing),
Cloudflare (Geo Steering), Google Cloud DNS (geolocation routing), NS1
(filter chains with geofence).

**Configuration:**
```yaml
edge:
  geodns:
    enabled: false           # Default: off
```

When enabled, the proxy accepts requests on both `*.{edge}.tunnel.{domain}`
and `*.tunnel.{domain}`.

## Helm Deployment

### Full Platform (API + co-located edge)

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
edge:
  enabled: true
  name: "us-east"        # Required when edge.enabled=true
```

### Remote Edge (proxy+bridge only)

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
edge:
  enabled: true
  name: "eu"
  joinToken: "bamf_edge_..."
  apiUrl: "https://bamf.example.com"
```

When `edge.enabled: true` and `core.api.enabled: false`, the chart deploys:
- Proxy Deployment + Service + ConfigMap + HPA + PDB
- Bridge StatefulSet + Headless Service + Per-Pod Services + HPA + PDB
- Edge Join Job (pre-install hook)
- ServiceAccount + Role for join job
- Ingress routes for `*.{edge-name}.tunnel.domain` and
  `*.bridge.{edge-name}.tunnel.domain`
- cert-manager Certificate for the edge's wildcard domains

### Validation

- `edge.enabled` requires `edge.name` to be non-empty
- `edge.enabled` with `core.api.enabled: false` requires `edge.joinToken`
  and `edge.apiUrl`
- `edge.name` must match `[a-z][a-z0-9-]*` (DNS label)

## API Endpoints

### Edge Token Management

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/api/v1/edge-tokens` | POST | Admin | Create edge token |
| `/api/v1/edge-tokens` | GET | Admin/Audit | List edge tokens |
| `/api/v1/edge-tokens/{id}` | DELETE | Admin | Revoke token by ID |
| `/api/v1/edge-tokens/{name}/revoke` | POST | Admin | Revoke by name |

### Edge Management

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/api/v1/edges/join` | POST | None (token in body) | Register edge |
| `/api/v1/edges` | GET | Admin/Audit | List edges |
| `/api/v1/edges/{id}` | DELETE | Admin | Deactivate edge |

## Security

- **Per-edge tokens**: Each edge has unique internal and bootstrap
  tokens. Revoking an edge invalidates both.
- **Token rotation**: Re-joining regenerates both tokens. Requires coordinated
  restart of proxy and bridge pods.
- **Edge deactivation**: `is_active=false` rejects all proxy authorize
  calls and bridge bootstrap attempts.
- **Network isolation**: Edge proxies only need to reach the central API
  (HTTPS). Bridges accept agent relay connections (mTLS) and proxy forwarding.
- **TLS**: `edge.apiUrl` must be HTTPS. Bridge relay uses BAMF CA mTLS.
- **CA distribution**: Join response includes the CA cert. If CA rotates,
  edges must re-join.

See [Security Model](security.md#edge-trust-boundary) for threat analysis.
