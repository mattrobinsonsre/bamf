# REST API Reference

All endpoints are prefixed with `/api/v1` unless otherwise noted.

## Health

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/health` | No | Liveness probe |
| GET | `/ready` | No | Readiness probe (checks DB + Redis) |

## Authentication

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/auth/providers` | No | List configured auth providers |
| GET | `/auth/authorize` | No | Start auth flow (redirects to IDP) |
| POST | `/auth/local/authorize` | No | Direct JSON login with PKCE (Web UI) |
| POST | `/auth/local/login` | No | Form-based local login (CLI redirect) |
| GET | `/auth/callback` | No | OIDC/SAML callback handler |
| POST | `/auth/saml/acs` | No | SAML assertion consumer service |
| POST | `/auth/token` | No | Exchange code + PKCE verifier for session |
| GET | `/auth/sessions` | Yes | List current user's sessions |
| GET | `/auth/sessions/all` | Admin | List all active sessions |
| DELETE | `/auth/sessions/user/{email}` | Admin | Revoke all sessions for a user |
| POST | `/auth/logout` | Yes | Revoke current session |
| POST | `/auth/logout/all` | Yes | Revoke all current user's sessions |

## Users

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/users` | Yes | List users (paginated) |
| GET | `/users/recent` | Admin/Audit | Recently-seen users |
| POST | `/users` | Admin | Create local user |
| GET | `/users/{email}` | Yes | Get user by email |
| PATCH | `/users/{email}` | Admin | Update user |
| DELETE | `/users/{email}` | Admin | Delete user |

## Roles

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/roles` | Yes | List all roles (built-in + custom) |
| POST | `/roles` | Admin | Create custom role |
| GET | `/roles/{name}` | Yes | Get role by name |
| PATCH | `/roles/{name}` | Admin | Update custom role |
| DELETE | `/roles/{name}` | Admin | Delete custom role |

## Role Assignments

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/role-assignments` | Admin/Audit | List all role assignments |
| GET | `/role-assignments/identities` | Admin/Audit | List known identities |
| GET | `/role-assignments/stale` | Admin/Audit | Identities with stale assignments |
| PUT | `/role-assignments` | Admin | Set roles for (provider, email) |
| DELETE | `/role-assignments/{provider}/{email}/{role}` | Admin | Remove assignment |

## Resources

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/resources` | Yes | List accessible resources |

Resources are reported by agents via heartbeats and stored in Redis. There is no
CRUD API for resources — they are managed through agent configuration.

## Connect

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/connect` | Yes | Request tunnel to a resource |

**Request:**
```json
{
  "resource_name": "web-prod-01",
  "reconnect_session_id": null
}
```

**Response:**
```json
{
  "bridge_hostname": "0.bridge.tunnel.bamf.example.com",
  "bridge_port": 8443,
  "session_cert": "...",
  "session_key": "...",
  "ca_certificate": "...",
  "session_id": "...",
  "session_expires_at": "2026-02-13T10:08:40Z",
  "resource_type": "ssh"
}
```

## Tunnels

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/tunnels/active` | Admin/Audit | List active tunnel sessions across all bridges |
| DELETE | `/tunnels/{session_id}` | Yes | Terminate a tunnel session |

Active tunnels are tracked in Redis (session → user, resource, bridge). A user
can terminate their own tunnel; admins can terminate any.

## Terminal

Browser-based SSH and database terminals. Session state lives in the bridge; the
API is a stateless WebSocket relay. Connecting is two steps — mint a one-time
ticket over HTTPS, then open the WebSocket with it.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/terminal/ticket` | Yes | Issue a one-time WebSocket ticket for a session |
| WS | `/terminal/ssh/{session_id}` | Ticket | SSH web-terminal relay |
| WS | `/terminal/db/{session_id}` | Ticket | Database web-terminal relay |

The ticket is bound to the session and user, stored in Redis with a 60s TTL, and
consumed atomically (`GETDEL`) on connect — single-use and replay-proof. Pass it
as the `ticket` query parameter on the WebSocket URL.

## Agents

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/agents/join` | No* | Register agent with join token |
| GET | `/agents` | Admin/Audit | List agents with runtime state |
| GET | `/agents/{id}` | Admin/Audit | Get agent (by UUID or name) |
| DELETE | `/agents/{id}` | Admin | Delete agent |
| POST | `/agents/{id}/heartbeat` | Cert | Agent heartbeat |
| POST | `/agents/{id}/renew` | Cert | Renew agent certificate |
| POST | `/agents/{id}/drain` | Cert | Mark an agent instance draining |
| POST | `/agents/{id}/instance/{iid}/offline` | Cert | Remove a shut-down instance |
| GET | `/agents/{id}/events` | Cert | SSE stream for tunnel commands |

Agent endpoints require the agent's certificate (`X-Bamf-Client-Cert`) whose CN
matches the target agent — an agent may only act as itself.

*Join endpoint requires a valid join token in the request body.

## Join Tokens

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/tokens` | Admin/Audit | List tokens |
| POST | `/tokens` | Admin | Create token |
| GET | `/tokens/{id}` | Admin/Audit | Get token |
| DELETE | `/tokens/{id}` | Admin | Revoke token by ID |
| POST | `/tokens/{name}/revoke` | Admin | Revoke token by name |

**Create Request:**
```json
{
  "name": "prod-agents",
  "expires_in_hours": 24,
  "max_uses": 10,
  "agent_labels": {"env": "prod"}
}
```

## Outposts

Regional proxy+bridge deployments that register with the central control plane.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/outposts/join` | No* | Register an outpost (returns its internal + bridge-bootstrap tokens) |
| GET | `/outposts` | Admin/Audit | List registered outposts |
| GET | `/outposts/{id}` | Admin/Audit | Get an outpost |
| DELETE | `/outposts/{id}` | Admin | Deregister an outpost |

*Join requires a valid outpost join token in the request body.

## Outpost Tokens

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/outpost-tokens` | Admin/Audit | List outpost join tokens |
| POST | `/outpost-tokens` | Admin | Create an outpost join token |
| GET | `/outpost-tokens/{id}` | Admin/Audit | Get a token |
| DELETE | `/outpost-tokens/{id}` | Admin | Revoke a token by ID |
| POST | `/outpost-tokens/{name}/revoke` | Admin | Revoke a token by name |

## Certificates

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/certificates/ca` | No | Get CA public certificate |
| POST | `/certificates/user` | Yes | Issue user identity certificate |
| POST | `/certificates/service` | Admin | Issue service certificate |
| POST | `/certificates/revoke` | Admin | Revoke a certificate by SHA-256 fingerprint |
| GET | `/certificates/revoked` | Admin/Audit | List revoked certificates |

Revocation is a kill-switch for leaked long-lived agent/bridge certificates.
Revoked fingerprints are enforced at the API cert-auth layer (agent/bridge
requests presenting `X-Bamf-Client-Cert` get `401` once revoked). The durable
list lives in Postgres and is mirrored into a Redis set for O(1) checks;
enforcement fails open if Redis is unavailable. User sessions are revoked
separately via `/auth/sessions`, and tunnel session certs are 30-second TTL, so
revocation targets the long-lived service certs.

## Audit Log

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/audit` | Admin/Audit | Query audit events |

**Query Parameters:**
- `limit` — Page size (default 50)
- `cursor` — Pagination cursor
- `event_type` — Filter by type (auth, admin, session)
- `action` — Filter by action (login, access, create, etc.)
- `actor_id` — Filter by actor email
- `target_type` — Filter by target type
- `target_id` — Filter by target ID
- `success` — Filter by success/failure
- `since` / `until` — Time range (ISO 8601)

## Session Recordings

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/audit/recordings` | Admin/Audit | List session recordings |
| GET | `/audit/recordings/{id}` | Admin/Audit | Get recording by ID (includes full data) |

**List Query Parameters:**
- `limit` — Page size (default 50)
- `cursor` — Pagination cursor
- `user_email` — Filter by user
- `resource_name` — Filter by resource
- `recording_type` — Filter by type: `terminal`, `queries`, `http`
- `session_id` — Filter by session UUID
- `since` / `until` — Time range (ISO 8601)

**Recording Types:**
- `terminal` — SSH session recordings in asciicast v2 format (from `ssh-audit`)
- `queries` — Database query logs in queries-v1 format (from `postgres-audit`, `mysql-audit`)
- `http` — HTTP request/response exchanges in http-exchange-v1 format (from `http-audit`)

## Kubernetes Proxy

Kubernetes API access is **not** served by this API server — it is handled by
the standalone **proxy service** (`bamf-proxy`), the same tier that serves web
app access. `bamf kube login` writes a kubeconfig whose server points at the
proxy; requests are authenticated per-request and relayed to the agent, which
impersonates the user against the K8s API. See the
[Kubernetes guide](../guides/kubernetes.md).

## Internal Endpoints

Used by bridges, agents, and the standalone proxy service — not end users.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/internal/bridges/bootstrap` | Token | Bootstrap bridge with cert |
| POST | `/internal/bridges/register` | Cert | Register bridge |
| POST | `/internal/bridges/renew` | Cert | Renew bridge certificate |
| POST | `/internal/bridges/{id}/heartbeat` | Cert | Bridge heartbeat |
| POST | `/internal/bridges/{id}/status` | Cert | Report bridge status (tunnel counts, health) |
| POST | `/internal/bridges/{id}/drain` | Cert | Notify bridge draining for shutdown |
| POST | `/internal/sessions/validate` | Cert | Validate session token |
| POST | `/internal/tunnels/establish` | Cert | Get agent connection info |
| POST | `/internal/tunnels/established` | Cert | Notify tunnel established |
| POST | `/internal/tunnels/closed` | Cert | Notify tunnel closed |
| POST | `/internal/sessions/{id}/recording` | Cert | Upload session recording |
| POST | `/internal/proxy/authorize` | Token | Proxy: authorize a web/kube request |
| POST | `/internal/proxy/audit` | Token | Proxy: record an HTTP access audit event |
| POST | `/internal/proxy/recording` | Token | Proxy: upload an HTTP exchange recording |

## Pagination

Large collections (`/users`, `/agents`, `/tokens`, `/audit`) use cursor-based
pagination with the `{items, next_cursor, has_more}` envelope below. Some
smaller list endpoints (`/resources`, `/role-assignments`, `/certificates/revoked`,
`/auth/sessions`) return a flat array or a custom envelope instead. The
cursor-paginated form:

```
GET /api/v1/users?limit=50&cursor=eyJpZCI6ICIxMjMifQ==
```

Response includes `next_cursor` and `has_more`:
```json
{
  "items": [...],
  "next_cursor": "eyJpZCI6ICIxNTAifQ==",
  "has_more": true
}
```

## Authentication Methods

- **Session token**: `Authorization: Bearer {token}` — for CLI and web UI
- **Client certificate**: `X-Bamf-Client-Cert: {base64 PEM}` — for agents and bridges
- **Session cookie**: `bamf_session` cookie — for web app proxy

## Error Format

```json
{
  "detail": "Resource not found"
}
```

Standard HTTP status codes: 400, 401, 403, 404, 409, 422, 500.
