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
| GET | `/auth/ca/public` | No | Download BAMF CA public certificate |
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
  "bridge_hostname": "bridge-0.tunnel.bamf.example.com",
  "bridge_port": 443,
  "session_cert": "...",
  "session_key": "...",
  "ca_certificate": "...",
  "session_id": "...",
  "session_expires_at": "2026-02-13T10:08:40Z",
  "resource_type": "ssh"
}
```

## Agents

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/agents/join` | No* | Register agent with join token |
| GET | `/agents` | Admin/Audit | List agents with runtime state |
| GET | `/agents/{id}` | Admin/Audit | Get agent (by UUID or name) |
| DELETE | `/agents/{id}` | Admin | Delete agent |
| POST | `/agents/{id}/heartbeat` | Cert | Agent heartbeat |
| POST | `/agents/{id}/status` | Cert | Update agent status |
| POST | `/agents/{id}/renew` | Cert | Renew agent certificate |
| GET | `/agents/{id}/events` | Cert | SSE stream for tunnel commands |

*Join endpoint requires a valid join token in the request body.

## Join Tokens

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/tokens` | Admin/Audit | List tokens |
| POST | `/tokens` | Admin | Create token |
| GET | `/tokens/{id}` | Admin/Audit | Get token |
| DELETE | `/tokens/{id}` | Admin | Revoke token |

**Create Request:**
```json
{
  "name": "prod-agents",
  "expires_in_hours": 24,
  "max_uses": 10,
  "agent_labels": {"env": "prod"}
}
```

## Certificates

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/certificates/ca` | No | Get CA public certificate |
| POST | `/certificates/user` | Yes | Issue user identity certificate |
| POST | `/certificates/service` | Admin | Issue service certificate |

## Audit Log

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| GET | `/audit` | Yes | Query audit events |

**Query Parameters:**
- `limit` — Page size (default 50)
- `cursor` — Pagination cursor
- `event_type` — Filter by type (auth, admin, session)
- `action` — Filter by action (login, access, create, etc.)
- `actor_id` — Filter by actor email
- `since` / `until` — Time range (ISO 8601)

## Kubernetes Proxy

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| * | `/kube/{resource}/{path}` | Yes | Proxy to K8s API |

Supports all HTTP methods. The path after the resource name is forwarded to the
Kubernetes API.

## Internal Endpoints

Used by bridges and agents, not end users.

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/internal/bridges/bootstrap` | Token | Bootstrap bridge with cert |
| POST | `/internal/bridges/register` | Cert | Register bridge |
| POST | `/internal/bridges/{id}/heartbeat` | Cert | Bridge heartbeat |
| POST | `/internal/sessions/validate` | Cert | Validate session token |
| POST | `/internal/tunnels/establish` | Cert | Get agent connection info |
| POST | `/internal/tunnels/established` | Cert | Notify tunnel established |
| POST | `/internal/tunnels/closed` | Cert | Notify tunnel closed |

## Pagination

All list endpoints use cursor-based pagination:

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
