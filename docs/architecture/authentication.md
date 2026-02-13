# Authentication Architecture

All authentication in BAMF — local password, OIDC, SAML — flows through the
same pipeline. Clients never talk directly to identity providers.

## Unified Auth Flow

```
Client (CLI / Web UI)
  │
  ▼
BAMF API
  ├── LocalConnector  (password validation)
  ├── OIDCConnector   (Auth0, Okta, Google, Azure AD)
  └── SAMLConnector   (Azure AD, Okta, OneLogin)
  │
  ▼
Issues Session + Certificate
```

### Step by Step

1. Client generates PKCE code verifier + challenge and a random state
2. Client calls `GET /auth/authorize` with provider name, redirect URI, PKCE
3. API stores auth state in Redis (5-minute TTL)
4. API redirects to provider:
   - **External IDP**: redirects to Auth0/Okta/etc.
   - **Local**: redirects to Web UI login page (`/login?cli_state=...`)
5. User authenticates at the provider
6. Provider redirects back to API callback
7. API processes identity (roles from IDP claims + internal assignments)
8. API generates one-time `bamf_code`, redirects to client
9. Client exchanges `bamf_code` + PKCE verifier via `POST /auth/token`
10. API creates Redis session, returns opaque session token + certificate

### CLI Login

```
bamf login --provider auth0
  └── starts localhost HTTP server
  └── opens browser to /auth/authorize
  └── browser → IDP login → callback → localhost
  └── CLI exchanges code for session
  └── stores token + cert in ~/.bamf/keys/
```

### Web UI Login

Same flow, but the redirect URI points to the web app's callback page instead
of localhost.

## Connector Abstraction

All providers implement the `SSOConnector` interface:

- `build_authorization_request()` — generate the redirect URL
- `handle_callback()` — process the provider's response

The `LocalConnector` is an SSO connector that happens to use BAMF's own login
page instead of an external IDP.

## Sessions

BAMF uses server-side sessions stored in Redis. Clients receive an **opaque
session token** — not a JWT.

```
Redis key: bamf:session:{token}
Value: {email, roles, provider_name, created_at, expires_at, last_active_at}
```

Benefits:
- **Immediate revocation** — delete the Redis key, access stops instantly
- **No token leakage risk** — token is meaningless without Redis
- **Admin visibility** — list and revoke any session

JWTs are only used for short-lived certificates and inter-service communication.

## Role Resolution at Login

Roles are gathered from multiple sources and merged (union):

1. **IDP groups**: Values with `bamf:` prefix are stripped and recognized as
   BAMF roles (e.g., `bamf:admin` → `admin`)
2. **Claims-to-roles mapping**: Explicit config rules translate IDP claim
   values to BAMF roles
3. **Internal role assignments**: `(provider, email)` entries in the
   `role_assignments` table

Login never writes role assignments — the process is read-only.

## Identity Model

| User Type | Database | Identity Source | Role Source |
|-----------|----------|-----------------|-------------|
| Local | `users` table | Password hash in DB | Internal assignments |
| SSO | Not stored | IdP token | IDP claims + internal assignments |

SSO users do not have a row in the `users` table. Recent logins are cached in
Redis for admin UX.

## Component Authentication

| Connection | Method |
|------------|--------|
| CLI → API | `X-Bamf-Client-Cert` header (identity cert) |
| Agent → API | `X-Bamf-Client-Cert` header (agent cert) |
| CLI → Bridge | mTLS (session cert) |
| Agent → Bridge | mTLS (session cert) |
| Bridge → API | `X-Bamf-Client-Cert` header (bridge cert) |
| Browser → API | Session cookie |

The pattern: if you have a BAMF CA cert, present it. For connections through
the Gateway (public internet), the cert travels as an HTTP header. For direct
connections (bridge mTLS), the cert is in the TLS handshake.

## Auth API Endpoints

| Endpoint | Method | Auth | Purpose |
|----------|--------|------|---------|
| `/auth/providers` | GET | No | List configured providers |
| `/auth/authorize` | GET | No | Start auth flow |
| `/auth/callback` | GET | No | OIDC callback |
| `/auth/saml/acs` | POST | No | SAML assertion consumer |
| `/auth/local/login` | POST | No | Local credential validation |
| `/auth/token` | POST | No | Exchange code for session |
| `/auth/sessions` | GET | Yes | List active sessions |
| `/auth/logout` | POST | Yes | Revoke current session |
