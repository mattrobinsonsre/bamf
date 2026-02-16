# Security Model and Threat Analysis

BAMF's security is built on short-lived certificates, a private CA, and the
principle that authorization decisions should be encoded into the credential
itself. This document describes the trust model, threat boundaries, and what
happens when each component is compromised.

## Trust Model

Two independent trust chains protect different parts of the system:

### Public HTTPS (Let's Encrypt)

Protects the API surface — management endpoints, web UI, web app proxy, and
the initial trust bootstrap for CLI and agents.

- Managed by cert-manager
- Standard browser-trusted certificates
- TLS terminated at the ingress layer (Traefik or Istio Gateway)

### BAMF Internal CA

Protects the tunnel infrastructure — CLI ↔ Bridge ↔ Agent connections.

- Self-signed CA generated at install time
- Issues short-lived identity and session certificates
- Private key held only by the API server
- Public cert distributed to all components

These two chains are completely independent. Compromising Let's Encrypt (or
cert-manager, or the ingress controller) gives no access to the tunnel
infrastructure. Compromising the BAMF CA gives no access to the public HTTPS
surface.

## Trust Boundaries

```
┌─────────────────────────────────────────────────────────┐
│                    Public Internet                       │
│  Untrusted. All traffic is TLS-encrypted.               │
└─────────────┬──────────────────────┬────────────────────┘
              │ HTTPS (Let's Encrypt)│ mTLS (BAMF CA)
              ▼                      ▼
┌─────────────────────┐  ┌──────────────────────────────┐
│  BOUNDARY 1: API    │  │  BOUNDARY 2: Bridge          │
│  Authenticates all  │  │  Validates BAMF CA certs     │
│  requests. Issues   │  │  only. Zero runtime deps.    │
│  certs. Enforces    │  │  Never calls API/DB/Redis.   │
│  RBAC. Writes audit.│  │  Byte-level relay only.      │
│  Holds CA key.      │  │                              │
└────────┬────────────┘  └──────────────────────────────┘
         │                           │
         ▼                           ▼
┌─────────────────────┐  ┌──────────────────────────────┐
│  BOUNDARY 3: Data   │  │  BOUNDARY 4: Agent           │
│  PostgreSQL + Redis  │  │  Runs alongside targets.     │
│  Only API connects.  │  │  Has network access to       │
│  Bridge/Agent/CLI    │  │  target resources. Cert      │
│  never touch DB.     │  │  identifies agent. Scoped    │
│                      │  │  to configured resources.    │
└──────────────────────┘  └──────────────────────────────┘
```

### Boundary 1: API Server

The API is the security decision-maker. It:
- Authenticates all users (SSO, local password) and machines (agent certs)
- Holds the CA private key and issues all certificates
- Evaluates RBAC for every access request
- Writes every security event to the audit log
- Has direct access to PostgreSQL and Redis

**If the API is compromised**: Full platform compromise. The attacker has the
CA key and can issue arbitrary certificates, access all resources, read all
audit history, and impersonate any user. This is the highest-value target.

**Mitigations**:
- Run multiple replicas behind a load balancer (no single point of failure)
- Network policies restrict who can reach the API pods
- The CA key can be managed by cert-manager or external PKI to reduce the
  blast radius (the API never sees the raw key)
- Audit logs are append-only (no API endpoint to delete them)
- Rate limiting on all endpoints

### Boundary 2: Bridge

The bridge is a protocol-agnostic relay. It validates certificates against the
BAMF CA and splices bytes. It has **zero runtime dependencies** — no database,
no Redis, no API calls during tunnel operation.

**If a bridge is compromised**: The attacker can read traffic flowing through
that specific bridge pod. They cannot issue new certificates, access other
bridges, or authenticate as other users. The damage is limited to active
tunnels on that one pod.

**Mitigations**:
- Bridges are internal pods, not directly internet-exposed (SNI passthrough
  means the ingress doesn't terminate tunnel TLS — it just routes)
- Bridge certificates are short-lived (24h) and bridge-specific
- SSH tunnels have an additional encryption layer (SSH's own crypto runs
  inside the TLS tunnel)
- Bridges are stateless and ephemeral — no persistent data to exfiltrate
- Tunnel migration moves sessions to other bridges during maintenance

### Boundary 3: Data Layer

PostgreSQL stores identity and audit history. Redis stores runtime state.
**Only the API connects to either.** Bridges, agents, and CLI never touch
the data layer.

**If PostgreSQL is compromised**: The attacker gets user records (bcrypt-hashed
passwords for local users), role definitions, audit history, session recordings,
and the CA key backup. They cannot directly access resources (no live session
tokens — those are in Redis).

**If Redis is compromised**: The attacker gets active session tokens, agent
heartbeat data, resource catalog, and bridge registrations. They could
impersonate active sessions. They cannot get passwords, roles, or audit
history (those are in PostgreSQL).

**Mitigations**:
- Network policies restrict database access to API pods only
- Passwords are bcrypt-hashed (cost 12)
- Session tokens are opaque random bytes (not JWTs — useless without Redis)
- Redis keys have TTLs (sessions expire automatically)
- PostgreSQL supports SSL/TLS for in-cluster connections

### Boundary 4: Agent

Agents run alongside target resources and have network access to them. An agent
knows how to reach the resources configured in its `agent.yaml`.

**If an agent is compromised**: The attacker can access all resources that agent
is configured to proxy. For SSH resources, they get shell access to the target
host. For database resources, they get database access. For Kubernetes
resources, they get the agent's impersonation capability (which can impersonate
any user/group).

**Mitigations**:
- Agents are scoped: they only proxy resources listed in their config
- Agent certificates identify the specific agent — all traffic is attributable
- Agent certificates are short-lived (24h) and auto-renewed
- Join tokens (used for initial registration) can be single-use and
  time-limited
- Kubernetes agents use impersonation, not direct admin access — the K8s audit
  log shows the impersonated user, not the agent

## Trust Bootstrap

The bootstrap process establishes trust without requiring pre-shared secrets
(other than the initial join token for agents):

```
Step 1: CLI/Agent → API (public HTTPS)
  Trust: Let's Encrypt certificate (browser-grade)
  Auth:  SSO token (CLI) or join token (agent)

Step 2: API → CLI/Agent
  Response: BAMF CA public cert + signed identity cert
  Trust: The HTTPS connection guarantees this came from the real API

Step 3: CLI/Agent → Bridge (mTLS with BAMF CA)
  Trust: Both sides present certs signed by the same CA
  Auth:  Session cert with encoded authorization (SAN URIs)
```

A MITM attacker who compromises the public HTTPS connection (e.g., via a rogue
CA) could serve a fake BAMF CA cert. This would allow them to impersonate the
bridge. Mitigation: certificate pinning (planned), and the initial HTTPS
connection uses standard browser-grade TLS with certificate transparency.

## Certificate Security

### Session Certificates — Authorization as Credential

Session certs are the core security mechanism for tunnels. They encode the
complete authorization decision:

```
x509 Certificate (signed by BAMF CA):
  Subject CN: alice@corp.com
  SAN URIs:
    bamf://session/a1b2c3d4      — unique session ID
    bamf://resource/orders-db     — authorized resource
    bamf://bridge/bridge-0        — assigned bridge pod
  Not After: 30 seconds (extended on successful connection)
  Key Usage: Client Authentication
```

**Security properties**:

| Property | How it's enforced |
|----------|-------------------|
| **Bridge-pinned** | SAN URI `bamf://bridge/{id}` — cert only works on one bridge |
| **Resource-pinned** | SAN URI `bamf://resource/{name}` — cert only authorizes one resource |
| **Time-limited** | 30-second setup window, then session duration |
| **Non-replayable** | Unique session ID; bridge tracks active sessions |
| **Self-contained** | Bridge validates cert chain + reads SANs. No API call needed. |

### What a stolen session cert gets you

If an attacker steals a session cert and key during the 30-second setup window:
- They can connect to the assigned bridge (and only that bridge)
- They can access the assigned resource (and only that resource)
- The bridge will match them with the legitimate session — one side connects
  and the other is rejected (first-come wins)
- After 30 seconds, the cert is expired and useless

If stolen after connection: the cert is already bound to a TLS session. The
attacker would need to also steal the TLS session keys.

### What a stolen identity cert gets you

If an attacker steals a user's identity cert (12-hour lifetime):
- They can authenticate to the API as that user
- They can request tunnel sessions for any resource that user has access to
- They cannot bypass RBAC — the API still evaluates permissions

Mitigation: identity certs are stored in `~/.bamf/keys/` with 0600 permissions.
The short lifetime (12 hours) limits the exposure window.

## Session Security

### Server-Side Sessions (not JWTs)

BAMF deliberately uses server-side sessions (Redis) instead of JWTs for client
authentication. This is a security decision:

| | Server-side sessions | JWTs |
|---|---|---|
| **Revocation** | Instant (delete Redis key) | Impossible until expiry |
| **Stolen token** | Revoke immediately | Valid until expiry |
| **Token content** | Opaque random bytes | Contains claims (information leak) |
| **Admin visibility** | List all active sessions | No server-side state |

A stolen JWT is a ticking time bomb — valid until it expires, and you can't
revoke it without maintaining a blocklist (which defeats the purpose of JWTs).
A stolen session token can be revoked instantly.

### Session Lifecycle

1. User authenticates (SSO or local)
2. API creates session in Redis with configurable TTL (default 12h)
3. Client receives opaque session token
4. Every API request: token → Redis lookup → session data (email, roles)
5. Logout: delete Redis key → instant revocation
6. TTL expiry: Redis automatically removes stale sessions

## Data Flow Security

### TCP Tunnel (SSH, Database)

```
psql → CLI → [TLS: BAMF CA] → Bridge → [TLS: BAMF CA] → Agent → PostgreSQL
       ^                        ^                         ^
       Session cert             Validates both            Session cert
       (client side)            cert chains               (agent side)
```

- Two independent TLS sessions (CLI↔Bridge and Agent↔Bridge)
- Bridge terminates both and splices plaintext between them
- Bridge can read tunnel content (necessary for relay)
- SSH adds its own encryption layer inside the TLS tunnel
- Database protocols (PostgreSQL, MySQL) also support SSL/TLS to the target

### HTTP Proxy (Web App, Kubernetes)

```
Browser → [HTTPS: Let's Encrypt] → API → [internal HTTP] → Bridge → [gRPC] → Agent → Target
          ^                         ^                                          ^
          Session cookie            RBAC check                                 Forwards
          (browser auth)            per request                                HTTP request
```

- Browser authenticates via session cookie (set after SSO login)
- API evaluates RBAC on every HTTP request
- API rewrites headers (Host, Origin, CORS, cookies) for transparent proxying
- Internal API→Bridge communication is over cluster network (no public exposure)
- Agent forwards to target over internal network

### Kubernetes API Access

```
kubectl → [HTTPS] → API → [internal] → Bridge → [gRPC] → Agent → [HTTPS + Impersonation] → K8s API
                     ^                                     ^
                     Resolves k8s_groups                   Sets Impersonate-User
                     from BAMF roles                       and Impersonate-Group
```

- BAMF controls **who can reach the cluster** (authentication + RBAC)
- Kubernetes controls **what they can do** (K8s RBAC on impersonated identity)
- The agent's ServiceAccount has `impersonate` permission — it's a privileged
  credential that never leaves the cluster
- K8s audit log shows the impersonated user, not the agent SA

## Attack Scenarios

### Scenario: Compromised user workstation

**Impact**: Attacker gets `~/.bamf/credentials.json` (session token) and
`~/.bamf/keys/` (identity cert).

**What they can do**: Authenticate as the user, request tunnels, access
resources within the user's RBAC permissions.

**What they can't do**: Escalate beyond the user's roles, access resources
denied by RBAC, delete audit logs.

**Response**: Admin revokes all sessions for the user
(`DELETE /api/v1/auth/sessions?email=user@corp.com`). Identity cert expires
within 12 hours. Session token is instantly invalidated.

### Scenario: Compromised join token

**Impact**: Attacker can register a rogue agent.

**What they can do**: Register an agent with arbitrary resource names and
labels. If those names match existing resources, the rogue agent could
intercept tunnel connections.

**What they can't do**: Access resources directly (the agent only receives
connections for its registered resources, and the API routes to the agent
with the longest-registered name). Access the database or Redis.

**Response**: Revoke the join token. Delete the rogue agent registration.
Audit log shows when the agent registered and from what IP.

**Prevention**: Use single-use, short-lived join tokens. Delete tokens after
agent registration.

### Scenario: Network attacker (MITM)

**Impact**: Attacker positions between client and bridge.

**What they can do**: Nothing. Both sides of the tunnel use mTLS with BAMF CA
certificates. The attacker cannot present a valid certificate. The TLS
handshake fails.

**Exception**: If the attacker compromises the BAMF CA private key, they can
issue valid certificates and MITM tunnel connections. See "Compromised CA
Private Key" below.

### Scenario: Compromised CA private key

**Impact**: Full tunnel infrastructure compromise.

**What they can do**: Issue arbitrary session certs, impersonate any user or
agent to any bridge, read all tunnel traffic.

**What they can't do**: Access the API (which uses public HTTPS, not the BAMF
CA), modify the database, or delete audit logs.

**Response**: Rotate the CA (generate new CA, re-issue all certs, restart all
components). All existing session certs become invalid. Agents need to
re-register.

**Prevention**:
- Only the API server mounts the CA private key
- Use cert-manager or external PKI (Vault, AWS ACM PCA) to manage the CA
  outside the API process
- Enable Kubernetes network policies to restrict access to the CA secret

### Scenario: Rogue bridge pod

**Impact**: Attacker runs a pod that impersonates a bridge.

**What they can do**: Nothing without a valid bridge certificate signed by the
BAMF CA. Clients and agents validate the bridge's cert. A rogue pod without
a CA-signed cert cannot complete the TLS handshake.

**If they also have the CA key**: They can issue a bridge cert and intercept
tunnels routed to that bridge. The API would need to be tricked into routing
sessions to the rogue bridge (which requires compromising the API or Redis).

## MFA

BAMF intentionally does not implement MFA. MFA is the IdP's responsibility:

- Auth0, Okta, Azure AD all support MFA policies
- BAMF enforces "external SSO required" for specific roles via
  `require_external_sso_for_roles`
- This eliminates libfido2, device registration, and per-session MFA
  complexity — and the vulnerability surface that comes with implementing
  cryptographic ceremonies

Configure `require_external_sso_for_roles` to ensure privileged roles can only
authenticate through an IdP that enforces MFA.

## Audit

All security-relevant events are recorded:

- Login success/failure (provider, email, IP, user agent)
- Certificate issued/renewed (type, subject, lifetime)
- Resource access granted/denied (user, resource, reason)
- Session start/end (user, resource, bridge, duration)
- Admin actions (user/role/token CRUD, with before/after state)

Events include actor identity, timestamp, request ID, and source IP. Audit
logs are stored in PostgreSQL with time-based partitioning and configurable
retention (default 90 days).

See [Monitoring](../operations/monitoring.md) for querying the audit log.

## Network Security

### External Access

| Traffic | Ingress Path | TLS |
|---------|-------------|-----|
| API / Web UI | HTTPRoute or IngressRoute | Let's Encrypt (terminated) |
| Web app proxy | HTTPRoute or IngressRoute (wildcard) | Let's Encrypt (terminated) |
| Tunnels | TLSRoute or IngressRouteTCP | BAMF CA (passthrough) |

### Internal Access

| Traffic | Path | TLS |
|---------|------|-----|
| API → PostgreSQL | Cluster network | Optional (sslmode) |
| API → Redis | Cluster network | Optional |
| API → Bridge (relay) | Cluster network | None (internal) |

Internal traffic is protected by Kubernetes network policies. Istio service
mesh can be enabled for internal mTLS if required.

## Hardening Checklist

- [ ] Use external SSO (not local auth) for production
- [ ] Set `require_external_sso_for_roles: [admin]`
- [ ] Enable MFA in your identity provider
- [ ] Use short-lived join tokens (single-use when possible)
- [ ] Enable PostgreSQL SSL (`sslmode: require` or `verify-full`)
- [ ] Deploy Kubernetes NetworkPolicies restricting database access to API pods
- [ ] Use cert-manager or external PKI for the BAMF CA
- [ ] Configure audit log retention and export to SIEM
- [ ] Enable rate limiting on the API
- [ ] Run `govulncheck` and `pip-audit` regularly
