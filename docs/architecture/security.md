# Security Model

BAMF's security is built on short-lived certificates, a private CA, and the
principle that authorization decisions should be encoded into the credential
itself.

## Trust Model

Two independent trust chains protect different parts of the system:

### Public HTTPS (Let's Encrypt)

Protects the API surface — management endpoints, web UI, web app proxy, and
the initial trust bootstrap for CLI and agents.

- Managed by cert-manager
- Standard browser-trusted certificates
- TLS terminated at the Istio Gateway

### BAMF Internal CA

Protects the tunnel infrastructure — CLI ↔ Bridge ↔ Agent connections.

- Self-signed CA generated at install time
- Issues short-lived identity and session certificates
- Private key held only by the API server
- Public cert distributed to all components

## Trust Bootstrap

1. CLI/Agent connects to API via public HTTPS (trusts Let's Encrypt)
2. Authenticates (SSO for CLI, join token for agents)
3. Downloads BAMF CA public cert from API (`/api/v1/certificates/ca`)
4. Receives identity certificate signed by BAMF CA
5. All subsequent tunnel connections use BAMF CA for mutual TLS

## Certificate Lifetimes

| Certificate | Lifetime | Rationale |
|---|---|---|
| User identity | 12 hours | Workday-length, auto-renewed with valid session |
| Agent identity | 24 hours | Longer to avoid frequent re-registration |
| Bridge identity | 24 hours | Same as agent |
| Session (tunnel) | 30s setup, extended on connect | Minimal exposure window |

Short lifetimes limit the damage from credential theft. A stolen session cert
is useless after 30 seconds (or after the tunnel closes).

## Session Certificates — Authorization as Credential

Session certs are the key security innovation. They encode the authorization
decision into the certificate:

```
SAN URIs:
  bamf://session/{session_id}
  bamf://resource/{resource_name}
  bamf://bridge/{bridge_id}
```

This means:
- The bridge has **zero runtime dependencies** — no database, no Redis, no API
  calls at request time
- A session cert is **pinned to one bridge** — can't be replayed against others
- A session cert is **pinned to one resource** — can't be used to access
  different resources
- **Per-session authorization** — even with a valid identity cert, you can't
  connect without a session cert issued by the API

## Attack Surface

### Compromised Session Token

Session tokens are stored in Redis. A stolen token provides API access until it
expires or is revoked. Mitigation:

- Tokens are opaque (not JWTs) — can be instantly revoked
- 12-hour default lifetime
- Admins can revoke all sessions for a user

### Compromised CA Private Key

The CA key allows issuing arbitrary certificates. Mitigation:

- Stored in a K8s Secret + database backup
- Only the API server mounts it
- Consider cert-manager or external PKI for stronger key protection

### Compromised Agent

An agent has access to the resources it proxies. Mitigation:

- Agents are scoped to specific resources (configured in agent.yaml)
- Agent certificates identify the agent — all traffic is attributable
- Agent activity is logged in the audit trail

### Compromised Bridge

A bridge sees encrypted tunnel traffic pass through. It terminates TLS and can
read tunnel contents. Mitigation:

- Bridges are cluster-internal pods, not internet-exposed (SNI passthrough
  means the Gateway doesn't terminate tunnel TLS)
- Bridge certificates are short-lived (24h) and bridge-specific
- Tunnel data is application-level encrypted for protocols that support it
  (SSH has its own encryption layer inside the TLS tunnel)

## Network Security

### External Access

| Traffic | Ingress Path | TLS |
|---------|-------------|-----|
| API / Web UI | Gateway HTTPRoute | Let's Encrypt (terminated) |
| Web app proxy | Gateway HTTPRoute (wildcard) | Let's Encrypt (terminated) |
| Tunnels | Gateway TLSRoute | BAMF CA (passthrough) |

### Internal Access

| Traffic | Path | TLS |
|---------|------|-----|
| API → PostgreSQL | Cluster network | Optional (sslmode) |
| API → Redis | Cluster network | Optional |
| API → Bridge (relay) | Cluster network | None (internal) |

Internal traffic is protected by Kubernetes network policies. Istio service
mesh can be enabled for internal mTLS if required.

## MFA

BAMF intentionally does not implement MFA. MFA is the IdP's responsibility:

- Auth0, Okta, Azure AD all support MFA policies
- BAMF enforces "external SSO required" for specific roles
- This eliminates libfido2, device registration, and per-session MFA complexity

Configure `require_external_sso_for_roles` to ensure privileged roles can only
authenticate through an IdP that enforces MFA.

## Audit

All security-relevant events are recorded:

- Login success/failure (provider, email, IP)
- Certificate issued/renewed
- Resource access granted/denied
- Session start/end
- Admin actions (user/role/token CRUD)

Events include actor identity, timestamp, request ID, and source IP.
See [Monitoring](../operations/monitoring.md) for querying the audit log.
