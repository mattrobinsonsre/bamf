# BAMF vs Teleport

BAMF is an open-source alternative to [Teleport](https://goteleport.com/) for
secure infrastructure access. This page compares the two projects to help you
decide which is right for your team.

## License

Teleport Community Edition switched to a commercial license starting with
[version 16](https://github.com/gravitational/teleport/discussions/39158)
(June 2024). Companies may only use it if they have fewer than 100 employees
**and** less than $10M annual revenue. Larger organizations must purchase
Teleport Enterprise — there is no free option. Companies also cannot embed
or resell Teleport Community in their products or services.

Prior to v16, Teleport Community was AGPLv3. The source remains available but
the license is no longer open-source by any standard definition.

BAMF is licensed under the **GNU General Public License v3.0** with no usage
restrictions. Any organization can use, modify, and distribute BAMF regardless
of size or revenue. There is no CLA.

| | BAMF | Teleport Community |
|---|---|---|
| License | GPLv3 | Commercial (employee + revenue caps) |
| Source available | Yes | Yes |
| Free for individuals | Yes | Yes |
| Free for companies >100 employees | Yes | No |
| Free for companies >$10M revenue | Yes | No |
| Embedding / reselling | Permitted (GPLv3 terms) | Prohibited |

## SSO — The Biggest Gap

This is the single most important difference for most teams.

Teleport Community Edition supports **GitHub SSO only**. To use Okta, Azure AD,
Google Workspace, Auth0, Keycloak, or any generic OIDC/SAML provider, you need
Teleport Enterprise.

BAMF includes full SSO support in the open-source release:

| SSO Provider | BAMF (GPLv3) | Teleport Community | Teleport Enterprise |
|---|---|---|---|
| GitHub | Planned | Yes | Yes |
| Auth0 | Yes | No | Yes |
| Okta | Yes | No | Yes |
| Google Workspace | Yes | No | Yes |
| Microsoft Entra ID (Azure AD) | Yes | No | Yes |
| Keycloak | Yes | No | Yes |
| Generic OIDC | Yes | No | Yes |
| Generic SAML 2.0 | Yes | No | Yes |

Without SSO, teams must manage individual user accounts and passwords — a
significant operational burden and security risk. SSO is table stakes for any
team that uses an identity provider, which is nearly every team.

BAMF delegates MFA entirely to the identity provider. Teleport implements its
own per-session MFA (TOTP, WebAuthn) which adds complexity to the codebase and
user experience. With BAMF, your IdP controls MFA policy — if your IdP requires
hardware keys, BAMF respects that without needing its own MFA implementation.

## Feature Comparison

### Access Protocols

| Feature | BAMF | Teleport Community |
|---|---|---|
| SSH access | Yes (wraps native ssh) | Yes (custom tsh client) |
| Database access (PostgreSQL, MySQL) | Yes (TCP tunnels) | Yes |
| Kubernetes access | Yes (impersonation) | Yes |
| Web application proxy | Yes (HTTP proxy) | Yes |
| Windows/RDP desktop access | No | Yes |
| Generic TCP tunnels | Yes | Yes |

BAMF wraps the native `ssh`, `scp`, and `sftp` commands via `ProxyCommand`.
All SSH flags, port forwarding, jump hosts, and config options work unchanged.
Teleport uses a custom `tsh` client that reimplements SSH — it supports most
common options but not all.

### Security

| Feature | BAMF | Teleport Community |
|---|---|---|
| Short-lived certificates | Yes (x509 + SSH) | Yes (SSH + x509) |
| Certificate authority | Built-in | Built-in |
| mTLS tunnels | Yes | Yes |
| Role-based access control | Yes | Yes |
| Per-session MFA | No (delegated to IdP) | Yes (TOTP, WebAuthn) |
| Session & identity locks | No | No (Enterprise only) |
| Device trust | No | No (Enterprise only) |
| FIPS-compliant binaries | No | No (Enterprise only) |

### Audit and Compliance

| Feature | BAMF | Teleport Community |
|---|---|---|
| Structured audit logs | Yes | Yes |
| SIEM export | Yes (REST API) | Yes |
| SSH session recording | Yes (asciicast v2, opt-in `ssh-audit` type) | Yes |
| Database query audit | Yes (passive wire protocol tapping, `postgres-audit`/`mysql-audit`) | No |
| HTTP request/response audit | Yes (full exchange capture, `http-audit` type) | No |
| Session playback (web UI) | Yes (asciinema player, query viewer, HTTP exchange viewer) | Yes |
| Enhanced session recording (kernel) | No | Yes |
| Dual authorization | No | No (Enterprise only) |
| Session moderation | No | No (Enterprise only) |

### Operations

| Feature | BAMF | Teleport Community |
|---|---|---|
| Helm chart | Yes | Yes |
| High availability | Yes (multi-replica) | Yes |
| Terraform provider | No | Yes |
| Auto-discovery (AWS/GCP/Azure) | No | Yes |
| Trusted clusters (federation) | No | Yes |

## Build Complexity

One of BAMF's design goals is a radically simpler build process.

### BAMF

```
Languages:    Go + Python + TypeScript
C toolchain:  Not required (CGO_ENABLED=0)
Build tools:  go build, poetry, npm, docker
Build time:   ~2 minutes (clean build)
Binary size:  ~19 MB (CLI)
```

BAMF produces static Go binaries with zero C dependencies. The API server
is standard Python/FastAPI. The web UI is a standard Next.js application.
Any developer with Go, Python, and Node.js installed can build from source
in minutes.

### Teleport

```
Languages:    Go + Rust + TypeScript
C toolchain:  Required (CGO_ENABLED=1)
C libraries:  libfido2, OpenSSL 1.1 (for tsh FIDO support)
Rust:         Required (for Desktop Access)
Build tools:  go build, cargo, yarn, make
Build time:   15-30+ minutes (clean build)
Memory:       1+ GB RAM minimum
Binary size:  ~150 MB (teleport)
```

Teleport requires CGo for FIDO2/WebAuthn support (libfido2 C library), Rust
for the Desktop Access RDP implementation, and yarn for the web UI. The build
uses `CGO_ENABLED=1`, meaning cross-compilation requires a C cross-toolchain
for each target platform. The `teleport` binary is roughly 8x larger than
BAMF's CLI.

Source: [Teleport installation docs](https://goteleport.com/installing/)

## Architecture Comparison

### BAMF

- **Go** for the data path: CLI, bridge (tunnel relay), agent
- **Python/FastAPI** for the control plane: API, CA, RBAC, SSO, HTTP proxy
- **Next.js** for the web UI
- Bridge is a protocol-agnostic byte relay — never interprets tunneled traffic
- Agent is a lightweight static binary (~15 MB)
- Session certificates encode authorization decisions directly — bridge has
  zero runtime dependencies (no database, no Redis, no API calls)

### Teleport

- **Go** for all server components (with CGo for FIDO2)
- **Rust** for Desktop Access (RDP)
- **TypeScript** for the web UI
- Single `teleport` binary serves as proxy, auth, and node
- Teleport Auth Service issues certificates and manages cluster state
- Teleport Proxy Service handles routing, TLS termination, and web UI

## What BAMF Doesn't Have (Yet)

BAMF is a younger project. Features that Teleport has and BAMF does not:

- **Windows/RDP desktop access** — Teleport has a Rust-based RDP gateway.
  BAMF has no RDP support and no plans for it in the near term.
- **Auto-discovery** — Teleport can automatically discover EC2 instances,
  RDS databases, EKS clusters, etc. BAMF requires manual agent configuration.
- **Terraform provider** — Teleport has a mature Terraform provider for
  managing resources as code. BAMF uses the REST API and Helm values.
- **Trusted clusters** — Teleport supports federated multi-cluster topologies.
  BAMF is single-cluster.
- **Machine ID / workload identity** — Teleport has a separate product for
  service-to-service authentication. BAMF is focused on human access.
- **GitHub SSO** — Teleport Community supports GitHub as an SSO provider.
  BAMF supports OIDC and SAML providers but does not have a dedicated GitHub
  connector yet.

## When to Choose BAMF

- Your team uses an identity provider (Okta, Azure AD, Auth0, Google, Keycloak)
  and needs SSO without paying for an enterprise license
- You want a truly open-source solution (GPLv3) with no usage restrictions
- You value build simplicity — standard Go + Python toolchains, no C/Rust deps
- You don't need Windows/RDP desktop access
- You prefer a lighter-weight deployment (separate Go data path + Python control plane)

## When to Choose Teleport

- You need Windows/RDP desktop access
- You need auto-discovery of cloud resources (EC2, RDS, EKS)
- You need trusted clusters / multi-cluster federation
- You're a small team (<100 employees, <$10M revenue) and GitHub SSO is sufficient
- You need the mature Terraform provider ecosystem
- You're willing to pay for Enterprise to unlock full SSO and governance features
