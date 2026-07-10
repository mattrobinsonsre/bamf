# BAMF vs Teleport

BAMF is an open-source alternative to [Teleport](https://goteleport.com/) for
secure infrastructure access. This page compares BAMF to Teleport in depth (its
closest full-featured peer) and, more briefly, to
[other open-source options](#other-open-source-options).

## What makes BAMF different

Two things stand out:

1. **It's trivial to build and run.** BAMF is pure Go, Python, and TypeScript —
   no C toolchain, no Rust, no protobuf codegen, no custom build tooling. Static
   Go binaries cross-compile with `CGO_ENABLED=0`, the API is standard
   FastAPI, and the UI is standard Next.js, so a clean build takes minutes on a
   laptop (see [Build complexity](#build-complexity)).
2. **It's genuinely free, with no strings.** MPL-2.0 (file-level copyleft), no
   employee or revenue caps, no CLA, and embedding or reselling is permitted.
   Full SSO — Auth0, Okta, Google, Microsoft Entra ID, Keycloak, and generic
   OIDC/SAML — is in the open-source release, not behind an enterprise license.

## License

Teleport Community Edition switched to a commercial license starting with
[version 16](https://github.com/gravitational/teleport/discussions/39158)
(June 2024). Companies may only use it if they have fewer than 100 employees
**and** less than $10M annual revenue. Larger organizations must purchase
Teleport Enterprise — there is no free option. Companies also cannot embed
or resell Teleport Community in their products or services.

Prior to v16, Teleport Community was AGPLv3. The source remains available but
the license is no longer open-source by any standard definition.

BAMF is licensed under the **Mozilla Public License 2.0** with no usage
restrictions. Any organization can use, modify, and distribute BAMF regardless
of size or revenue. There is no CLA.

| | BAMF | Teleport Community |
|---|---|---|
| License | MPL-2.0 | Commercial (employee + revenue caps) |
| Source available | Yes | Yes |
| Free for individuals | Yes | Yes |
| Free for companies >100 employees | Yes | No |
| Free for companies >$10M revenue | Yes | No |
| Embedding / reselling | Permitted (MPL-2.0, file-level copyleft) | Prohibited |

## SSO — The Biggest Gap

This is the single most important difference for most teams.

Teleport Community Edition supports **GitHub SSO only**. To use Okta, Azure AD,
Google Workspace, Auth0, Keycloak, or any generic OIDC/SAML provider, you need
Teleport Enterprise.

BAMF includes full SSO support in the open-source release:

| SSO Provider | BAMF (MPL-2.0) | Teleport Community | Teleport Enterprise |
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
| Short-lived certificates | Yes (x509) | Yes (SSH + x509) |
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
- Session certificates encode authorization decisions directly — bridge validates
  certs locally during tunnel operation (no database or Redis access)

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

## Other open-source options

Teleport is BAMF's closest feature peer, so it gets the detailed comparison
above. Two other well-regarded open-source projects solve overlapping problems
with different scope and trade-offs — both are actively developed and worth
evaluating on their own merits:

- **[Warpgate](https://github.com/warp-tech/warpgate)** — a smart bastion for
  SSH, HTTP(S), and databases, written in Rust and shipped as a single binary
  under Apache-2.0. It's lightweight and easy to run, with a web admin UI and
  session recording. Its scope is deliberately narrower than BAMF's — a protocol
  bastion rather than a full access platform (for example, it doesn't provide
  Kubernetes access). If you want the smallest possible SSH/DB bastion, Warpgate
  is an excellent fit.
- **[JumpServer](https://github.com/jumpserver/jumpserver)** — a mature, broad
  open-source PAM / bastion (GPLv3 core, with a separate commercial edition),
  written in Python and Go. It covers a very wide surface — SSH, RDP, VNC,
  databases, Kubernetes, web apps, organizations, and a rich web console. It is
  more feature-complete than BAMF today, and correspondingly heavier to operate.
  If you need RDP/VNC or broad PAM features in one open-source product,
  JumpServer is worth a look.

At a glance (a high-level orientation, not an exhaustive matrix — check each
project's own docs for current specifics):

| | BAMF | Warpgate | JumpServer |
|---|---|---|---|
| License | MPL-2.0 (no caps) | Apache-2.0 | GPLv3 (+ commercial edition) |
| Language | Go + Python + TypeScript | Rust | Python + Go |
| Positioning | Full access platform, trivial build | Lightweight protocol bastion | Broad, feature-rich PAM |
| RDP / VNC | No | No | Yes |

BAMF's niche sits between them: Teleport-like breadth (SSH, databases,
Kubernetes, web apps, session recording, RBAC) with Warpgate-like build and
operational simplicity, plus SSO in the open-source release — all under a
permissive, cap-free license.

## When to Choose BAMF

- Your team uses an identity provider (Okta, Azure AD, Auth0, Google, Keycloak)
  and needs SSO without paying for an enterprise license
- You want a truly open-source solution (MPL-2.0) with no usage restrictions
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
