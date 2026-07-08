# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Previous minor | Security fixes only |

We recommend always running the latest release.

## Reporting a Vulnerability

**Please do not open a public issue for security vulnerabilities** — a public
issue discloses the flaw before a fix is available.

Report privately through GitHub's private vulnerability reporting:
[**Report a vulnerability**](https://github.com/mattrobinsonsre/bamf/security/advisories/new).
Include a description, steps to reproduce, affected versions, and any
proof-of-concept. We aim to acknowledge reports within a few working days and
will coordinate a fix and a disclosure timeline with you.

## Security Design

BAMF's security model is documented in detail:

- [Security Architecture](docs/architecture/security.md) — threat model, trust
  boundaries, and component-by-component analysis
- [Authentication](docs/architecture/authentication.md) — auth flows, session
  management, SSO integration
- [Tunnels](docs/architecture/tunnels.md) — certificate-based tunnel security,
  mTLS, session certs

### Key Security Properties

- **Short-lived certificates**: User certs expire in 12 hours, session certs
  in 30 seconds. No long-lived secrets.
- **Authorization encoded in credentials**: Session certificates contain the
  authorization decision (who, what resource, which bridge) in SAN URIs. The
  bridge has zero runtime dependencies — no database, no Redis, no API calls.
- **MFA delegated to IdP**: BAMF never implements MFA. Your identity provider
  (Auth0, Okta, Azure AD) handles MFA enforcement. This eliminates an entire
  class of implementation vulnerabilities.
- **Immediate session revocation**: Sessions are server-side (Redis), not JWTs.
  Revoking a session takes effect instantly.

### Dependency Security

- `govulncheck` (Go), `pip-audit` (Python), and Trivy (container images) run in
  CI on every pull request.
- Dependencies are reviewed weekly.
- No CGo — the Go attack surface is limited to pure Go code.

### Vulnerability suppression policy

The default is to **fix**, not suppress: bump the dependency or base image. A
scanner finding may be suppressed **only when both** of the following hold:

1. no fixed release can be taken yet — there is no fix upstream, or the fix is
   blocked by a compatibility pin we can't move; **and**
2. it is not exploitable in BAMF's configuration (transitive/unused dependency,
   unreachable code path, base-image package we never invoke).

Every suppression lives in a committed allowlist (used identically by local runs
and CI) and **must** carry a justification block: what it is, why it is
safe/unavoidable, and an explicit **"drop when …"** re-evaluation condition.

| Scanner | Allowlist | Format |
|---|---|---|
| Trivy (images) | [`pentest/trivy/.trivyignore`](pentest/trivy/.trivyignore) | one CVE per line + justification comment |
| pip-audit (Python) | [`pentest/pip-audit/ignore-vulns.txt`](pentest/pip-audit/ignore-vulns.txt) | one ID per line + justification comment (read by `scripts/security-scan.sh`) |
| govulncheck (Go) | none — reports only reachable code, so a finding is fixed; a genuinely unfixable, unreachable case is documented here | — |

Item G of the pre-release audit (see `AGENTS.md`) re-reviews every active
suppression on each release and drops any a version bump now fixes.

## Security-Related Configuration

See [Deployment Guide](docs/admin/deployment.md) for production hardening,
including:

- TLS configuration
- Network policies
- Certificate rotation
- Audit log retention
- `require_external_sso_for_roles` enforcement
