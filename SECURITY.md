# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Previous minor | Security fixes only |

We recommend always running the latest release.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

To report a vulnerability, email **security@bamf.dev** with:

1. A description of the vulnerability
2. Steps to reproduce
3. Affected versions (if known)
4. Any potential impact assessment

You will receive an acknowledgment within 48 hours. We aim to provide an
initial assessment within 5 business days and a fix or mitigation plan within
30 days, depending on severity.

## Disclosure Policy

- We follow coordinated disclosure. We ask that reporters give us reasonable
  time to address issues before public disclosure (typically 90 days).
- We will credit reporters in the security advisory unless they prefer to
  remain anonymous.
- Security fixes are released as patch versions with a GitHub Security Advisory.

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

- `govulncheck` (Go) and `pip-audit` (Python) run in CI on every pull request.
- Dependencies are reviewed weekly.
- No CGo — the Go attack surface is limited to pure Go code.

## Security-Related Configuration

See [Deployment Guide](docs/admin/deployment.md) for production hardening,
including:

- TLS configuration
- Network policies
- Certificate rotation
- Audit log retention
- `require_external_sso_for_roles` enforcement
