# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest release | Yes |
| Previous minor | Security fixes only |

We recommend always running the latest release.

## Reporting a Vulnerability

To report a security vulnerability, please
[open a GitHub issue](https://github.com/mattrobinsonsre/bamf/issues/new).
Include a description of the vulnerability, steps to reproduce, and affected
versions if known.

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
