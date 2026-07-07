# Security Hardening

Operational hardening for a production BAMF deployment. This is the *how to lock
it down* companion to the design-level [Security](../architecture/security.md)
page and the [Production Checklist](../operations/production-checklist.md).

## Transport security

- **PostgreSQL**: require TLS — `core.postgresql.external.sslmode: require` (or
  `verify-full` with a CA bundle).
- **Redis**: use a TLS endpoint where your provider offers one; keep Redis on a
  private subnet regardless.
- **Ingress**: terminate public TLS at the ingress with a cert-manager-issued
  wildcard (`tls.certManager`). Tunnel mTLS (CLI ↔ bridge ↔ agent) uses the
  BAMF internal CA and is independent of the public cert.

## Authentication hardening

- **Disable local auth** (`core.auth.local.enabled: false`) so all access goes
  through your IdP, where MFA is enforced. Keep at most one break-glass local
  admin, and know its blast radius.
- **Require SSO for privileged roles** — list `admin`, `k8s-access`, etc. under
  `require_external_sso_for_roles` so they can never be reached via local
  password.
- **Short user certs** — `core.api.config.certificates.user_ttl_hours` (default
  12). Lower it if your sessions should expire faster; users re-login via SSO.

## Secrets

- **Kubernetes Secrets only** — never place a password, client secret, or join
  token in the API ConfigMap. The chart wires all of these via `secretKeyRef` /
  `existingSecret`; CI's `helm-config-contract` fails a build that leaks one.
- **ExternalSecrets Operator** (recommended) — sync DB/Redis/OIDC credentials
  from AWS Secrets Manager / Vault / etc. rather than inline `password:` values,
  so nothing sensitive lives in your GitOps repo.
- **The CA key** is stored in the `bamf-ca` Secret and mirrored into PostgreSQL
  for disaster recovery — protect database backups accordingly (see
  [Disaster Recovery](../operations/disaster-recovery.md)).

## Network policies

The chart does not ship NetworkPolicies — author them for your cluster. Enforce:

- Only **API pods** may reach PostgreSQL and Redis. Bridges, agents, the proxy,
  and web UI must not.
- Bridge tunnel ports accept traffic only from the ingress controller.
- Default-deny egress where practical; allow agents only their targets + the API.

## Pod security

Set `podSecurityContext` (and container `securityContext`) per component to run
as non-root, read-only root filesystem where possible, and drop all
capabilities. The bridge needs `devpts` for web-terminal PTYs but still runs
unprivileged. Align with the Kubernetes **Restricted** Pod Security Standard.

## Rate limiting

Two independent tiers, both worth enabling:

- **Ingress** (`gateway.rateLimit`) — coarse per-IP limiting at the edge
  (Traefik Middleware / Istio EnvoyFilter).
- **API app tier** (`core.api.config.rate_limit`) — a Redis-backed sliding
  window that distinguishes authenticated from anonymous traffic and applies a
  strict per-IP limit to `/auth/*` for login brute-force defence. Tune
  `trusted_proxy_hops` to the number of proxies in front of the API so client
  IPs aren't spoofable.

## Audit logging

- **Retention** — `core.api.config.audit.retention_days` (default 90; `0`
  disables pruning and keeps rows forever). A background sweep enforces it.
- **API self-audit** — `core.api.config.audit.api_audit_enabled` records API
  request/response exchanges (with redaction) for a full control-plane trail.
- **SIEM export** — poll the audit API (`GET /api/v1/audit`, cursor-paginated)
  from your SIEM. Sensitive headers/bodies are redacted before storage.

## Database hardening

- Dedicated database and least-privilege role for BAMF (no superuser).
- Encryption at rest (default on managed providers) and in transit (above).
- Restrict network access to the API's security group / subnet only.

## Agent isolation

- **Join tokens** are short-lived (default 24h) and can be usage-capped and
  revoked. Delete a token once the agent has registered — the cert then carries
  identity, and the token is no longer needed.
- **Kubernetes access** is via impersonation: the agent's ServiceAccount holds
  `impersonate` and BAMF roles decide which `kubernetes_groups` a user maps to.
  Never grant a proxied app its own K8s RBAC — that bypasses BAMF entirely. Keep
  the agent SA scoped to impersonation only.
