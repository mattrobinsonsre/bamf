# Production Readiness Checklist

Work through this before putting a BAMF deployment in front of real users. Each
item links to the page with the detail. Treat unchecked items as blockers, not
nice-to-haves.

## Infrastructure

- [ ] **Kubernetes 1.27+** with a **Traefik v3** or **Istio** ingress that can do
      **SNI-based TLS passthrough** (standard `Ingress` cannot route tunnel
      traffic to individual bridge pods). See
      [Deployment → Ingress Requirements](../admin/deployment.md).
- [ ] **External PostgreSQL** (`core.postgresql.external.enabled: true`) — RDS,
      Aurora, Cloud SQL, etc. — with Multi-AZ/HA and automated backups. The
      bundled subchart is dev/staging only.
- [ ] **External Redis** (`core.redis.external.enabled: true`) — ElastiCache,
      Memorystore, etc. Redis holds live tunnel/session state; losing it is
      recoverable (agents re-register, users re-login) but disruptive.
- [ ] **Wildcard DNS** for `*.tunnel.<domain>` and `*.bridge.tunnel.<domain>`
      pointing at the ingress LoadBalancer.

## Certificates & the internal CA

- [ ] **Public TLS** via cert-manager — a wildcard cert for `*.tunnel.<domain>`
      (DNS-01) referenced through `tls.certManager.issuerRef`, plus the
      API/Web host cert.
- [ ] **Internal CA** — issued and owned by the API, backed up inside PostgreSQL
      (so a database backup is a complete CA backup). No separate CA key to
      manage. See [Certificates](../admin/certificates.md).
- [ ] **Certificate lifetimes** reviewed (`core.api.config.certificates`):
      user 12h, agent 8760h (1 year), bridge 24h. Shorten user certs if your
      threat model calls for it.

## Authentication & access control

- [ ] **SSO configured** (OIDC/SAML) as the default provider; Auth0 or your IdP.
      See [SSO](../admin/sso.md).
- [ ] **Local auth disabled** for production (`core.auth.local.enabled: false`)
      unless you have a deliberate break-glass local admin.
- [ ] **`require_external_sso_for_roles`** set so privileged roles (admin,
      k8s-access) can't be obtained via local password.
- [ ] **RBAC reviewed** — roles, allow/deny by label and name, and
      `kubernetes_groups` mappings. Deny wins; admin bypasses everything. See
      [RBAC](../admin/rbac.md).

## Secrets

- [ ] **No secrets in ConfigMaps** — database/Redis passwords, OIDC client
      secrets, and join tokens flow via `secretKeyRef` / `existingSecret` /
      ExternalSecrets, never the API ConfigMap. CI enforces this
      (`helm-config-contract`), but confirm your overrides follow it.
- [ ] **ExternalSecrets** (recommended) syncing DB/Redis/OIDC credentials from
      your secret store rather than inline `password:` values.

## Networking & isolation

- [ ] **NetworkPolicy** applied so only API pods reach PostgreSQL/Redis (the
      chart does not ship one — author it for your cluster). Bridges, agents,
      and the proxy must never connect to the data stores directly.
- [ ] **Rate limiting** enabled at both tiers: ingress (`gateway.rateLimit`) and
      the API's per-IP sliding window (`core.api.config.rate_limit`, which
      applies a stricter limit to `/auth/*`).
- [ ] **`podSecurityContext`** set per component (run as non-root, drop
      capabilities) — see [Security Hardening](../admin/security-hardening.md).

## Backups & recovery

- [ ] **PostgreSQL backups** automated (daily minimum, hourly for prod) — this
      captures users, roles, audit log, and the CA. See
      [Backup & Restore](backup-restore.md).
- [ ] **Restores tested** on a schedule, not assumed. Rehearse the
      [Disaster Recovery](disaster-recovery.md) break-glass path at least once.

## Monitoring & observability

- [ ] **Bridge metrics** scraped (`bamf_bridge_*`, the only Prometheus surface).
      See [Monitoring](monitoring.md).
- [ ] **Structured logs** shipped to your aggregator (JSON, stdout).
- [ ] **Audit log retention** set (`core.api.config.audit.retention_days`,
      default 90; `0` keeps forever) and, if required, exported to a SIEM via
      the audit API.

## Scaling & availability

- [ ] **API replicas ≥ 2** with an HPA and a PodDisruptionBudget (`pdb`).
- [ ] **Bridge HPA** and per-pod Services/TLSRoutes pre-created up to
      `maxReplicas`. See [Scaling](scaling.md).
- [ ] **Spot/termination handling** — `terminationGracePeriodSeconds` and
      preStop drains are set so tunnels migrate or reconnect cleanly.

## Pre-go-live validation

Smoke-test the real stack, not just unit tests:

- [ ] `bamf login` through your production IdP issues a certificate.
- [ ] `bamf ssh <resource>` opens a session and it appears in the audit log.
- [ ] A web app resource loads through `https://<app>.tunnel.<domain>`.
- [ ] `kubectl --context bamf-<cluster> get pods` works via the proxy.
- [ ] An access-denied case is actually denied (negative test).
- [ ] Kill a bridge pod mid-session and confirm the reliable stream reconnects.
