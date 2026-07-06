# Certificate Management

BAMF uses an internal Certificate Authority (CA) for tunnel authentication.
This is separate from the public HTTPS certificates used by the Istio Gateway.

## Certificate Types

| Certificate | Issued to | Lifetime | Purpose |
|---|---|---|---|
| **Identity cert** | CLI user (after login) | 12 hours | Proves user identity to API |
| **Session cert** | CLI user + agent (per tunnel) | 30s setup, extended on connect | Authorizes a specific tunnel session |
| **Agent cert** | Agent (at registration) | 1 year (8760 hours) | Proves agent identity |
| **Bridge cert** | Bridge (at startup) | 24 hours | Proves bridge identity for mTLS |

## Session Certificates

Session certs are the key innovation. They encode the authorization decision
directly into the certificate using custom SAN URIs:

```
SAN URIs:
  bamf://session/{session_id}      — pairs client + agent
  bamf://resource/{resource_name}  — target resource
  bamf://bridge/{bridge_id}        — which bridge this is for
  bamf://role/{role_name}          — authorized role (one per role)
```

The bridge validates the cert chain against the BAMF CA, reads the SAN URIs,
and pairs connections by session ID. No runtime API calls needed.

## Internal CA Options

### Helm-Generated CA (Default)

Helm generates the CA keypair at install time. It's stored in a K8s Secret and
preserved across upgrades:

```yaml
ca:
  provider: helm
  duration: 87600h  # 10 years
```

Pros: Zero dependencies, works out of the box.
Cons: Manual rotation (delete secret + upgrade).

### cert-manager Managed CA

Use cert-manager for automatic renewal:

```yaml
ca:
  provider: cert-manager
  certManager:
    duration: 87600h
    renewBefore: 720h  # 30 days
```

When `issuerName` is empty, the chart creates a self-signed issuer chain
automatically.

### Existing CA

Bring your own CA from Vault, corporate PKI, etc.:

```yaml
ca:
  provider: existing
  existing:
    secretName: my-corporate-ca
    certKey: tls.crt
    keyKey: tls.key
```

## CA Component Access

| Component | Secret Access | Usage |
|-----------|---------------|-------|
| API | cert + key | Signs all certificates |
| Bridge | cert only | Validates session certs |
| CLI | Downloaded from API | Validates bridge cert |
| Agent | Downloaded from API | Validates bridge cert |

Only the API server needs the CA private key. CLI and agents fetch the public
cert from `/api/v1/certificates/ca` over public HTTPS.

## Certificate Revocation

BAMF certificates are short-lived, but the long-lived service certs (agents
default to 1 year, bridges to 24h) need a kill-switch for the case where a
private key leaks. A revocation denylist provides it.

```zsh
# Revoke a certificate by its SHA-256 fingerprint (admin only)
curl -X POST https://bamf.example.com/api/v1/certificates/revoke \
  -H "Authorization: Bearer $BAMF_SESSION" \
  -H "Content-Type: application/json" \
  -d '{"fingerprint": "<sha256-hex>", "reason": "key compromised"}'

# List revoked certificates (admin or audit)
curl https://bamf.example.com/api/v1/certificates/revoked \
  -H "Authorization: Bearer $BAMF_SESSION"
```

How it works:

- **Durable source of truth** — revoked fingerprints are stored in Postgres, so
  they survive restarts and are covered by your database backup.
- **Fast enforcement** — the denylist is mirrored into a Redis set and checked on
  every agent/bridge request (those presenting `X-Bamf-Client-Cert`). A revoked
  cert gets `401`. The set is re-seeded from Postgres at startup and periodically
  thereafter, so it survives a Redis restart/flush.
- **Fails open** — if Redis is unavailable the check fails open (consistent with
  the rate limiter); the periodic re-seed bounds the exposure window.
- **Scope** — revocation targets the long-lived service certs. User access is
  revoked separately by deleting the session (`DELETE /api/v1/auth/sessions/{id}`
  or `revoke_all_user_sessions`), and per-tunnel session certs are 30-second TTL,
  so a revoked identity simply stops getting new ones.

Fingerprints are normalized on ingest (lowercase, colons/spaces stripped), so
either `AA:BB:CC…` or `aabbcc…` forms work.

## CA Backup and Recovery

The CA cert and key are stored in the database (in addition to the K8s Secret).
A PostgreSQL backup includes everything needed for disaster recovery.

Recovery procedure:
1. Restore PostgreSQL from backup
2. Deploy BAMF with `ca.provider: bootstrap-from-db`
3. API extracts CA from database, creates K8s Secret
4. All components start normally

Manual extraction:
```zsh
bamf admin ca export --output ca.crt --key ca.key
```

## Public HTTPS Certificates

Public-facing TLS (API, Web UI, web app proxy) uses Let's Encrypt via
cert-manager, configured in the Gateway section:

```yaml
tls:
  certManager:
    enabled: true
    issuerRef:
      name: letsencrypt-prod
      kind: ClusterIssuer
```

Two certificates are created:
- `bamf.example.com` — API and Web UI
- `*.tunnel.bamf.example.com` — web app proxy and tunnel HTTPS (wildcard,
  requires DNS-01 challenge)

## Trust Model

```
Public Internet (Let's Encrypt)     Internal (BAMF CA)
         │                                  │
    Istio Gateway                     Bridge ↔ Agent
    API endpoints                     CLI ↔ Bridge
    Web UI                            Session certs
    Web app proxy
```

Public HTTPS protects the API surface. The BAMF CA protects the tunnel
infrastructure. These are independent trust chains — compromising one does
not affect the other.
