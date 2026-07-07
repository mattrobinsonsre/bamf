# Disaster Recovery

Break-glass recovery of a BAMF control plane after losing the cluster, the
database, or both. The single source of truth you must protect is **PostgreSQL**
— it holds users, roles, role assignments, the audit log, and the internal CA
(cert + key). A PostgreSQL backup is therefore a complete recovery point.
Redis is disposable: its state rebuilds itself.

See [Backup & Restore](backup-restore.md) for how to *take* the backups this
procedure restores from.

## What survives what

| Loss | Impact | Recovery |
|---|---|---|
| Redis only | New tunnels/sessions fail transiently | Restart Redis; bridges re-register, agents reconnect, users re-login. No restore needed. |
| API pods / cluster (DB intact) | Control plane down | Redeploy the chart against the same PostgreSQL; the CA and all identity come back from the DB. |
| PostgreSQL | Users, roles, audit, and CA lost | Restore PostgreSQL from backup (below), then redeploy. |

## Full recovery from a database backup

### 1. Restore PostgreSQL

Restore your latest backup into a reachable PostgreSQL instance (see
[Backup & Restore](backup-restore.md) for `pg_dump`/snapshot specifics). This
brings back users, roles, role assignments, the audit log, and the CA keypair.

### 2. Redeploy BAMF against the restored database

```sh
helm upgrade --install bamf oci://ghcr.io/mattrobinsonsre/bamf \
  --namespace bamf --create-namespace \
  --values production-values.yaml \
  --set core.postgresql.external.host=<restored-db-host>
```

### 3. The CA recovers automatically

On startup the API reads the CA from the `bamf-ca` Kubernetes Secret. If that
Secret is missing (a fresh cluster) but the CA exists in the restored database,
the API **recreates the Secret from the database**. No manual CA import is
needed — protecting the database protects the CA.

### 4. Bring components back and let clients reconnect

- Bridges register in Redis on startup and become available.
- Agents reconnect over HTTPS; if their certificates are still within their
  1-year validity they resume without re-registration and re-publish resources.
- Users run `bamf login` again to get fresh short-lived certs.

## Verification

- `/ready` on the API returns 200 (DB + Redis reachable).
- `bamf login` issues a certificate through your IdP.
- Existing agents show **online** and their resources appear in `bamf ls`.
- A `bamf ssh <resource>` session succeeds and lands in the audit log.
- Spot-check the audit log for pre-incident entries (confirms the DB restore
  captured history).

## Notes

- **Rehearse this.** A restore you have never tested is a hope, not a plan. Run
  it against a scratch database on a schedule.
- **CA rotation window**: a database backup taken *before* a CA rotation is your
  rollback for a bad rotation — keep enough retention to cover your rotation
  cadence.
- **Redis-only restores are unnecessary** — never try to "restore" Redis; let it
  rebuild from live heartbeats and logins.
