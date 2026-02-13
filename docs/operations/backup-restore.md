# Backup and Restore

## What to Back Up

**PostgreSQL** is the only critical backup target. It contains:
- User accounts and credentials
- RBAC roles and assignments
- Agent registrations and join tokens
- Audit log (security events, admin actions)
- Session recordings
- CA certificate and private key (disaster recovery copy)

**Redis** is ephemeral by design. A Redis restart loses runtime state, but this
is recoverable: bridges re-register, agents reconnect, users re-login.

**Kubernetes Secrets** contain the CA keypair and TLS certificates, but the CA
is also stored in the database, and TLS certs are managed by cert-manager.

## Backup Strategies

### pg_dump (Logical Backup)

```zsh
# Full backup
pg_dump -h bamf-db.example.com -U bamf -d bamf -Fc -f bamf-$(date +%Y%m%d).dump

# Restore
pg_restore -h bamf-db.example.com -U bamf -d bamf bamf-20260213.dump
```

### Cloud Provider Snapshots

- **AWS RDS**: Automated backups + manual snapshots
- **GCP Cloud SQL**: Automated + on-demand backups
- **Azure Database**: Automated backups with PITR

### Velero (Full Cluster)

For backing up the entire BAMF namespace including Secrets:

```zsh
velero backup create bamf-backup --include-namespaces bamf
velero restore create --from-backup bamf-backup
```

## Backup Schedule

| Environment | Frequency | Retention |
|-------------|-----------|-----------|
| Production | Hourly | 30 days |
| Staging | Daily | 7 days |
| Development | Manual | As needed |

## Disaster Recovery

### Full Recovery from Database Backup

1. Provision new PostgreSQL instance
2. Restore backup: `pg_restore -d bamf bamf-backup.dump`
3. Deploy BAMF with `ca.provider: bootstrap-from-db`
4. API extracts CA from database, creates K8s Secret
5. Verify: agents reconnect, users can log in

### CA Key Recovery

If the K8s Secret containing the CA is deleted but PostgreSQL is intact:

```zsh
# API auto-recovers on startup: detects missing Secret, reads CA from DB
kubectl -n bamf rollout restart deployment/bamf-api
```

Or manually extract:
```zsh
bamf admin ca export --output ca.crt --key ca.key
kubectl -n bamf create secret generic bamf-ca \
  --from-file=ca.crt --from-file=ca.key
```

### Partial Recovery

If only Redis is lost (restart, eviction):
- No action needed — all components reconnect and re-register
- Active tunnel sessions will disconnect; users reconnect

If only individual pods are lost:
- Kubernetes restarts them automatically
- Bridges re-register; agents reconnect
- Active tunnels migrate via reliable stream protocol

## Testing Restores

Regularly test your backup process:

```zsh
# Create a test database
createdb bamf_restore_test

# Restore backup
pg_restore -d bamf_restore_test bamf-backup.dump

# Verify data
psql bamf_restore_test -c "SELECT count(*) FROM users;"
psql bamf_restore_test -c "SELECT count(*) FROM audit_logs;"
psql bamf_restore_test -c "SELECT count(*) FROM certificate_authority;"

# Clean up
dropdb bamf_restore_test
```
