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

The full break-glass procedure — restoring PostgreSQL, letting the API recover
the CA from the database, and bringing components back online — lives on its own
page: [Disaster Recovery](disaster-recovery.md).

In brief: PostgreSQL is the only thing you must restore (it holds users, roles,
the audit log, and the CA). If the `bamf-ca` Secret is gone but the database is
intact, the API recreates it from the database on the next start
(`kubectl -n bamf rollout restart deployment/bamf-api`). If only Redis is lost,
do nothing — bridges re-register, agents reconnect, and users re-login.

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
