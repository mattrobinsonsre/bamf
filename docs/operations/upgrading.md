# Upgrading

## Helm Upgrade

```zsh
# Check current version
helm -n bamf list

# Upgrade to latest
helm upgrade bamf oci://ghcr.io/mattrobinsonsre/bamf/charts/bamf \
  --namespace bamf \
  --values production-values.yaml

# Upgrade to specific version
helm upgrade bamf oci://ghcr.io/mattrobinsonsre/bamf/charts/bamf \
  --namespace bamf \
  --version 1.2.0 \
  --values production-values.yaml
```

## Upgrade Process

### What Happens During Upgrade

1. **Database migrations** run first (Helm pre-upgrade hook)
2. **API pods** roll out with the new image (rolling update)
3. **Bridge pods** roll out one at a time (StatefulSet ordered update)
4. **Web UI pods** roll out with the new image
5. **Agent pods** roll out (if deployed via Helm)

### Zero-Downtime Upgrades

BAMF is designed for zero-downtime upgrades:

- **API**: Rolling update with PDB — at least one pod always serves requests
- **Bridge**: StatefulSet ordered update. Active tunnels on a draining bridge
  are migrated to other bridges via the reliable stream protocol. Users
  experience a brief stall (<2s) during migration, not a disconnect.
- **Web UI**: Rolling update, stateless
- **Agents**: Rolling restart. Active tunnels reconnect through the reliable
  stream protocol.

### Bridge Upgrade Behavior

Bridges are a StatefulSet — pods update in reverse ordinal order (highest first).
For each pod:

1. Kubernetes sends SIGTERM
2. Bridge notifies API: "draining"
3. API migrates active tunnels to other bridge pods
4. Once drained (or `terminationGracePeriodSeconds` reached), pod exits
5. New pod starts with updated image

## Pre-Upgrade Checklist

1. **Backup the database**: `pg_dump` or cloud provider snapshot
2. **Check release notes**: Review breaking changes and migration notes
3. **Verify cluster health**: All pods running, no pending migrations
4. **Test in staging first**: Always upgrade staging before production

## Rollback

```zsh
# List revision history
helm -n bamf history bamf

# Rollback to previous revision
helm -n bamf rollback bamf

# Rollback to specific revision
helm -n bamf rollback bamf 3
```

**Database rollback**: If the new version included database migrations, you may
need to rollback those too:

```zsh
# Check migration status
kubectl -n bamf exec -it deploy/bamf-api -- alembic current

# Rollback last migration
kubectl -n bamf exec -it deploy/bamf-api -- alembic downgrade -1
```

## Version Compatibility

| Component | Compatibility |
|-----------|---------------|
| CLI ↔ API | CLI version should be ≤ API version. Newer APIs are backward compatible. |
| Agent ↔ API | Same as CLI. Update API first, then agents. |
| Bridge ↔ API | Tightly coupled. Update together via Helm. |
| Database | Forward-only migrations. Rollback requires explicit Alembic downgrade. |

**Recommended upgrade order**: API (includes bridge) → agents → CLI

## Agent Updates

### Kubernetes Agents

Agents deployed via Helm update automatically with `helm upgrade`.

### VM Agents

Update the binary and restart:

```zsh
# Download new version
curl -L https://github.com/mattrobinsonsre/bamf/releases/latest/download/bamf-agent-linux-amd64 \
  -o /usr/local/bin/bamf-agent.new

# Swap binary and restart
mv /usr/local/bin/bamf-agent.new /usr/local/bin/bamf-agent
chmod +x /usr/local/bin/bamf-agent
systemctl restart bamf-agent
```

The agent reconnects with its stored certificate — no re-registration needed.

## CLI Updates

Download the new binary:

```zsh
curl -L https://github.com/mattrobinsonsre/bamf/releases/latest/download/bamf-darwin-arm64 \
  -o /usr/local/bin/bamf && chmod +x /usr/local/bin/bamf
```

The CLI stores credentials in `~/.bamf/` — these persist across updates.
