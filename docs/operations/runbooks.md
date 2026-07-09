# Operational Runbooks

Per-condition response playbooks. Each follows **Symptoms → Diagnosis →
Resolution → Verification**. Commands assume `kubectl` is pointed at the BAMF
cluster and the release is named `bamf` in namespace `bamf`.

For historical logs of pods that have already restarted or been evicted, query
your log aggregator rather than `kubectl logs` — pod logs are ephemeral.

## Bridge pod OOM-killed or restarting

### Symptoms
Active tunnels stall for 1–2s then recover; `kubectl get pods` shows a
`bamf-bridge-N` with a recent restart or `OOMKilled` last state.

### Diagnosis
```sh
kubectl -n bamf describe pod bamf-bridge-0 | grep -A3 "Last State"
kubectl -n bamf top pod -l app.kubernetes.io/component=bridge
```
`ssh-audit` sessions hold SSH state in the bridge and cannot survive a crash;
plain `ssh`/DB tunnels use the reliable stream and reconnect automatically.

### Resolution
Raise `edge.bridge.resources.limits.memory` and roll the StatefulSet. If OOM
is driven by session count, lower `targetTunnelsPerPod` (or
`nonMigratableOversubscribeFactor` for `ssh-audit`-heavy fleets) so the HPA
scales out sooner.

### Verification
`bamf_bridge_*` memory metrics settle below the limit; no further `OOMKilled`
events; a test tunnel survives a `kubectl delete pod bamf-bridge-0`.

## Bridge draining for scale-in / maintenance

### Symptoms
A bridge is being removed (scale-in, node drain, spot warning) and you want
zero-disruption handoff.

### Diagnosis
```sh
kubectl -n bamf get pods -l app.kubernetes.io/component=bridge
```

### Resolution
On SIGTERM the bridge notifies the API to drain and migrates active tunnels to
other bridges before exiting (within `terminationGracePeriodSeconds`). Don't
`--force` delete — that skips the drain. If a drain hangs, confirm other
bridges have capacity (HPA `minReplicas` > 1) before the grace period expires.

### Verification
Sessions on the drained bridge migrated (no client disconnects); the pod exited
0; `bridges:available` in Redis no longer lists it.

## Agent shows offline

### Symptoms
A resource disappears from `bamf ls`; the Agents page shows the agent offline.

### Diagnosis
An agent is marked offline after 3 missed 60s heartbeats. Check:
```sh
kubectl -n <agent-ns> logs deploy/bamf-agent --tail=100
```
Look for API-connectivity errors (agent → API over HTTPS) or an expired agent
certificate.

### Resolution
- **Network**: confirm the agent can reach `platformUrl` (public HTTPS). Agent
  SSE reconnect uses exponential backoff (1s → 5m).
- **Cert expired**: agent certs last 1 year and auto-renew before expiry; if it
  lapsed, re-deploy with a valid join token so it re-registers. The cert is
  stored in a K8s Secret (or the data dir on VMs) and survives pod restarts.

### Verification
Agent status flips online; its resources reappear in `bamf ls`; a tunnel to one
of them succeeds.

## Certificate authority expiry approaching

### Symptoms
Monitoring flags the internal CA nearing expiry, or newly issued identity/session
certs fail validation at the bridge.

### Diagnosis
The CA is owned by the API and mirrored into PostgreSQL. Inspect the CA cert via
`GET /api/v1/certificates/ca` (or the `bamf-ca` Secret).

### Resolution
CA rotation is an admin operation — plan it in a maintenance window. After
rotation, agents and CLIs fetch the new CA public cert at their next bootstrap
(inline in join/login responses); long-lived agent certs remain valid until
their own expiry. Because the CA lives in PostgreSQL, a DB backup taken before
rotation is your rollback.

### Verification
New `bamf login` / `bamf ssh` sessions validate against the bridge; existing
agents reconnect without re-registration.

## Redis unavailable

### Symptoms
New tunnel setup fails; the resource catalog empties; browser proxy sessions
fail. Existing spliced tunnels keep flowing (the bridge holds no Redis
dependency mid-tunnel).

### Diagnosis
```sh
kubectl -n bamf logs deploy/bamf-api --tail=100 | grep -i redis
```

### Resolution
Restore Redis connectivity. All Redis state is recoverable: bridges re-register
on heartbeat, agents reconnect and re-publish resources, sessions time out and
users reconnect. No data is lost from Redis loss alone — durable identity and
audit live in PostgreSQL.

### Verification
`bamf ls` repopulates; a new `bamf ssh` succeeds; the Agents/Bridges views
refill.

## API pod CrashLoopBackOff

### Symptoms
`bamf-api` pods restart repeatedly; the platform is unreachable.

### Diagnosis
Investigate before deleting — do not hope a restart fixes it.
```sh
kubectl -n bamf logs deploy/bamf-api --previous --tail=200
kubectl -n bamf describe pod -l app.kubernetes.io/component=api
```
Common causes: bad `DATABASE_URL`/credentials, unreachable PostgreSQL, or a
pending migration.

### Resolution
- **DB connectivity/creds**: fix the Secret/`externalSecret` and roll.
- **Migration mismatch**: ensure the migration job ran `alembic upgrade head`
  for this release (see below).

### Verification
Pods reach `Ready`; `/ready` returns 200 (it checks DB + Redis).

## Migration job failed

### Symptoms
Helm upgrade hangs or the API won't start after a version bump; the migration
job/hook is in `Error`.

### Diagnosis
```sh
kubectl -n bamf logs job/bamf-migrations
```

### Resolution
Fix the underlying DB issue (permissions, connectivity, a conflicting manual
change) and re-run the upgrade. For external PostgreSQL the migration runs as a
pre-install/upgrade hook and must complete before the deployment proceeds. Never
edit `alembic_version` by hand unless you understand exactly which revision the
schema is at.

### Verification
The job completes; `alembic upgrade head` is a no-op on re-run; the API starts
and `/ready` is green.

## Tunnel setup times out

### Symptoms
`bamf ssh <resource>` errors after ~30s with a setup timeout.

### Diagnosis
Tunnel setup fails if the agent doesn't dial the assigned bridge within 30s.
Check the agent is online (`bamf ls`), reachable, and that the SNI hostname
`N.bridge.tunnel.<domain>` resolves and routes to the bridge pod.

### Resolution
- Agent offline → see [Agent shows offline](#agent-shows-offline).
- SNI routing broken → verify the per-pod Service + TLSRoute/IngressRouteTCP for
  that bridge ordinal exist (pre-created up to `maxReplicas`).

### Verification
`bamf ssh` connects; the session start appears in the audit log.
