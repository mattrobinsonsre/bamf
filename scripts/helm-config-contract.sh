#!/usr/bin/env bash
# helm-config-contract: enforce the AGENTS.md hard rule "secrets flow via
# secretKeyRef / existingSecret, never into a ConfigMap." Renders every
# documented topology and fails if any ConfigMap data value contains a
# secret-looking assignment (password/token/secret/key = <literal>).
#
# Uses helm via Docker (no local helm needed) + python3 (present on CI runners).
set -euo pipefail
cd "$(dirname "$0")/.."

HELM=(docker run --rm -v "$PWD:/chart" -w /chart alpine/helm:3.17.2)
AGENT="agent.enabled=true,agent.joinToken=dummy,agent.config.name=ci-agent"
TOPOLOGIES=(
  "core.enabled=true,edge.enabled=true,agent.enabled=false"
  "core.enabled=false,edge.enabled=true,agent.enabled=false"
  "core.enabled=false,edge.enabled=false,$AGENT"
  "core.enabled=true,edge.enabled=true,$AGENT"
)

rc=0
for sets in "${TOPOLOGIES[@]}"; do
  if ! "${HELM[@]}" template helm/bamf --set "$sets" \
      | python3 scripts/lib/scan_configmap_secrets.py; then
    echo "  ^ topology: $sets"
    rc=1
  fi
done

if [ "$rc" -eq 0 ]; then
  echo "helm-config-contract: no secret values in any ConfigMap"
fi
exit "$rc"
