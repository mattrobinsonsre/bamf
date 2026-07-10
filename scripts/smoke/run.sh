#!/usr/bin/env bash
# Run the full BAMF live smoke suite against a running stack.
# Backs AGENTS.md release gate F. Usage: scripts/smoke/run.sh  (or: make smoke)
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=scripts/smoke/lib.sh
source ./lib.sh
guard_local

echo "BAMF smoke — target: $BAMF_SMOKE_URL"
echo

res="$(./seed-fixture.sh)"
echo "$res"
resource="$(printf '%s' "$res" | sed -n 's/^RESOURCE=//p' | tail -1)"
echo

RESOURCE="$resource" ./smoke-cert-issue.sh
echo
echo "${GREEN}All smoke checks passed.${NC}"
