#!/usr/bin/env bash
# Smoke: assert the stack is up and has an agent-provided resource to target.
# Prints the name of a usable resource on stdout (consumed by smoke-tunnel.sh).
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=scripts/smoke/lib.sh
source ./lib.sh
guard_local

info "Health / readiness"
req "$BAMF_SMOKE_URL/health" >/dev/null || fail "/health unreachable at $BAMF_SMOKE_URL"
req "$BAMF_SMOKE_URL/ready"  >/dev/null || fail "/ready not ready"
pass "API healthy and ready"

info "Login (local admin, PKCE)"
token="$(smoke_login)" || fail "login flow failed"
pass "session issued (${#token}-char token)"

info "Resource catalogue (agent-provided)"
resources_json="$(req "$API/resources" -H "Authorization: Bearer $token")" || fail "GET /resources failed"
name="$(printf '%s' "$resources_json" | sed -n 's/.*"name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)"
[ -n "$name" ] || fail "no resources registered — is an agent online? ($resources_json)"
pass "found resource: $name"

# Emit the resource name for the tunnel smoke (last line = machine-readable).
printf 'RESOURCE=%s\n' "$name"
