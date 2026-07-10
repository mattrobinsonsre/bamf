#!/usr/bin/env bash
# Smoke: certificate issuance + tunnel authorization (the high-blast-radius path).
#
# Drives POST /connect for a real resource and asserts the API returns a
# BAMF-CA-issued session certificate whose SAN URIs encode the authorization
# decision (session / resource / bridge). This exercises the CA, RBAC, and
# bridge assignment end-to-end — the session cert IS the authorization, so a
# valid one proves the whole issuance path works on the live stack.
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=scripts/smoke/lib.sh
source ./lib.sh
guard_local

RESOURCE="${1:-${RESOURCE:-}}"
if [ -z "$RESOURCE" ]; then
  RESOURCE="$(./seed-fixture.sh | sed -n 's/^RESOURCE=//p' | tail -1)"
fi
[ -n "$RESOURCE" ] || fail "no resource to connect to"

info "Login"
token="$(smoke_login)" || fail "login failed"
pass "session issued"

info "Connect to '$RESOURCE' (issues a session certificate)"
resp="$(req -X POST "$API/connect" \
  -H "Authorization: Bearer $token" \
  -H 'Content-Type: application/json' \
  -d "$(printf '{"resource_name":"%s"}' "$RESOURCE")")" || fail "POST /connect failed for '$RESOURCE'"

bridge="$(printf '%s' "$resp" | sed -n 's/.*"bridge_hostname"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
[ -n "$bridge" ] || fail "no bridge_hostname in connect response ($resp)"
pass "bridge assigned: $bridge"

# Extract the PEM session cert (JSON-escaped \n) and verify its SAN URIs.
cert="$(printf '%s' "$resp" \
  | sed -n 's/.*"session_cert"[[:space:]]*:[[:space:]]*"\(-----BEGIN[^"]*\)".*/\1/p' \
  | sed 's/\\n/\n/g')"
[ -n "$cert" ] || fail "no session_cert in connect response"

sans="$(printf '%s' "$cert" | openssl x509 -noout -text 2>/dev/null | grep -A1 'Subject Alternative Name' | tr ',' '\n')"
printf '%s' "$sans" | grep -q 'bamf://session/'  || fail "session cert missing bamf://session SAN"
printf '%s' "$sans" | grep -q "bamf://resource/$RESOURCE" || fail "session cert missing bamf://resource/$RESOURCE SAN"
printf '%s' "$sans" | grep -q 'bamf://bridge/'   || fail "session cert missing bamf://bridge SAN"
pass "session cert issued with authorization SANs (session, resource=$RESOURCE, bridge)"

info "Certificate-issuance + tunnel-authorization smoke passed"
