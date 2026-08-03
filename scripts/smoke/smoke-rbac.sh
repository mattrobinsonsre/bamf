#!/usr/bin/env bash
# Smoke: RBAC negative path — a non-admin session must be DENIED admin-only
# surface while still being a valid authenticated session.
#
# Reject-by-default is BAMF's core security posture (AGENTS.md #7), so the gate
# before external users must prove denial, not just that the happy path works.
# This creates a throwaway non-admin local user, logs in as them, asserts they
# can reach a normal authenticated endpoint (200) but are refused an admin-only
# one (403), then deletes the user.
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=scripts/smoke/lib.sh
source ./lib.sh
guard_local

NONADMIN_EMAIL="${SMOKE_NONADMIN_EMAIL:-smoke-nonadmin@example.com}"
NONADMIN_PW="${SMOKE_NONADMIN_PW:-Smoke-NonAdmin-Pw-9271}"

info "Admin login"
admin="$(smoke_login)" || fail "admin login failed"
pass "admin session issued"

info "Create throwaway non-admin user ($NONADMIN_EMAIL, no roles)"
# Idempotent: tolerate 409 if a previous run left the user behind.
code="$(status POST "$API/users" -H "Authorization: Bearer $admin" \
  -H 'Content-Type: application/json' \
  -d "$(printf '{"email":"%s","password":"%s","roles":[]}' "$NONADMIN_EMAIL" "$NONADMIN_PW")")"
case "$code" in
  201|409) pass "non-admin user present (HTTP $code)" ;;
  *) fail "create non-admin user returned HTTP $code (expected 201/409)" ;;
esac

# Always clean up the throwaway user, even if an assertion below fails.
cleanup_user() {
  status DELETE "$API/users/$NONADMIN_EMAIL" -H "Authorization: Bearer $admin" >/dev/null 2>&1 || true
}
trap cleanup_user EXIT

info "Log in as the non-admin"
nonadmin="$(smoke_login "$NONADMIN_EMAIL" "$NONADMIN_PW")" || fail "non-admin login failed"
pass "non-admin session issued"

info "Non-admin CAN reach a normal authenticated endpoint (GET /resources)"
code="$(status GET "$API/resources" -H "Authorization: Bearer $nonadmin")"
[ "$code" = "200" ] || fail "non-admin GET /resources returned HTTP $code (expected 200)"
pass "authenticated access allowed (HTTP 200)"

info "Non-admin is DENIED an admin-only endpoint (GET /users/recent)"
code="$(status GET "$API/users/recent" -H "Authorization: Bearer $nonadmin")"
[ "$code" = "403" ] || fail "non-admin GET /users/recent returned HTTP $code (expected 403 — RBAC not enforcing!)"
pass "admin-only surface denied (HTTP 403)"

info "Non-admin is DENIED a state-changing admin endpoint (POST /users)"
code="$(status POST "$API/users" -H "Authorization: Bearer $nonadmin" \
  -H 'Content-Type: application/json' \
  -d '{"email":"smoke-should-not-exist@example.com","password":"Smoke-Nope-Pw-1234","roles":["admin"]}')"
[ "$code" = "403" ] || fail "non-admin POST /users returned HTTP $code (expected 403 — privilege escalation!)"
pass "admin-only mutation denied (HTTP 403)"

echo "${GREEN}RBAC negative-path smoke passed.${NC}"
