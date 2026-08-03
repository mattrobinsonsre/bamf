#!/usr/bin/env bash
# Smoke: session revocation is immediate.
#
# BAMF uses opaque server-side (Redis) sessions specifically so access can be
# revoked instantly — not self-contained JWTs that stay valid until expiry. The
# gate before external users must prove that property holds on the live stack:
# a token works, then after POST /auth/logout the SAME token is refused (401).
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=scripts/smoke/lib.sh
source ./lib.sh
guard_local

info "Login"
token="$(smoke_login)" || fail "login failed"
pass "session issued"

info "Token works before logout (GET /auth/sessions)"
code="$(status GET "$API/auth/sessions" -H "Authorization: Bearer $token")"
[ "$code" = "200" ] || fail "authenticated GET returned HTTP $code before logout (expected 200)"
pass "token accepted (HTTP 200)"

info "Revoke the session (POST /auth/logout)"
req -X POST "$API/auth/logout" -H "Authorization: Bearer $token" >/dev/null || fail "logout failed"
pass "logout accepted"

info "The SAME token is now refused (immediate revocation)"
code="$(status GET "$API/auth/sessions" -H "Authorization: Bearer $token")"
[ "$code" = "401" ] || fail "revoked token returned HTTP $code (expected 401 — revocation not immediate!)"
pass "revoked token rejected (HTTP 401)"

echo "${GREEN}Session-revocation smoke passed.${NC}"
