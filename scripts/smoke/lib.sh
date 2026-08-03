#!/usr/bin/env bash
# Shared helpers for the BAMF live smoke harness.
#
# The smoke harness backs AGENTS.md release gate F ("live smoke for destructive /
# high-blast-radius surfaces … end-to-end"): it drives real authentication,
# certificate issuance, and tunnel authorization against a running stack, rather
# than trusting unit tests. It talks only to the public HTTP API, so it is
# stack-agnostic (local Tilt/k3d or a remote deployment) — point it with
# BAMF_SMOKE_URL.
#
# Env:
#   BAMF_SMOKE_URL       Base URL of the stack        (default https://bamf.local)
#   BAMF_SMOKE_EMAIL     Local admin email            (default admin)
#   BAMF_SMOKE_PASSWORD  Local admin password         (default admin)
#   BAMF_SMOKE_INSECURE  curl -k for self-signed TLS  (default 1 — mkcert/dev)

set -euo pipefail

BAMF_SMOKE_URL="${BAMF_SMOKE_URL:-https://bamf.local}"
BAMF_SMOKE_EMAIL="${BAMF_SMOKE_EMAIL:-admin}"
BAMF_SMOKE_PASSWORD="${BAMF_SMOKE_PASSWORD:-admin}"
BAMF_SMOKE_INSECURE="${BAMF_SMOKE_INSECURE:-1}"

API="${BAMF_SMOKE_URL%/}/api/v1"

# --retry makes curl transparently retry the ingress rate-limit (429) and 5xx
# with backoff (honoring Retry-After) — the smoke does a burst of logins and the
# gateway rate-limits auth. curl's --retry set is 408/429/500/502/503/504 only,
# so a negative-path 401/403 is NOT retried (the status helper still sees it).
_retry=(--retry 6 --retry-delay 1 --retry-max-time 45 --retry-connrefused)
_curl_opts=(--fail-with-body -sS --max-time 20 "${_retry[@]}")
[ "$BAMF_SMOKE_INSECURE" = "1" ] && _curl_opts+=(-k)
# Same, but WITHOUT --fail-with-body, for asserting on non-2xx status codes.
_curl_status_opts=(-sS --max-time 20 "${_retry[@]}" -o /dev/null -w '%{http_code}')
[ "$BAMF_SMOKE_INSECURE" = "1" ] && _curl_status_opts+=(-k)

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; NC=$'\033[0m'
info()  { echo "${YELLOW}==>${NC} $*"; }
pass()  { echo "${GREEN}  ✓${NC} $*"; }
fail()  { echo "${RED}  ✗ $*${NC}" >&2; exit 1; }

req() { curl "${_curl_opts[@]}" "$@"; }

# status <method> <url> [curl args...] — echo the HTTP status code, never fail.
# Use for negative-path assertions (a non-admin must get 403, a revoked token 401).
status() { local m="$1" u="$2"; shift 2; curl "${_curl_status_opts[@]}" -X "$m" "$u" "$@"; }

# base64url without padding.
_b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

# pkce_verifier / pkce_challenge — RFC 7636 S256.
pkce_verifier()  { openssl rand -hex 32; }              # 64 unreserved chars
pkce_challenge() { printf '%s' "$1" | openssl dgst -binary -sha256 | _b64url; }

# smoke_login [email] [password] — drive the scriptable local PKCE flow and echo
# a session token. Defaults to the admin creds; pass args to log in as another
# user (used by the RBAC negative-path smoke).
# POST /auth/local/authorize (JSON creds + PKCE) -> code -> POST /auth/token.
smoke_login() {
  local email="${1:-$BAMF_SMOKE_EMAIL}" password="${2:-$BAMF_SMOKE_PASSWORD}"
  local verifier challenge code token
  verifier="$(pkce_verifier)"
  challenge="$(pkce_challenge "$verifier")"

  code="$(req -X POST "$API/auth/local/authorize" \
    -H 'Content-Type: application/json' \
    -d "$(printf '{"email":"%s","password":"%s","code_challenge":"%s","code_challenge_method":"S256","state":"smoke"}' \
          "$email" "$password" "$challenge")" \
    | sed -n 's/.*"code"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  [ -n "$code" ] || return 1

  token="$(req -X POST "$API/auth/token" \
    -H 'Content-Type: application/x-www-form-urlencoded' \
    --data-urlencode 'grant_type=authorization_code' \
    --data-urlencode "code=$code" \
    --data-urlencode "code_verifier=$verifier" \
    | sed -n 's/.*"session_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  [ -n "$token" ] || return 1
  printf '%s' "$token"
}

# guard_local — refuse to run against something that looks like production unless
# BAMF_SMOKE_FORCE=1. The smoke creates real (short-lived) sessions and certs.
guard_local() {
  case "$BAMF_SMOKE_URL" in
    *bamf.local*|*localhost*|*127.0.0.1*|*.svc*|*:8000*) return 0 ;;
  esac
  if [ "${BAMF_SMOKE_FORCE:-0}" != "1" ]; then
    fail "BAMF_SMOKE_URL='$BAMF_SMOKE_URL' doesn't look local. Set BAMF_SMOKE_FORCE=1 to run against it anyway."
  fi
}
