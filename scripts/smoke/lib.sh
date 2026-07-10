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

_curl_opts=(--fail-with-body -sS --max-time 20)
[ "$BAMF_SMOKE_INSECURE" = "1" ] && _curl_opts+=(-k)

RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[1;33m'; NC=$'\033[0m'
info()  { echo "${YELLOW}==>${NC} $*"; }
pass()  { echo "${GREEN}  ✓${NC} $*"; }
fail()  { echo "${RED}  ✗ $*${NC}" >&2; exit 1; }

req() { curl "${_curl_opts[@]}" "$@"; }

# base64url without padding.
_b64url() { openssl base64 -A | tr '+/' '-_' | tr -d '='; }

# pkce_verifier / pkce_challenge — RFC 7636 S256.
pkce_verifier()  { openssl rand -hex 32; }              # 64 unreserved chars
pkce_challenge() { printf '%s' "$1" | openssl dgst -binary -sha256 | _b64url; }

# smoke_login — drive the scriptable local PKCE flow and echo a session token.
# POST /auth/local/authorize (JSON creds + PKCE) -> code -> POST /auth/token.
smoke_login() {
  local verifier challenge code token
  verifier="$(pkce_verifier)"
  challenge="$(pkce_challenge "$verifier")"

  code="$(req -X POST "$API/auth/local/authorize" \
    -H 'Content-Type: application/json' \
    -d "$(printf '{"email":"%s","password":"%s","code_challenge":"%s","code_challenge_method":"S256","state":"smoke"}' \
          "$BAMF_SMOKE_EMAIL" "$BAMF_SMOKE_PASSWORD" "$challenge")" \
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
