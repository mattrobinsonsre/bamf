#!/usr/bin/env bash
# Smoke: the data-path tunnel actually carries bytes end-to-end.
#
# smoke-cert-issue.sh proves a session certificate is issued (the authorization
# path). This proves the *byte path*: open a `bamf tcp` tunnel to an SSH resource,
# send an SSH client identification string, and read the server's back. The agent
# dials the target lazily — only on the first client byte through the tunnel (so
# `bamf tcp` doesn't start the target's auth timeout before a client connects) —
# so we must send first, exactly as a real ssh client does. Getting "SSH-2.0-…"
# back can only mean real bytes traversed CLI → bridge → agent → sshd and back.
#
# Unlike the API-only `make smoke`, this needs the full stack (bridge + agent +
# the ssh test fixture) and the bamf CLI — so it's a separate `make smoke-tunnel`
# tier. Set BAMF_CLI to a prebuilt binary to skip the build.
set -euo pipefail
cd "$(dirname "$0")"
# shellcheck source=scripts/smoke/lib.sh
source ./lib.sh
guard_local

REPO_ROOT="$(cd ../.. && pwd)"
RESOURCE="${SMOKE_TUNNEL_RESOURCE:-test-ssh}"
LOCAL_PORT="${SMOKE_TUNNEL_PORT:-45872}"

echo "BAMF tunnel smoke — resource: $RESOURCE, target: $BAMF_SMOKE_URL"
echo

# --- Locate or build the bamf CLI ---
if [ -n "${BAMF_CLI:-}" ]; then
  BAMF_BIN="$BAMF_CLI"
else
  command -v go >/dev/null || fail "go not found — build the CLI and set BAMF_CLI, or install Go"
  info "Building the bamf CLI"
  BAMF_BIN="$(mktemp -d)/bamf"
  (cd "$REPO_ROOT" && CGO_ENABLED=0 go build -o "$BAMF_BIN" ./cmd/bamf) || fail "go build ./cmd/bamf failed"
fi
pass "bamf CLI ready ($BAMF_BIN)"

# --- Headless auth into an isolated BAMF home (never touches the real ~/.bamf) ---
info "Login (headless)"
token="$(smoke_login)" || fail "login failed"
bamf_home="$(mktemp -d)"
mkdir -p "$bamf_home/.bamf"
# The CLI checks session_expires_at locally, so stamp a near-future expiry (the
# server-side session is the real authority; this just clears the client check).
expires="$(python3 -c "import datetime as d; print((d.datetime.now(d.timezone.utc)+d.timedelta(hours=1)).strftime('%Y-%m-%dT%H:%M:%SZ'))")"
printf '{"session_token":"%s","api_url":"%s","expires_at":"%s"}\n' \
  "$token" "$BAMF_SMOKE_URL" "$expires" > "$bamf_home/.bamf/credentials.json"
chmod 600 "$bamf_home/.bamf/credentials.json"
pass "session written to an isolated BAMF home"

# --- Exchange SSH banners through the tunnel ---
# `bamf tcp` is one-shot: it establishes the bridge tunnel eagerly, serves
# exactly ONE local connection, then exits. So each attempt must (re)start
# `bamf tcp`, wait for its listener via the "Listening on" log line (NOT by
# opening a probe connection — that would consume the one-and-only connection),
# then make the single connection a real SSH-style exchange: send a client
# identification string first (the agent dials the target lazily on the first
# client byte) and read the server's banner back. Getting "SSH-2.0-…" back
# proves bytes traversed CLI → bridge → agent → sshd and back.
info "Exchanging the SSH protocol banner through the tunnel"
tcp_log="$(mktemp)"
tcp_pid=""
cleanup() { [ -n "$tcp_pid" ] && kill "$tcp_pid" 2>/dev/null || true; }
trap cleanup EXIT

banner=""
for attempt in $(seq 1 12); do
  : >"$tcp_log"
  HOME="$bamf_home" BAMF_API_URL="$BAMF_SMOKE_URL" \
    "$BAMF_BIN" tcp "$RESOURCE" -p "$LOCAL_PORT" >"$tcp_log" 2>&1 &
  tcp_pid=$!

  # Wait for the listener without consuming the single connection: the CLI
  # prints "Listening on …" once the local listener is bound.
  up=0
  for _ in $(seq 1 40); do
    kill -0 "$tcp_pid" 2>/dev/null || break
    grep -q "Listening on" "$tcp_log" 2>/dev/null && { up=1; break; }
    sleep 0.25
  done
  if [ "$up" != 1 ]; then
    kill "$tcp_pid" 2>/dev/null || true
    wait "$tcp_pid" 2>/dev/null || true
    sleep 1
    continue
  fi

  banner="$(timeout 8 bash -c "exec 3<>/dev/tcp/127.0.0.1/$LOCAL_PORT; printf 'SSH-2.0-BAMF-smoke\r\n' >&3; head -c 32 <&3" 2>/dev/null || true)"
  banner="${banner%%$'\r'*}"
  kill "$tcp_pid" 2>/dev/null || true
  wait "$tcp_pid" 2>/dev/null || true
  tcp_pid=""
  case "$banner" in SSH-2.0-*|SSH-1.*) break ;; esac
  sleep 2
done
case "$banner" in
  SSH-2.0-*|SSH-1.*) pass "tunnel carried bytes end-to-end: $banner" ;;
  *) fail "no SSH banner through the tunnel (got: '$banner')"$'\n'"last tunnel log: $(cat "$tcp_log")" ;;
esac

echo
echo "${GREEN}Data-path tunnel smoke passed.${NC}"
