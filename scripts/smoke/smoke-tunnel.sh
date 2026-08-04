#!/usr/bin/env bash
# Smoke: the data-path tunnel actually carries bytes end-to-end.
#
# smoke-cert-issue.sh proves a session certificate is issued (the authorization
# path). This proves the *byte path*: open a `bamf tcp` tunnel to an SSH resource
# and read the SSH protocol banner off the local listener. An SSH server sends
# "SSH-2.0-…" the instant a TCP connection lands, so receiving it can only mean
# real bytes traversed CLI → bridge → agent → sshd.
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

# --- Open the tunnel in the background ---
info "Opening 'bamf tcp $RESOURCE' on 127.0.0.1:$LOCAL_PORT"
tcp_log="$(mktemp)"
HOME="$bamf_home" BAMF_API_URL="$BAMF_SMOKE_URL" \
  "$BAMF_BIN" tcp "$RESOURCE" -p "$LOCAL_PORT" >"$tcp_log" 2>&1 &
tcp_pid=$!
cleanup() { kill "$tcp_pid" 2>/dev/null || true; }
trap cleanup EXIT

# Wait for the listener (or a fast failure).
up=0
for _ in $(seq 1 40); do
  kill -0 "$tcp_pid" 2>/dev/null || fail "tunnel exited early:"$'\n'"$(cat "$tcp_log")"
  if (exec 3<>"/dev/tcp/127.0.0.1/$LOCAL_PORT") 2>/dev/null; then up=1; break; fi
  sleep 0.5
done
[ "$up" = 1 ] || fail "tunnel listener never came up:"$'\n'"$(cat "$tcp_log")"
pass "tunnel listener up on 127.0.0.1:$LOCAL_PORT"

# --- Read the SSH banner through the tunnel ---
# Each connection to the local listener triggers a fresh CLI → bridge → agent →
# sshd dial, so retry: the agent's relay may still be settling, and a transient
# hiccup on any hop yields an empty read rather than a wrong one.
info "Reading the SSH protocol banner through the tunnel"
banner=""
for _ in $(seq 1 20); do
  banner="$(timeout 8 bash -c "exec 3<>/dev/tcp/127.0.0.1/$LOCAL_PORT; head -c 32 <&3" 2>/dev/null || true)"
  banner="${banner%%$'\r'*}"
  case "$banner" in SSH-2.0-*|SSH-1.*) break ;; esac
  sleep 2
done
case "$banner" in
  SSH-2.0-*|SSH-1.*) pass "tunnel carried bytes end-to-end: $banner" ;;
  *) fail "no SSH banner through the tunnel (got: '$banner')"$'\n'"tunnel log: $(cat "$tcp_log")" ;;
esac

echo
echo "${GREEN}Data-path tunnel smoke passed.${NC}"
