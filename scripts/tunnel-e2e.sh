#!/usr/bin/env bash
# Tunnel E2E — boot a FULL BAMF stack on k3d and prove a tunnel carries bytes
# end-to-end. Runnable locally (`make test-tunnel-e2e`) and in its own CI job.
#
# This is deliberately separate from the fast, core-only web E2E (scripts/e2e.sh):
# it's heavier (edge bridge/proxy + a demo agent + an SSH fixture, every image
# built from the current tree) and slower, so it doesn't weigh down the web gate.
# It installs the chart (values-eval), then runs `bamf tcp test-ssh` and asserts
# the SSH banner comes back — CLI → bridge → agent → sshd. sslip.io wildcard DNS
# resolves the bridge SNI hostname and bridge_port tracks gateway.ports.https, so
# the host-side CLI reaches the bridge on the k3d-mapped port.
#
# Env: E2E_HTTPS_PORT (default 443), E2E_IP (127.0.0.1), E2E_IMAGE_TAG (e2e),
#      E2E_TUNNEL_PORT (local listener, default 45899), E2E_KEEP=1 to skip teardown.
set -euo pipefail

CLUSTER="${E2E_CLUSTER:-bamf-tunnel-e2e}"
KCTX="k3d-${CLUSTER}"     # explicit context — never switch the user's global one
NS=bamf
IP="${E2E_IP:-127.0.0.1}"
HTTPS_PORT="${E2E_HTTPS_PORT:-443}"
TAG="${E2E_IMAGE_TAG:-e2e}"
TLS_SECRET=bamf-e2e-tls
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
HOST="bamf.${IP}.sslip.io"
TUNNEL_DOMAIN="${IP}.sslip.io"
PORT_SUFFIX=""; [ "$HTTPS_PORT" != "443" ] && PORT_SUFFIX=":${HTTPS_PORT}"
BASE_URL="https://${HOST}${PORT_SUFFIX}"

Y=$'\033[1;33m'; NC=$'\033[0m'
step() { echo "${Y}==>${NC} $*"; }

on_exit() {
  local rc=$?
  if [ "$rc" -ne 0 ]; then
    echo "${Y}==> E2E failed (rc=$rc) — cluster diagnostics:${NC}"
    kubectl --context "$KCTX" -n "$NS" get pods,events 2>/dev/null || true
    kubectl --context "$KCTX" -n "$NS" describe pods 2>/dev/null | tail -80 || true
    kubectl --context "$KCTX" -n "$NS" logs -l app.kubernetes.io/instance=bamf \
      --tail=60 --all-containers --prefix 2>/dev/null || true
  fi
  [ "${E2E_KEEP:-0}" = "1" ] || k3d cluster delete "$CLUSTER" >/dev/null 2>&1 || true
}
trap on_exit EXIT

step "Building API + Web + Bridge + Agent images from the current tree (tag: $TAG)"
docker build -q -f "$REPO_ROOT/docker/Dockerfile.api" -t "bamf-api:$TAG" "$REPO_ROOT" >/dev/null
docker build -q -f "$REPO_ROOT/docker/Dockerfile.web" -t "bamf-web:$TAG" "$REPO_ROOT" >/dev/null
docker build -q -f "$REPO_ROOT/docker/Dockerfile.bridge" -t "bamf-bridge:$TAG" "$REPO_ROOT" >/dev/null
docker build -q -f "$REPO_ROOT/docker/Dockerfile.agent" -t "bamf-agent:$TAG" "$REPO_ROOT" >/dev/null
docker build -q -f "$REPO_ROOT/docker/Dockerfile.proxy" -t "bamf-proxy:$TAG" "$REPO_ROOT" >/dev/null

step "Creating k3d cluster '$CLUSTER' (host :$HTTPS_PORT → 443)"
k3d cluster create "$CLUSTER" \
  --port "${HTTPS_PORT}:443@loadbalancer" \
  --kubeconfig-switch-context=false --wait
# k3d image import can report success but leave the image unresolvable by the
# kubelet (ErrImageNeverPull, #976) — flaky, and worse the more images there are.
# Import, then VERIFY each is in the node's containerd; re-import any that aren't.
import_images() {
  local node="k3d-${CLUSTER}-server-0" img missing attempt
  k3d image import -c "$CLUSTER" "$@" >/dev/null 2>&1 || true
  for attempt in 1 2 3 4; do
    missing=()
    for img in "$@"; do
      docker exec "$node" crictl images 2>/dev/null \
        | grep -qE "(^|/)${img%%:*}[[:space:]]+${img##*:}[[:space:]]" || missing+=("$img")
    done
    [ "${#missing[@]}" -eq 0 ] && return 0
    echo "images not yet resolvable (attempt $attempt): ${missing[*]} — re-importing"
    k3d image import -c "$CLUSTER" "${missing[@]}" >/dev/null 2>&1 || true
    sleep 3
  done
  echo "images still missing after retries: ${missing[*]}"; return 1
}
import_images "bamf-api:$TAG" "bamf-web:$TAG" "bamf-bridge:$TAG" "bamf-agent:$TAG" "bamf-proxy:$TAG"
kubectl --context "$KCTX" create namespace "$NS" --dry-run=client -o yaml | kubectl --context "$KCTX" apply -f - >/dev/null

# SSH fixture — the data-path tunnel smoke connects to this through the tunnel.
# linuxserver/openssh-server speaks the SSH banner immediately on TCP connect, so
# reading "SSH-2.0-…" off a `bamf tcp` listener proves the full byte path works.
step "Deploying the SSH test fixture"
kubectl --context "$KCTX" apply -f - >/dev/null <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata: { name: bamf-test-ssh, namespace: bamf }
spec:
  replicas: 1
  selector: { matchLabels: { app: bamf-test-ssh } }
  template:
    metadata: { labels: { app: bamf-test-ssh } }
    spec:
      containers:
        - name: sshd
          image: linuxserver/openssh-server:latest
          env:
            - { name: PUID, value: "1000" }
            - { name: PGID, value: "1000" }
            - { name: PASSWORD_ACCESS, value: "true" }
            - { name: USER_NAME, value: "testuser" }
            - { name: USER_PASSWORD, value: "testpass" }
          ports: [ { containerPort: 2222 } ]
---
apiVersion: v1
kind: Service
metadata: { name: bamf-test-ssh, namespace: bamf }
spec:
  selector: { app: bamf-test-ssh }
  ports: [ { port: 22, targetPort: 2222 } ]
YAML

# k3d reconciles its bundled Traefik asynchronously (k3s helm-controller) AFTER
# `k3d cluster create --wait` returns, so the Traefik Deployment AND its CRDs may
# not exist yet. A ready Deployment does not imply the traefik.io/v1alpha1 CRDs
# are Established — and the BAMF chart renders a Middleware + IngressRoute(TCP).
# Wait for the CRDs to exist and be Established before `helm install`, or the
# install races ahead of them: "no matches for kind Middleware in
# traefik.io/v1alpha1". No `|| true` here — a real timeout must fail the run.
step "Waiting for Traefik CRDs + deployment (k3d installs Traefik async)"
# Poll each CRD's Established condition via jsonpath rather than
# `kubectl wait --for=condition=established`: that command errors out
# (".status.conditions accessor error: <nil> is of the type <nil>") if it runs
# in the brief window after the CRD exists but before its status.conditions is
# populated. The jsonpath is empty while the CRD is absent OR conditionless, so
# the loop just keeps waiting until it flips to True.
for crd in middlewares.traefik.io ingressroutes.traefik.io ingressroutetcps.traefik.io; do
  deadline=$((SECONDS + 120))
  until [ "$(kubectl --context "$KCTX" get crd "$crd" \
      -o jsonpath='{.status.conditions[?(@.type=="Established")].status}' 2>/dev/null)" = "True" ]; do
    [ "$SECONDS" -ge "$deadline" ] && { echo "timed out waiting for CRD $crd to be Established"; exit 1; }
    sleep 2
  done
done
# The traefik Deployment is created by a separate HelmChart CR *after* the CRDs,
# so it may not exist yet — `rollout status` errors ("deployments.apps traefik
# not found") on a missing deployment instead of waiting. Wait for it to appear,
# then wait for the rollout.
deadline=$((SECONDS + 120))
until kubectl --context "$KCTX" -n kube-system get deploy/traefik >/dev/null 2>&1; do
  [ "$SECONDS" -ge "$deadline" ] && { echo "timed out waiting for the traefik deployment to appear"; exit 1; }
  sleep 2
done
kubectl --context "$KCTX" -n kube-system rollout status deploy/traefik --timeout=150s

step "Self-signed TLS for ${HOST}"
tlsdir="$(mktemp -d)"
CERT_FILE="$tlsdir/tls.crt"   # kept so the bamf CLI can trust it via SSL_CERT_FILE
openssl req -x509 -newkey rsa:2048 -nodes -days 7 \
  -keyout "$tlsdir/tls.key" -out "$CERT_FILE" \
  -subj "/CN=${HOST}" -addext "subjectAltName=DNS:${HOST},DNS:*.tunnel.${TUNNEL_DOMAIN},DNS:*.bridge.local.tunnel.${TUNNEL_DOMAIN}" 2>/dev/null
kubectl --context "$KCTX" -n "$NS" create secret tls "$TLS_SECRET" \
  --cert="$CERT_FILE" --key="$tlsdir/tls.key" --dry-run=client -o yaml \
  | kubectl --context "$KCTX" apply -f - >/dev/null

step "Installing BAMF (full stack: core + edge + agent) from the local chart"
# values-eval already enables edge + agent and seeds the agent join token; point
# the agent at the SSH fixture (replacing the eval demo resource) so the data-path
# smoke has a byte target.
helm --kube-context "$KCTX" upgrade --install bamf "$REPO_ROOT/helm/bamf" -n "$NS" \
  -f "$REPO_ROOT/helm/bamf/values-eval.yaml" \
  --set gateway.hostname="$HOST" --set gateway.tunnelDomain="$TUNNEL_DOMAIN" \
  --set gateway.ports.https="$HTTPS_PORT" --set tls.existingSecret="$TLS_SECRET" \
  --set core.api.image.repository=bamf-api --set core.api.image.tag="$TAG" --set core.api.image.pullPolicy=Never \
  --set core.web.image.repository=bamf-web --set core.web.image.tag="$TAG" --set core.web.image.pullPolicy=Never \
  --set edge.bridge.image.repository=bamf-bridge --set edge.bridge.image.tag="$TAG" --set edge.bridge.image.pullPolicy=Never \
  --set edge.proxy.image.repository=bamf-proxy --set edge.proxy.image.tag="$TAG" --set edge.proxy.image.pullPolicy=Never \
  --set agent.image.repository=bamf-agent --set agent.image.tag="$TAG" --set agent.image.pullPolicy=Never \
  --set-json 'agent.config.resources=[{"name":"test-ssh","type":"ssh","hostname":"bamf-test-ssh.bamf.svc.cluster.local","port":22,"labels":{"env":"e2e"}}]' \
  --timeout 300s

step "Waiting for API + Web + Bridge + Agent"
kubectl --context "$KCTX" -n "$NS" rollout status deploy/bamf-api --timeout=240s
kubectl --context "$KCTX" -n "$NS" rollout status deploy/bamf-web --timeout=240s
kubectl --context "$KCTX" -n "$NS" rollout status statefulset/bamf-bridge --timeout=240s
kubectl --context "$KCTX" -n "$NS" rollout status deploy/bamf-agent --timeout=240s
kubectl --context "$KCTX" -n "$NS" rollout status deploy/bamf-test-ssh --timeout=180s

step "Pre-warming the API readiness path"
for _ in 1 2 3; do curl -ksS -o /dev/null "${BASE_URL}/ready" || true; sleep 2; done

# ── Data-path tunnel smoke ──────────────────────────────────────────────────
# The whole point of this job: prove a tunnel actually carries bytes end-to-end
# (CLI → bridge → agent → sshd). The bridge SNI hostname
# (0.bridge.local.<IP>.sslip.io) resolves via sslip.io, and bridge_port tracks
# gateway.ports.https, so the host-side CLI reaches it on the mapped port.
cd "$REPO_ROOT"
export BAMF_SMOKE_URL="$BASE_URL"
# shellcheck source=scripts/smoke/lib.sh
source scripts/smoke/lib.sh

step "Waiting for the agent to register the SSH resource"
registered=0
for _ in $(seq 1 60); do
  tok="$(smoke_login 2>/dev/null)" || { sleep 2; continue; }
  if req "$API/resources" -H "Authorization: Bearer $tok" 2>/dev/null | grep -q '"test-ssh"'; then
    registered=1; break
  fi
  sleep 2
done
[ "$registered" = 1 ] || { echo "agent never registered test-ssh"; exit 1; }
pass "agent registered test-ssh"

step "Data-path tunnel smoke (SSH banner through the tunnel)"
# The CLI's Go HTTPS calls to the API must trust the self-signed cert → SSL_CERT_FILE.
SSL_CERT_FILE="$CERT_FILE" SMOKE_TUNNEL_PORT="${E2E_TUNNEL_PORT:-45899}" \
  scripts/smoke/smoke-tunnel.sh
