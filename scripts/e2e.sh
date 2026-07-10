#!/usr/bin/env bash
# Web E2E — boot a minimal core-only BAMF stack on k3d and run the Playwright
# suite (web/e2e) against it. Runnable locally (`make test-e2e`) and in CI.
#
# Core-only (API + Web + Postgres + Redis + bootstrap admin) — no bridge/agent/
# proxy, since the UI E2E only needs login + RBAC-gated pages. Builds the API and
# Web images from the current tree so it tests the branch code, imports them into
# k3d, installs the local chart, and runs Playwright against the sslip.io URL.
#
# Env: E2E_HTTPS_PORT (default 443), E2E_IP (127.0.0.1), E2E_IMAGE_TAG (e2e),
#      E2E_KEEP=1 to skip teardown for debugging.
set -euo pipefail

CLUSTER="${E2E_CLUSTER:-bamf-e2e}"
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

cleanup() { [ "${E2E_KEEP:-0}" = "1" ] || k3d cluster delete "$CLUSTER" >/dev/null 2>&1 || true; }
trap cleanup EXIT

step "Building API + Web images from the current tree (tag: $TAG)"
docker build -q -f "$REPO_ROOT/docker/Dockerfile.api" -t "bamf-api:$TAG" "$REPO_ROOT" >/dev/null
docker build -q -f "$REPO_ROOT/docker/Dockerfile.web" -t "bamf-web:$TAG" "$REPO_ROOT" >/dev/null

step "Creating k3d cluster '$CLUSTER' (host :$HTTPS_PORT → 443)"
k3d cluster create "$CLUSTER" \
  --port "${HTTPS_PORT}:443@loadbalancer" \
  --kubeconfig-switch-context=false --wait
k3d image import -c "$CLUSTER" "bamf-api:$TAG" "bamf-web:$TAG"
kubectl --context "$KCTX" create namespace "$NS" --dry-run=client -o yaml | kubectl --context "$KCTX" apply -f - >/dev/null
kubectl --context "$KCTX" -n kube-system rollout status deploy/traefik --timeout=150s || true

step "Self-signed TLS for ${HOST}"
tlsdir="$(mktemp -d)"
openssl req -x509 -newkey rsa:2048 -nodes -days 7 \
  -keyout "$tlsdir/tls.key" -out "$tlsdir/tls.crt" \
  -subj "/CN=${HOST}" -addext "subjectAltName=DNS:${HOST},DNS:*.tunnel.${TUNNEL_DOMAIN}" 2>/dev/null
kubectl --context "$KCTX" -n "$NS" create secret tls "$TLS_SECRET" \
  --cert="$tlsdir/tls.crt" --key="$tlsdir/tls.key" --dry-run=client -o yaml \
  | kubectl --context "$KCTX" apply -f - >/dev/null
rm -rf "$tlsdir"

step "Installing BAMF (core-only) from the local chart"
helm --kube-context "$KCTX" upgrade --install bamf "$REPO_ROOT/helm/bamf" -n "$NS" \
  -f "$REPO_ROOT/helm/bamf/values-eval.yaml" \
  --set edge.enabled=false --set agent.enabled=false \
  --set gateway.hostname="$HOST" --set gateway.tunnelDomain="$TUNNEL_DOMAIN" \
  --set gateway.ports.https="$HTTPS_PORT" --set tls.existingSecret="$TLS_SECRET" \
  --set core.api.image.repository=bamf-api --set core.api.image.tag="$TAG" --set core.api.image.pullPolicy=Never \
  --set core.web.image.repository=bamf-web --set core.web.image.tag="$TAG" --set core.web.image.pullPolicy=Never \
  --timeout 300s

step "Waiting for API + Web"
kubectl --context "$KCTX" -n "$NS" rollout status deploy/bamf-api --timeout=240s
kubectl --context "$KCTX" -n "$NS" rollout status deploy/bamf-web --timeout=240s

step "Running Playwright against ${BASE_URL}"
cd "$REPO_ROOT/web"
[ -d node_modules ] || npm ci
npx playwright install --with-deps chromium
BAMF_E2E_BASE_URL="$BASE_URL" BAMF_E2E_ADMIN_EMAIL=admin BAMF_E2E_ADMIN_PASSWORD=admin npm run e2e
