#!/usr/bin/env bash
# Throwaway BAMF evaluation cluster — one command, no domain, no build.
#
#   scripts/eval.sh up      # create a k3d cluster and install BAMF (make eval)
#   scripts/eval.sh down    # delete it                          (make eval-down)
#   scripts/eval.sh up --local-build   # install the local chart instead of OCI
#
# Uses k3d (k3s-in-docker, ships Traefik v3 which BAMF needs for SNI passthrough)
# and sslip.io wildcard DNS, so the *.tunnel.* hostnames resolve without a real
# domain or /etc/hosts edits. NOT for production.
#
# Env overrides: EVAL_CLUSTER, EVAL_NAMESPACE, EVAL_IP (default 127.0.0.1),
#   EVAL_HTTPS_PORT (443), EVAL_HTTP_PORT (80), EVAL_CHART_VERSION, EVAL_CHART_REF.
set -euo pipefail

CLUSTER="${EVAL_CLUSTER:-bamf-eval}"
KCTX="k3d-${EVAL_CLUSTER:-bamf-eval}"   # explicit context — never switch the user's global one
NS="${EVAL_NAMESPACE:-bamf}"
IP="${EVAL_IP:-127.0.0.1}"
HTTPS_PORT="${EVAL_HTTPS_PORT:-443}"
HTTP_PORT="${EVAL_HTTP_PORT:-80}"
CHART_REF="${EVAL_CHART_REF:-oci://ghcr.io/mattrobinsonsre/bamf}"
CHART_VERSION="${EVAL_CHART_VERSION:-0.11.0}"
TLS_SECRET="bamf-eval-tls"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

HOST="bamf.${IP}.sslip.io"
TUNNEL_DOMAIN="${IP}.sslip.io"
PORT_SUFFIX=""; [ "$HTTPS_PORT" != "443" ] && PORT_SUFFIX=":${HTTPS_PORT}"
BASE_URL="https://${HOST}${PORT_SUFFIX}"

Y=$'\033[1;33m'; G=$'\033[0;32m'; NC=$'\033[0m'
step() { echo "${Y}==>${NC} $*"; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing prerequisite: $1" >&2; exit 1; }; }

gen_tls() {
  local dir; dir="$(mktemp -d)"
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
    -keyout "$dir/tls.key" -out "$dir/tls.crt" \
    -subj "/CN=${HOST}" \
    -addext "subjectAltName=DNS:${HOST},DNS:*.tunnel.${TUNNEL_DOMAIN}" 2>/dev/null
  kubectl --context "$KCTX" -n "$NS" create secret tls "$TLS_SECRET" \
    --cert="$dir/tls.crt" --key="$dir/tls.key" \
    --dry-run=client -o yaml | kubectl --context "$KCTX" apply -f - >/dev/null
  rm -rf "$dir"
}

up() {
  local local_build=0
  [ "${1:-}" = "--local-build" ] && local_build=1
  need k3d; need docker; need helm; need kubectl; need openssl

  if k3d cluster list -o json 2>/dev/null | grep -q "\"name\":\"${CLUSTER}\""; then
    step "k3d cluster '${CLUSTER}' already exists — reusing"
  else
    step "Creating k3d cluster '${CLUSTER}' (host :${HTTPS_PORT}→443, :${HTTP_PORT}→80)"
    k3d cluster create "$CLUSTER" \
      --port "${HTTPS_PORT}:443@loadbalancer" \
      --port "${HTTP_PORT}:80@loadbalancer" \
      --kubeconfig-switch-context=false \
      --wait
  fi
  # All operations target the eval cluster by explicit context — the user's
  # current-context is never changed.
  kubectl --context "$KCTX" create namespace "$NS" --dry-run=client -o yaml | kubectl --context "$KCTX" apply -f - >/dev/null

  step "Waiting for Traefik (k3s built-in ingress)"
  kubectl --context "$KCTX" -n kube-system rollout status deploy/traefik --timeout=150s || true

  step "Generating a self-signed TLS cert for ${HOST} and *.tunnel.${TUNNEL_DOMAIN}"
  gen_tls

  step "Deploying the demo target (traefik/whoami)"
  kubectl --context "$KCTX" apply -f "${REPO_ROOT}/scripts/eval/demo-target.yaml" >/dev/null

  # Build the helm invocation as one always-non-empty array (bash 3.2 + set -u safe).
  local helm_args
  helm_args=(--kube-context "$KCTX" upgrade --install bamf)
  if [ "$local_build" = 1 ]; then
    helm_args+=("${REPO_ROOT}/helm/bamf")
    step "Importing locally-built images into the cluster (--local-build)"
    for img in bamf-api bamf-bridge bamf-agent bamf-web bamf-proxy; do
      k3d image import -c "$CLUSTER" "ghcr.io/mattrobinsonsre/${img}:${EVAL_IMAGE_TAG:-latest}" 2>/dev/null || true
    done
    step "Installing BAMF (local chart)"
  else
    helm_args+=("$CHART_REF" --version "$CHART_VERSION")
    step "Installing BAMF (${CHART_REF} ${CHART_VERSION})"
  fi
  helm_args+=(
    -n "$NS"
    -f "${REPO_ROOT}/helm/bamf/values-eval.yaml"
    --set "gateway.hostname=${HOST}"
    --set "gateway.tunnelDomain=${TUNNEL_DOMAIN}"
    --set "gateway.ports.https=${HTTPS_PORT}"
    --set "tls.existingSecret=${TLS_SECRET}"
    --timeout 360s
  )
  # NB: no --wait. helm always waits for the post-install bootstrap hook (which
  # seeds the admin user + agent join token) regardless; --wait would instead
  # block on the *agent* becoming ready first, but the agent can't register
  # until that hook has created its token — a deadlock. Without --wait the hook
  # runs, the token appears, and the agent registers on its next retry.
  helm "${helm_args[@]}" || true

  step "Waiting for the stack to be ready"
  for target in deploy/bamf-api statefulset/bamf-bridge deploy/bamf-proxy deploy/bamf-web deploy/bamf-agent; do
    kubectl --context "$KCTX" -n "$NS" rollout status "$target" --timeout=180s || true
  done

  print_access
}

print_access() {
  cat <<EOF

${G}BAMF evaluation stack is up.${NC}

  Web UI / API   ${BASE_URL}
  API docs       ${BASE_URL}/api/docs
  Login          admin / admin
  Demo web app   https://demo.tunnel.${TUNNEL_DOMAIN}${PORT_SUFFIX}

  TLS is self-signed — accept the browser warning (or use curl -k).
  CLI:  bamf login --api ${BASE_URL}   then:  bamf ls

  Smoke it:  BAMF_SMOKE_URL=${BASE_URL} make smoke
  Tear down: make eval-down
EOF
}

down() {
  need k3d
  step "Deleting k3d cluster '${CLUSTER}'"
  k3d cluster delete "$CLUSTER"
}

case "${1:-}" in
  up)   shift; up "${1:-}" ;;
  down) down ;;
  *)    echo "usage: $0 up [--local-build] | down" >&2; exit 1 ;;
esac
