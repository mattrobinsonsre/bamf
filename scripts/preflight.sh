#!/usr/bin/env bash
# Preflight identity/access doctor — asserts a deployed BAMF stack is wired
# correctly before the first tunnel fails:
#   1. API ↔ Postgres / Redis are reachable  (/ready)
#   2. the internal CA is initialized         (/certificates/ca is served)
#   3. if an agent is deployed, its ServiceAccount can impersonate for
#      Kubernetes access (the k8s-proxy identity path).
#
# Read-only. It never switches the global kube context — it uses the current
# context, or BAMF_CONTEXT if set.
#
# Usage:  scripts/preflight.sh          (or: make preflight-identity)
# Env:    BAMF_NAMESPACE (bamf), BAMF_RELEASE (bamf), BAMF_CONTEXT (current)
set -uo pipefail   # deliberately NOT -e: run every check, then summarize.

NS="${BAMF_NAMESPACE:-bamf}"
RELEASE="${BAMF_RELEASE:-bamf}"
CTX="${BAMF_CONTEXT:-}"

K() { if [ -n "$CTX" ]; then kubectl --context "$CTX" "$@"; else kubectl "$@"; fi; }

G=$'\033[0;32m'; R=$'\033[0;31m'; Y=$'\033[1;33m'; NC=$'\033[0m'
FAIL=0
ok()   { echo "  ${G}✓${NC} $*"; }
bad()  { echo "  ${R}✗${NC} $*"; FAIL=1; }
warn() { echo "  ${Y}!${NC} $*"; }
hdr()  { echo; echo "${Y}==>${NC} $*"; }

echo "BAMF preflight — context: $(K config current-context 2>/dev/null || echo '?'), namespace: $NS"

hdr "Namespace"
if K get ns "$NS" >/dev/null 2>&1; then ok "namespace '$NS' exists"; else bad "namespace '$NS' not found"; echo; echo "${R}Preflight aborted.${NC}"; exit 1; fi

hdr "Control plane"
if K -n "$NS" get deploy "${RELEASE}-api" >/dev/null 2>&1; then ok "API deployment present"; else bad "'${RELEASE}-api' deployment not found"; fi

hdr "API ↔ Postgres / Redis"
ready="$(K -n "$NS" exec "deploy/${RELEASE}-api" -- python -c '
import urllib.request, urllib.error, json, sys
try:
    d = json.load(urllib.request.urlopen("http://localhost:8000/ready", timeout=5))
except urllib.error.HTTPError as e:
    d = json.load(e)          # 503 body still carries the per-service status
except Exception as e:
    print("unreachable:", e); sys.exit(0)
c = d.get("checks", {})
print(c.get("database", "?"), c.get("redis", "?"))
' 2>/dev/null)"
case "$ready" in
  "healthy healthy") ok "Postgres reachable"; ok "Redis reachable" ;;
  "") bad "could not reach the API pod to run the readiness check" ;;
  *) bad "/ready reports: ${ready}" ;;
esac

hdr "Internal CA"
if K -n "$NS" exec "deploy/${RELEASE}-api" -- python -c \
  'import urllib.request; urllib.request.urlopen("http://localhost:8000/api/v1/certificates/ca", timeout=5)' >/dev/null 2>&1; then
  ok "CA initialized (public cert served)"
else
  bad "CA public cert not available at /api/v1/certificates/ca"
fi

hdr "Agent Kubernetes impersonation RBAC"
if K -n "$NS" get sa "${RELEASE}-agent" >/dev/null 2>&1; then
  cani="$(K auth can-i impersonate users --as="system:serviceaccount:${NS}:${RELEASE}-agent" 2>/dev/null)"
  case "$cani" in
    yes) ok "agent SA can impersonate users" ;;
    no)  bad "agent SA '${RELEASE}-agent' cannot impersonate users — Kubernetes-type resources will fail" ;;
    *)   warn "couldn't evaluate impersonation (needs permission to create SubjectAccessReviews)" ;;
  esac
else
  warn "no agent ServiceAccount in '$NS' — skipping (impersonation is only needed for kubernetes-type resources)"
fi

echo
if [ "$FAIL" = 0 ]; then echo "${G}Preflight passed.${NC}"; else echo "${R}Preflight found problems (see ✗ above).${NC}"; exit 1; fi
