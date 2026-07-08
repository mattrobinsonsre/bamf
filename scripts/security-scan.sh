#!/usr/bin/env bash
# Run security vulnerability scanners.
# Usage: scripts/security-scan.sh [go|python|all]
# Default: all

set -euo pipefail
source "$(dirname "$0")/lib.sh"

scan_go() {
  # govulncheck reports only vulnerabilities in reachable code, so there is no
  # suppression file: a finding is fixed (bump the dep) rather than ignored. A
  # genuinely unfixable, unreachable case is documented in SECURITY.md instead.
  info "Running govulncheck (Go vulnerability scanner)..."
  docker_go govulncheck ./...
  success "govulncheck passed — no known vulnerabilities"
}

# Read a suppression allowlist file into `--ignore-vuln <ID>` args (comments and
# blank lines stripped). Local and CI read the same committed file.
_pip_audit_ignores() {
  local f="$REPO_ROOT/pentest/pip-audit/ignore-vulns.txt"
  [ -f "$f" ] || return 0
  # `grep -v` exits 1 when the file is all-comments (no lines selected); that is
  # the normal "no suppressions" case, not an error, so swallow it.
  grep -vE '^[[:space:]]*(#|$)' "$f" 2>/dev/null | sed 's/^/--ignore-vuln /' | tr '\n' ' ' || true
}

scan_python() {
  info "Running pip-audit (Python vulnerability scanner)..."
  ensure_test_image
  local ignores
  ignores="$(_pip_audit_ignores)"
  docker compose -f "$REPO_ROOT/docker-compose.test.yml" run --rm \
    --entrypoint sh test -c "pip install --quiet pip-audit && pip-audit ${ignores}"
  success "pip-audit passed — no known vulnerabilities"
}

target="${1:-all}"

case "$target" in
  go)     scan_go ;;
  python) scan_python ;;
  all)
    scan_go
    scan_python
    success "All security scans passed"
    ;;
  *)
    error "Unknown target: $target"
    echo "Usage: $0 [go|python|all]"
    exit 1
    ;;
esac
