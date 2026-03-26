#!/usr/bin/env bash
# Run security vulnerability scanners.
# Usage: scripts/security-scan.sh [go|python|all]
# Default: all

set -euo pipefail
source "$(dirname "$0")/lib.sh"

scan_go() {
  info "Running govulncheck (Go vulnerability scanner)..."
  docker_go govulncheck ./...
  success "govulncheck passed — no known vulnerabilities"
}

scan_python() {
  info "Running pip-audit (Python vulnerability scanner)..."
  ensure_test_image
  # --ignore-vuln: pygments 2.19.2 CVE-2026-4539 has no fix version available
  docker compose -f "$REPO_ROOT/docker-compose.test.yml" run --rm \
    --entrypoint sh test -c "pip install --quiet pip-audit && pip-audit --ignore-vuln CVE-2026-4539"
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
