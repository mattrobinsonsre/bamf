#!/usr/bin/env bash
# Lint all components in Docker.
# Usage: scripts/lint.sh [go|python|web|all]
# Default: all

set -euo pipefail
source "$(dirname "$0")/lib.sh"

lint_go() {
  info "Linting Go..."
  docker_go golangci-lint run ./...
  success "Go lint passed"
}

lint_python() {
  info "Linting Python..."
  COMPOSE_BAKE=false docker compose -f "$REPO_ROOT/docker-compose.test.yml" run --rm --build lint
  success "Python lint passed"
}

lint_web() {
  info "Linting Web (ESLint + TypeScript)..."
  docker_node sh -c "npm ci --ignore-scripts && npm run lint && npm run type-check"
  success "Web lint passed"
}

target="${1:-all}"

case "$target" in
  go)     lint_go ;;
  python) lint_python ;;
  web)    lint_web ;;
  all)
    lint_go
    lint_python
    lint_web
    success "All linters passed"
    ;;
  *)
    error "Unknown target: $target"
    echo "Usage: $0 [go|python|web|all]"
    exit 1
    ;;
esac
