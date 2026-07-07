#!/usr/bin/env bash
# Run all tests in Docker.
# Usage: scripts/test.sh [go|python|all]
# Default: all

set -euo pipefail
source "$(dirname "$0")/lib.sh"

test_go() {
  info "Testing Go..."
  docker_go env CGO_ENABLED=1 go test -v -race -count=1 ./...
  success "Go tests passed"
}

test_python() {
  info "Testing Python..."
  ensure_test_image
  docker compose -f "$REPO_ROOT/docker-compose.test.yml" run --rm test
  success "Python tests passed"
}

test_migrations() {
  info "Checking Alembic migrations (upgrade → downgrade base → upgrade)..."
  ensure_test_image
  docker compose -f "$REPO_ROOT/docker-compose.test.yml" run --rm migrate
  docker compose -f "$REPO_ROOT/docker-compose.test.yml" down -v >/dev/null 2>&1 || true
  success "Migrations round-trip cleanly"
}

target="${1:-all}"

case "$target" in
  go)         test_go ;;
  python)     test_python ;;
  migrations) test_migrations ;;
  all)
    test_go
    test_python
    test_migrations
    success "All tests passed"
    ;;
  *)
    error "Unknown target: $target"
    echo "Usage: $0 [go|python|migrations|all]"
    exit 1
    ;;
esac
