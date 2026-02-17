#!/usr/bin/env bash
# Shared variables and helpers for BAMF build scripts.
# Sourced by all other scripts in scripts/.

set -euo pipefail

# ── Repo root ─────────────────────────────────────────────
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── Version info ──────────────────────────────────────────
VERSION="${VERSION:-$(git -C "$REPO_ROOT" describe --tags --always --dirty 2>/dev/null || echo "dev")}"
GIT_COMMIT="${GIT_COMMIT:-$(git -C "$REPO_ROOT" rev-parse --short HEAD 2>/dev/null || echo "unknown")}"
BUILD_TIME="${BUILD_TIME:-$(date -u +"%Y-%m-%dT%H:%M:%SZ")}"

# Go ldflags for version injection (only CLI has version vars)
LDFLAGS="-s -w \
  -X github.com/mattrobinsonsre/bamf/cmd/bamf/cmd.Version=${VERSION} \
  -X github.com/mattrobinsonsre/bamf/cmd/bamf/cmd.GitCommit=${GIT_COMMIT} \
  -X github.com/mattrobinsonsre/bamf/cmd/bamf/cmd.BuildTime=${BUILD_TIME}"

# ── Registry and image names ─────────────────────────────
REGISTRY="${REGISTRY:-ghcr.io/mattrobinsonsre}"
CI_IMAGE="${CI_IMAGE:-bamf-ci:local}"

# ── Platform matrix ──────────────────────────────────────
# CLI + Agent: all 6 platforms
ALL_PLATFORMS="linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64"
# Bridge: Linux only (container-only)
LINUX_PLATFORMS="linux/amd64 linux/arm64"

# ── Output helpers ────────────────────────────────────────
info()    { printf '\033[1;34m==> %s\033[0m\n' "$*"; }
success() { printf '\033[1;32m==> %s\033[0m\n' "$*"; }
error()   { printf '\033[1;31m==> ERROR: %s\033[0m\n' "$*" >&2; }

# ── Docker helpers ────────────────────────────────────────

# Build the Go CI image if it doesn't exist locally.
ensure_ci_image() {
  if ! docker image inspect "$CI_IMAGE" &>/dev/null; then
    info "Building CI image ($CI_IMAGE)..."
    docker build -f "$REPO_ROOT/docker/Dockerfile.ci" -t "$CI_IMAGE" "$REPO_ROOT"
  fi
}

# Run a command inside the Go CI container.
# Usage: docker_go <command> [args...]
docker_go() {
  ensure_ci_image
  docker run --rm \
    -v "$REPO_ROOT:/build" \
    -v bamf-gomodcache:/go/pkg/mod \
    -v bamf-gobuildcache:/root/.cache/go-build \
    -w /build \
    -e "VERSION=${VERSION}" \
    -e "GIT_COMMIT=${GIT_COMMIT}" \
    -e "BUILD_TIME=${BUILD_TIME}" \
    -e CGO_ENABLED=0 \
    "$CI_IMAGE" \
    "$@"
}

# Build the Python test image if needed.
# Works around Docker Compose bake mode losing the dockerfile path.
TEST_IMAGE="${TEST_IMAGE:-bamf-test:local}"
ensure_test_image() {
  info "Building Python test image ($TEST_IMAGE)..."
  docker build -f "$REPO_ROOT/docker/Dockerfile.test" -t "$TEST_IMAGE" "$REPO_ROOT"
}

# Run a command inside a Node.js container.
# Usage: docker_node <command> [args...]
docker_node() {
  docker run --rm \
    -v "$REPO_ROOT/web:/app" \
    -v bamf-npmcache:/root/.npm \
    -w /app \
    node:25-alpine \
    "$@"
}
