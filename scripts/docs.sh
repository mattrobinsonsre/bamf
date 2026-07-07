#!/usr/bin/env bash
# Build (or serve) the documentation site.
# Usage: scripts/docs.sh [build|serve]
# Default: build
#
# `build` runs `mkdocs build --strict` — broken internal links and orphaned or
# missing nav pages fail the build. This is the docs-drift gate: a renamed page
# or a mistyped cross-link fails CI instead of silently 404-ing on the site.
# `serve` runs a live-reload preview on http://localhost:8000.
#
# Runs in the pinned mkdocs-material container, so no local Python/mkdocs
# install is required — only Docker.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

# Pinned by digest (mkdocs-material, mkdocs 1.6.1) for reproducible builds.
DOCS_IMAGE="squidfunk/mkdocs-material@sha256:868ad4d39fb5865b72d00173ade00f4eae2b38dde7ff790a011cc44ce4a8ff8e"

target="${1:-build}"
case "$target" in
  build)
    info "Building docs site (mkdocs --strict)..."
    docker run --rm -v "$REPO_ROOT":/docs "$DOCS_IMAGE" build --strict
    success "Docs built (strict): no broken links or nav gaps"
    ;;
  serve)
    info "Serving docs at http://localhost:8000 (ctrl-c to stop)..."
    docker run --rm -it -p 8000:8000 -v "$REPO_ROOT":/docs "$DOCS_IMAGE" serve --dev-addr 0.0.0.0:8000
    ;;
  *)
    error "Unknown target: $target"
    echo "Usage: $0 [build|serve]"
    exit 1
    ;;
esac
