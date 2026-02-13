#!/usr/bin/env bash
# Push images and create a GitHub Release.
# Usage: scripts/publish.sh [images|chart|release|all]
# Default: all
#
# Prerequisites:
#   images:  docker login ghcr.io
#   chart:   helm registry login ghcr.io
#   release: gh auth status

set -euo pipefail
source "$(dirname "$0")/lib.sh"

HELM_CHART_DIR="$REPO_ROOT/helm/bamf"

# ── Push multi-arch Docker images to GHCR ─────────────────
publish_images() {
  info "Publishing multi-arch Docker images to ${REGISTRY}..."
  "$REPO_ROOT/scripts/build.sh" images --push
  success "Images published"
}

# ── Push Helm chart to OCI registry ───────────────────────
publish_chart() {
  info "Publishing Helm chart to OCI..."

  # Strip leading 'v' from version for Helm (semver without prefix)
  local chart_version="${VERSION#v}"

  # Package the chart with version and appVersion from git tag
  helm package "$HELM_CHART_DIR" --destination "$REPO_ROOT/dist/" \
    --version "$chart_version" --app-version "$chart_version"

  # Push to GHCR OCI
  helm push "$REPO_ROOT/dist/bamf-${chart_version}.tgz" "oci://${REGISTRY}"

  success "Helm chart bamf:${chart_version} pushed to oci://${REGISTRY}"
}

# ── Create GitHub Release with binaries + packages ────────
publish_release() {
  info "Creating GitHub Release ${VERSION}..."

  # Verify dist/ has artifacts
  if [[ ! -d "$REPO_ROOT/dist" ]] || [[ -z "$(ls "$REPO_ROOT/dist/" 2>/dev/null)" ]]; then
    error "dist/ is empty — run 'scripts/build.sh' first"
    exit 1
  fi

  # Generate checksums (use gsha256sum on macOS, sha256sum on Linux)
  local sha_cmd="sha256sum"
  command -v gsha256sum &>/dev/null && sha_cmd="gsha256sum"

  info "Generating checksums..."
  (cd "$REPO_ROOT/dist" && $sha_cmd -- * > checksums.txt)

  info "Creating release..."
  gh release create "$VERSION" "$REPO_ROOT"/dist/* \
    --title "BAMF ${VERSION}" \
    --generate-notes

  success "GitHub Release ${VERSION} created"
}

target="${1:-all}"

case "$target" in
  images)  publish_images ;;
  chart)   publish_chart ;;
  release) publish_release ;;
  all)
    publish_images
    publish_chart
    publish_release
    success "All artifacts published"
    ;;
  *)
    error "Unknown target: $target"
    echo "Usage: $0 [images|chart|release|all]"
    exit 1
    ;;
esac
