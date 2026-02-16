#!/usr/bin/env bash
# Build binaries, packages, and/or Docker images.
# Usage: scripts/build.sh [binaries|packages|images|all] [--push]
# Default: all

set -euo pipefail
source "$(dirname "$0")/lib.sh"

PUSH=false
TARGETS=()

for arg in "$@"; do
  case "$arg" in
    --push) PUSH=true ;;
    *)      TARGETS+=("$arg") ;;
  esac
done

# Default to "all" if no targets specified
[[ ${#TARGETS[@]} -eq 0 ]] && TARGETS=("all")

# ── Build Go binaries for all platforms ───────────────────
build_binaries() {
  info "Cross-compiling Go binaries..."
  rm -rf "$REPO_ROOT/dist"
  mkdir -p "$REPO_ROOT/dist"

  docker_go bash -c '
    set -euo pipefail
    LDFLAGS="-s -w \
      -X github.com/mattrobinsonsre/bamf/cmd/bamf/cmd.Version=${VERSION} \
      -X github.com/mattrobinsonsre/bamf/cmd/bamf/cmd.GitCommit=${GIT_COMMIT} \
      -X github.com/mattrobinsonsre/bamf/cmd/bamf/cmd.BuildTime=${BUILD_TIME}"

    build() {
      local os=$1 arch=$2 bin=$3 cmd=$4
      local out="dist/${bin}-${os}-${arch}"
      [[ "$os" == "windows" ]] && out="${out}.exe"
      echo "  Building ${out}..."
      GOOS=$os GOARCH=$arch go build -ldflags="$LDFLAGS" -o "$out" "./cmd/$cmd"
    }

    # CLI + Agent: all 6 platforms
    for platform in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do
      os="${platform%%/*}"
      arch="${platform##*/}"
      build "$os" "$arch" bamf bamf
      build "$os" "$arch" bamf-agent bamf-agent
    done

    # Bridge: Linux only (container-only)
    for arch in amd64 arm64; do
      build linux "$arch" bamf-bridge bamf-bridge
    done

    echo "Done."
  '

  success "Binaries written to dist/"
}

# ── Build DEB and RPM packages for agent ──────────────────
build_packages() {
  info "Building agent packages (DEB + RPM)..."

  # Verify binaries exist
  for arch in amd64 arm64; do
    local bin="$REPO_ROOT/dist/bamf-agent-linux-${arch}"
    if [[ ! -f "$bin" ]]; then
      error "Missing $bin — run 'scripts/build.sh binaries' first"
      exit 1
    fi
  done

  for arch in amd64 arm64; do
    info "  Packaging ${arch}..."

    # nfpm doesn't expand env vars in contents.src — pre-expand the config
    local nfpm_config="$REPO_ROOT/dist/bamf-agent-${arch}.yaml"
    ARCH="$arch" VERSION="$VERSION" envsubst < "$REPO_ROOT/packaging/bamf-agent.yaml" > "$nfpm_config"

    for fmt in deb rpm; do
      docker run --rm \
        -v "$REPO_ROOT:/build" \
        -w /build \
        goreleaser/nfpm:latest \
        package \
          --config "dist/bamf-agent-${arch}.yaml" \
          --target "dist/" \
          --packager "$fmt"
    done

    rm -f "$nfpm_config"
  done

  success "Packages written to dist/"
}

# ── Build Docker images ──────────────────────────────────
build_images() {
  if $PUSH; then
    build_images_multiarch
  else
    build_images_local
  fi
}

build_images_local() {
  info "Building Docker images (single-arch, local)..."

  docker build -f "$REPO_ROOT/docker/Dockerfile.api" \
    -t "bamf-api:${VERSION}" "$REPO_ROOT"

  docker build -f "$REPO_ROOT/docker/Dockerfile.bridge" \
    -t "bamf-bridge:${VERSION}" "$REPO_ROOT"

  docker build -f "$REPO_ROOT/docker/Dockerfile.agent" \
    -t "bamf-agent:${VERSION}" "$REPO_ROOT"

  docker build -f "$REPO_ROOT/docker/Dockerfile.web" \
    -t "bamf-web:${VERSION}" "$REPO_ROOT"

  success "Local images built: bamf-{api,bridge,agent,web}:${VERSION}"
}

build_images_multiarch() {
  info "Building multi-arch Docker images..."

  # Verify cross-compiled binaries exist for bridge and agent
  for arch in amd64 arm64; do
    for bin in bamf-bridge bamf-agent; do
      if [[ ! -f "$REPO_ROOT/dist/${bin}-linux-${arch}" ]]; then
        error "Missing dist/${bin}-linux-${arch} — run 'scripts/build.sh binaries' first"
        exit 1
      fi
    done
  done

  local tags="-t ${REGISTRY}/bamf-api:${VERSION}"
  # Tag :latest only for semver tags (vX.Y.Z)
  if [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    tags="$tags -t ${REGISTRY}/bamf-api:latest"
  fi

  # API (Python — arch-independent build)
  info "  bamf-api..."
  docker buildx build -f "$REPO_ROOT/docker/Dockerfile.api" \
    --platform linux/amd64,linux/arm64 \
    $tags --push "$REPO_ROOT"

  # Web (Node — arch-independent build)
  tags="-t ${REGISTRY}/bamf-web:${VERSION}"
  [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] && tags="$tags -t ${REGISTRY}/bamf-web:latest"
  info "  bamf-web..."
  docker buildx build -f "$REPO_ROOT/docker/Dockerfile.web" \
    --platform linux/amd64,linux/arm64 \
    $tags --push "$REPO_ROOT"

  # Bridge (pre-built Go binary via Dockerfile.release)
  tags="-t ${REGISTRY}/bamf-bridge:${VERSION}"
  [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] && tags="$tags -t ${REGISTRY}/bamf-bridge:latest"
  info "  bamf-bridge..."
  docker buildx build -f "$REPO_ROOT/docker/Dockerfile.release" \
    --build-arg BINARY=bamf-bridge \
    --platform linux/amd64,linux/arm64 \
    $tags --push "$REPO_ROOT"

  # Agent (pre-built Go binary via Dockerfile.release)
  tags="-t ${REGISTRY}/bamf-agent:${VERSION}"
  [[ "$VERSION" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] && tags="$tags -t ${REGISTRY}/bamf-agent:latest"
  info "  bamf-agent..."
  docker buildx build -f "$REPO_ROOT/docker/Dockerfile.release" \
    --build-arg BINARY=bamf-agent \
    --platform linux/amd64,linux/arm64 \
    $tags --push "$REPO_ROOT"

  success "Multi-arch images pushed to ${REGISTRY}"
}

# ── Run targets ──────────────────────────────────────────
for target in "${TARGETS[@]}"; do
  case "$target" in
    binaries) build_binaries ;;
    packages) build_packages ;;
    images)   build_images ;;
    all)
      build_binaries
      build_packages
      build_images
      ;;
    *)
      error "Unknown target: $target"
      echo "Usage: $0 [binaries|packages|images|all] [--push]"
      exit 1
      ;;
  esac
done
