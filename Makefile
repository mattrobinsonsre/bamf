# BAMF Makefile
# Thin wrapper around scripts/*.sh — all build logic lives in scripts.
# Use gmake on macOS (GNU Make 4+).
#
# Docker-first: lint, test, build, and publish all run in containers.
# Local tooling: only needed for Tilt dev (Go, Rancher Desktop, Tilt, mkcert).

.PHONY: lint lint-go lint-python lint-web \
	test test-go test-python \
	build build-local images packages \
	publish publish-images publish-chart publish-release \
	release dev dev-down \
	security-scan security-scan-go security-scan-python \
	clean clean-cache test-down \
	db-migrate db-rollback db-reset proto \
	help

# ── Variables (for build-local only) ─────────────────────
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -s -w \
	-X github.com/mattrobinsonsre/bamf/cmd/bamf/cmd.Version=$(VERSION) \
	-X github.com/mattrobinsonsre/bamf/cmd/bamf/cmd.GitCommit=$(GIT_COMMIT) \
	-X github.com/mattrobinsonsre/bamf/cmd/bamf/cmd.BuildTime=$(BUILD_TIME)

# ── Lint ──────────────────────────────────────────────────
lint:               ## Lint all (Go + Python + Web) in Docker
	scripts/lint.sh

lint-go:            ## Lint Go only (Docker)
	scripts/lint.sh go

lint-python:        ## Lint Python only (Docker)
	scripts/lint.sh python

lint-web:           ## Lint Web only (Docker)
	scripts/lint.sh web

# ── Test ──────────────────────────────────────────────────
test:               ## Test all (Go + Python) in Docker
	scripts/test.sh

test-go:            ## Test Go only (Docker)
	scripts/test.sh go

test-python:        ## Test Python only (Docker)
	scripts/test.sh python

# ── Build ─────────────────────────────────────────────────
build:              ## Cross-compile Go binaries for all platforms (Docker)
	scripts/build.sh binaries

build-local:        ## Build Go binaries for current platform (local, needs Go)
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o bin/bamf ./cmd/bamf
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o bin/bamf-bridge ./cmd/bamf-bridge
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o bin/bamf-agent ./cmd/bamf-agent

images:             ## Build Docker images (single-arch, local)
	scripts/build.sh images

packages:           ## Build DEB and RPM packages for agent (Docker)
	scripts/build.sh packages

# ── Publish ───────────────────────────────────────────────
publish:            ## Build + push multi-arch images to GHCR
	scripts/publish.sh images

publish-images:     ## Push multi-arch images to GHCR
	scripts/publish.sh images

publish-chart:      ## Push Helm chart to OCI registry
	scripts/publish.sh chart

publish-release:    ## Create GitHub Release with binaries + packages
	scripts/publish.sh release

# ── Release ───────────────────────────────────────────────
release:            ## Full release: lint, test, build, publish
	scripts/lint.sh
	scripts/test.sh
	scripts/build.sh
	scripts/publish.sh

# ── Security Scanning ────────────────────────────────────
security-scan:          ## Run all security scanners (govulncheck + pip-audit)
	scripts/security-scan.sh

security-scan-go:       ## Run govulncheck (Go vulnerability scanner)
	scripts/security-scan.sh go

security-scan-python:   ## Run pip-audit (Python vulnerability scanner)
	scripts/security-scan.sh python

# ── Development ──────────────────────────────────────────
dev:                ## Start Tilt development environment
	tilt up

dev-down:           ## Stop Tilt
	tilt down

# ── Database (local dev — requires Poetry) ───────────────
db-migrate:         ## Run database migrations
	cd services && poetry run alembic upgrade head

db-rollback:        ## Rollback last migration
	cd services && poetry run alembic downgrade -1

db-reset:           ## Reset database (drop and recreate)
	cd services && poetry run alembic downgrade base
	cd services && poetry run alembic upgrade head

# ── Proto (local dev — requires protoc) ──────────────────
proto:              ## Regenerate protobuf code
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/*.proto

# ── Utility ──────────────────────────────────────────────
clean:              ## Clean build artifacts
	rm -rf bin/ dist/ coverage.out coverage.html
	rm -rf services/.pytest_cache services/.coverage services/htmlcov
	rm -rf web/.next web/node_modules/.cache

clean-cache:        ## Remove Docker build cache volumes
	docker volume rm bamf-gomodcache bamf-gobuildcache bamf-npmcache 2>/dev/null || true

test-down:          ## Tear down test containers
	docker compose -f docker-compose.test.yml down -v

help:               ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
