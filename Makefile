# BAMF Makefile
# Build, test, and development tasks
#
# Python targets run in Docker containers to avoid local PYTHONPATH conflicts.
# Go targets run locally. Use gmake on macOS (GNU Make 4+).

.PHONY: all build build-cli build-bridge build-agent build-all-platforms \
	test test-go test-python test-coverage \
	lint lint-go lint-python format \
	docker docker-api docker-bridge docker-agent docker-web \
	dev dev-down install-deps \
	db-migrate db-rollback db-reset proto clean help

# Default target
all: build

# ─────────────────────────────────────────────────────────────────────────────
# Variables
# ─────────────────────────────────────────────────────────────────────────────

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
GIT_COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS := -s -w \
	-X github.com/mattrobinsonsre/bamf/cmd/bamf/cmd.Version=$(VERSION) \
	-X github.com/mattrobinsonsre/bamf/cmd/bamf/cmd.GitCommit=$(GIT_COMMIT) \
	-X github.com/mattrobinsonsre/bamf/cmd/bamf/cmd.BuildTime=$(BUILD_TIME)

# Go build settings
GOOS ?= $(shell go env GOOS)
GOARCH ?= $(shell go env GOARCH)

# ─────────────────────────────────────────────────────────────────────────────
# Build targets
# ─────────────────────────────────────────────────────────────────────────────

build: build-cli build-bridge build-agent ## Build all Go binaries

build-cli: ## Build CLI binary
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o bin/bamf ./cmd/bamf

build-bridge: ## Build bridge binary (tunnel gateway)
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o bin/bamf-bridge ./cmd/bamf-bridge

build-agent: ## Build agent binary
	CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o bin/bamf-agent ./cmd/bamf-agent

build-all-platforms: ## Build binaries for all platforms
	@mkdir -p dist
	# Linux amd64
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o dist/bamf-linux-amd64 ./cmd/bamf
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o dist/bamf-agent-linux-amd64 ./cmd/bamf-agent
	# Linux arm64
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o dist/bamf-linux-arm64 ./cmd/bamf
	GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o dist/bamf-agent-linux-arm64 ./cmd/bamf-agent
	# macOS amd64
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o dist/bamf-darwin-amd64 ./cmd/bamf
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o dist/bamf-agent-darwin-amd64 ./cmd/bamf-agent
	# macOS arm64
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o dist/bamf-darwin-arm64 ./cmd/bamf
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o dist/bamf-agent-darwin-arm64 ./cmd/bamf-agent
	# Windows amd64
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o dist/bamf-windows-amd64.exe ./cmd/bamf
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o dist/bamf-agent-windows-amd64.exe ./cmd/bamf-agent
	# Windows arm64
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o dist/bamf-windows-arm64.exe ./cmd/bamf
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="$(LDFLAGS)" -o dist/bamf-agent-windows-arm64.exe ./cmd/bamf-agent

# ─────────────────────────────────────────────────────────────────────────────
# Test targets
# ─────────────────────────────────────────────────────────────────────────────

test: test-go test-python ## Run all tests

test-go: ## Run Go tests
	go test -v -race ./...

test-python: ## Run Python tests (containerized)
	docker compose -f docker-compose.test.yml run --rm --build test

test-coverage: ## Run tests with coverage
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

test-down: ## Tear down test containers
	docker compose -f docker-compose.test.yml down -v

# ─────────────────────────────────────────────────────────────────────────────
# Lint targets
# ─────────────────────────────────────────────────────────────────────────────

lint: lint-go lint-python ## Run all linters

lint-go: ## Run Go linter
	golangci-lint run ./...

lint-python: ## Run Python linter (containerized)
	docker compose -f docker-compose.test.yml run --rm --build lint

format: ## Format code
	gofmt -s -w .

# ─────────────────────────────────────────────────────────────────────────────
# Docker targets
# ─────────────────────────────────────────────────────────────────────────────

docker: docker-api docker-bridge docker-agent docker-web ## Build all Docker images

docker-api: ## Build API Docker image
	docker build -f docker/Dockerfile.api -t bamf-api:$(VERSION) .

docker-bridge: ## Build bridge Docker image (tunnel gateway)
	docker build -f docker/Dockerfile.bridge -t bamf-bridge:$(VERSION) .

docker-agent: build-all-platforms ## Build agent Docker image (requires pre-built binaries)
	docker buildx build -f docker/Dockerfile.agent \
		--platform linux/amd64,linux/arm64 \
		-t bamf-agent:$(VERSION) .

docker-web: ## Build web UI Docker image
	docker build -f docker/Dockerfile.web -t bamf-web:$(VERSION) .

# ─────────────────────────────────────────────────────────────────────────────
# Development targets
# ─────────────────────────────────────────────────────────────────────────────

dev: ## Start development environment (Tilt)
	tilt up

dev-down: ## Stop development environment
	tilt down

install-deps: ## Install development dependencies
	go mod download
	cd services && poetry install
	cd web && npm install

# ─────────────────────────────────────────────────────────────────────────────
# Database targets
# ─────────────────────────────────────────────────────────────────────────────

db-migrate: ## Run database migrations
	cd services && poetry run alembic upgrade head

db-rollback: ## Rollback last migration
	cd services && poetry run alembic downgrade -1

db-reset: ## Reset database (drop and recreate)
	cd services && poetry run alembic downgrade base
	cd services && poetry run alembic upgrade head

# ─────────────────────────────────────────────────────────────────────────────
# Proto targets
# ─────────────────────────────────────────────────────────────────────────────

proto: ## Regenerate protobuf code
	protoc --go_out=. --go_opt=paths=source_relative \
		--go-grpc_out=. --go-grpc_opt=paths=source_relative \
		proto/*.proto

# ─────────────────────────────────────────────────────────────────────────────
# Clean targets
# ─────────────────────────────────────────────────────────────────────────────

clean: ## Clean build artifacts
	rm -rf bin/ dist/ coverage.out coverage.html
	rm -rf services/.pytest_cache services/.coverage services/htmlcov
	rm -rf web/.next web/node_modules/.cache

# ─────────────────────────────────────────────────────────────────────────────
# Help
# ─────────────────────────────────────────────────────────────────────────────

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'
