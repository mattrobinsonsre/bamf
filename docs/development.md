# Development

Build BAMF from source and run the local development environment.

## Prerequisites

- **Docker** (Rancher Desktop recommended — ships with Kubernetes and Traefik)
- **gmake** (`brew install make`) — macOS system `make` is too old
- **Tilt** (`brew install tilt`) for hot-reload development
- **mkcert** (`brew install mkcert && mkcert -install`) for local TLS

Go, Python, and Node.js toolchains run inside Docker containers — no local
installation required. The Makefile handles container orchestration transparently.

## Building from Source

All builds run in Docker containers — no local Go, Python, or Node.js required.

### Go Binaries (all platforms)

```zsh
gmake build
# Cross-compiles for: linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64, windows/arm64
# Outputs to dist/
```

### Docker Images

```zsh
gmake images
# Builds: bamf-api, bamf-bridge, bamf-agent, bamf-web
```

### Go Binaries (local platform only, requires local Go)

```zsh
gmake build-local
# Produces: bin/bamf, bin/bamf-bridge, bin/bamf-agent
# Only needed for rapid iteration during development
```

## Running Tests

```zsh
# All tests (Go + Python, runs in Docker)
gmake test

# Go tests only
gmake test-go

# Python tests only (runs in Docker — never run Poetry tests locally)
gmake test-python
```

Python tests run in Docker via `docker-compose.test.yml` to avoid `PYTHONPATH`
pollution from the macOS shell environment.

## Linting

```zsh
# All linters (Go + Python + Web)
gmake lint

# Individual
gmake lint-go
gmake lint-python
gmake lint-web
```

## Local Development Environment

The local dev environment runs the full BAMF stack in Kubernetes via Tilt with
hot-reload.

### One-Time Cluster Setup

```zsh
# 1. Verify context (CRITICAL — never deploy to production!)
kubectl config use-context rancher-desktop

# 2. Create namespace
kubectl create namespace bamf

# 3. Add /etc/hosts entry
sudo sh -c 'echo "127.0.0.1 bamf.local" >> /etc/hosts'
```

Rancher Desktop ships with Traefik, which handles all routing out of the box.
No additional ingress controller setup is needed.

### Starting the Stack

```zsh
# Always verify context first!
kubectl config use-context rancher-desktop

# Start with hot-reload
gmake dev    # or: tilt up
```

Tilt will:
- Build Docker images locally via Rancher Desktop's dockerd
- Deploy all components via Helm
- Set up mkcert certificates
- Watch for file changes and rebuild/redeploy

### Accessing the Stack

| Service | URL |
|---------|-----|
| Web UI | https://bamf.local |
| API | https://bamf.local/api/v1/ |
| API docs | https://bamf.local/api/docs |
| Bridge tunnels | localhost:443 (SNI routing) |

Local dev credentials: `admin` / `admin`

### Database Migrations

```zsh
gmake db-migrate     # Apply migrations
gmake db-rollback    # Rollback last migration
gmake db-reset       # Full reset (drop + recreate)
```

## Project Structure

```
bamf/
├── services/          # Python API server (FastAPI)
│   ├── bamf/api/      # API routes, middleware
│   ├── bamf/auth/     # CA, RBAC, SSO
│   └── bamf/db/       # SQLAlchemy models
├── cmd/               # Go binaries (CLI, bridge, agent)
├── pkg/               # Go shared packages
├── web/               # Next.js frontend
├── helm/bamf/         # Helm chart
├── docker/            # Dockerfiles
├── alembic/           # Database migrations
└── docs/              # Documentation
```

## Conventions

- **Python**: FastAPI, async everywhere, structlog, ruff for formatting
- **Go**: slog, context propagation, no CGo, table-driven tests
- **TypeScript**: Strict mode, functional components, no `any`
- **Git**: Conventional commits (`feat:`, `fix:`, `refactor:`, etc.)
- **Helm**: Primary deployment mechanism; every service change needs chart updates

## Makefile Targets

| Target | Description |
|--------|-------------|
| `gmake dev` | Start Tilt development environment |
| `gmake dev-down` | Stop Tilt |
| `gmake build-local` | Build Go binaries for current platform |
| `gmake build` | Cross-compile Go binaries (Docker) |
| `gmake images` | Build Docker images |
| `gmake test` | Run all tests |
| `gmake test-go` | Run Go tests |
| `gmake test-python` | Run Python tests (Docker) |
| `gmake lint` | Run all linters |
| `gmake db-migrate` | Apply database migrations |
| `gmake db-rollback` | Rollback last migration |
| `gmake db-reset` | Full database reset |
| `gmake clean` | Remove build artifacts |
| `gmake help` | Show all targets |
