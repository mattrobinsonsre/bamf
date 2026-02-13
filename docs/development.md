# Development

Build BAMF from source and run the local development environment.

## Prerequisites

- **Go** 1.23+ (`brew install go`)
- **Python** 3.13+ (via pyenv or system)
- **Node.js** 20+ (`brew install node`)
- **Docker** (Rancher Desktop recommended)
- **gmake** (`brew install make`) — macOS system `make` is too old
- **Rancher Desktop** for local Kubernetes
- **Tilt** (`brew install tilt`) for hot-reload development
- **istioctl** (`brew install istioctl`) for Istio installation
- **mkcert** (`brew install mkcert && mkcert -install`) for local TLS

## Building from Source

### Go Binaries (local platform)

```zsh
gmake build-local
# Produces: bin/bamf, bin/bamf-bridge, bin/bamf-agent
```

### Docker Images

```zsh
gmake images
```

### Cross-platform Binaries (all architectures)

```zsh
gmake build
# Produces binaries for linux/amd64, linux/arm64, darwin/amd64, darwin/arm64, windows/amd64, windows/arm64
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

# 2. Install Gateway API CRDs
kubectl apply -f https://github.com/kubernetes-sigs/gateway-api/releases/download/v1.4.0/experimental-install.yaml \
  --server-side --force-conflicts

# 3. Install Istio
istioctl install --set profile=minimal \
  --set values.pilot.env.PILOT_ENABLE_ALPHA_GATEWAY_API=true -y

# 4. Create namespace
kubectl create namespace bamf

# 5. Add /etc/hosts entry
sudo sh -c 'echo "127.0.0.1 bamf.local" >> /etc/hosts'
```

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
| Web UI | https://bamf.local:8443 |
| API | https://bamf.local:8443/api/v1/ |
| API docs | https://bamf.local:8443/api/docs |
| Bridge tunnels | localhost:443 (SNI routing) |

Local dev credentials: `admin` / `admin`

Port 8443 is used instead of 443 to avoid conflict with Traefik (default in
Rancher Desktop).

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
