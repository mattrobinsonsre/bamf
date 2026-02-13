# Architecture Overview

BAMF is a hybrid Go + Python system. Go handles the data path (CLI, bridge,
agent) where portable static binaries and efficient byte-level protocol handling
matter. Python handles the control plane (API, CA, RBAC, SSO, HTTP proxy) where
development velocity and ecosystem richness are priorities.

## System Diagram

```
                           Public Internet
                                  │
                 ┌────────────────┴────────────────┐
                 │                                 │
                 ▼                                 ▼
      ┌──────────────────────────────────────────────────────┐
      │              Istio Gateway (single LB)               │
      │  ┌────────────┬─────────────┬───────────────────────┐│
      │  │  :443      │   :443      │      :443             ││
      │  │ HTTPRoute  │  HTTPRoute  │    TLSRoute           ││
      │  │bamf.domain │*.tunnel.dom │  (SNI passthrough)    ││
      │  │ TLS term   │  TLS term   │   per-bridge pod      ││
      │  └─────┬──────┴──────┬──────┴──────────┬────────────┘│
      └────────┼─────────────┼─────────────────┼─────────────┘
               │             │                 │
               ▼             ▼                 ▼
      ┌──────────────────┐   │        ┌──────────────────┐
      │   API Server     │◀──┘        │  Bridge          │
      │  Python/FastAPI  │            │  Go StatefulSet  │
      │  CA · RBAC · SSO │───────────▶│  tunnel relay    │
      │  HTTP proxy      │            │  bridge-0..N     │
      └────────┬─────────┘            └────────┬─────────┘
               │                               │
      ┌────────▼─────────┐            ┌────────▼─────────┐
      │   Web UI (SPA)   │            │   Agents (Go)    │
      │   Next.js/React  │            │   K8s or VM      │
      └──────────────────┘            └────────┬─────────┘
                                               │
                                        Target Resources
```

## Components

### API Server (Python / FastAPI)

The control plane. Owns the internal CA, issues certificates, handles
authentication (local + SSO), enforces RBAC, serves the REST API, and runs the
HTTP proxy for web application access.

- Exposed via Istio Gateway HTTPRoute (TLS termination with Let's Encrypt)
- Stateless — any pod handles any request, scaled by HPA
- Direct access to PostgreSQL and Redis
- The only component with the CA private key

### Bridge (Go)

A protocol-agnostic tunnel relay deployed as a StatefulSet. Listens on a single
port (443) for all tunnel traffic. Never interprets the tunneled protocol — it
validates mTLS session certs, matches connections by session ID, and splices
bytes.

- Exposed via Istio Gateway TLSRoute with SNI-based routing (TLS passthrough)
- Each pod gets a dedicated Service for direct SNI routing
- Registers in Redis on startup, renews via heartbeats
- Zero runtime dependencies beyond the BAMF CA public key
- Also relays HTTP proxy traffic from API to agents

### Agent (Go)

Lightweight static binary deployed alongside target resources. Registers with
the API using a join token, receives a certificate, and proxies connections to
target services.

- SSE connection to API for receiving tunnel commands
- On-demand mTLS connections to bridge pods
- Reports heartbeats and resource catalog via SSE
- Auto-detects environment (K8s vs filesystem) for cert storage

### CLI (Go)

Single static binary for end users. Wraps native tools (`ssh`, `scp`, `psql`,
`mysql`) with BAMF tunnel support.

- SSO login via browser (localhost callback)
- Stores certificates in `~/.bamf/keys/`
- All SSH/SCP flags pass through to the native command

### Web UI (Next.js / React)

Single-page application for browser-based management. Resources, sessions,
users, roles, agents, tokens, audit — all managed through the web UI.

## Data Flow

### TCP Tunnels (SSH, Database)

```
CLI ──mTLS──▶ Bridge ◀──mTLS── Agent ──TCP──▶ Target
         (session cert)    (session cert)
```

1. CLI requests session from API
2. API issues session certs for both CLI and agent
3. Both connect to assigned bridge pod via mTLS
4. Bridge matches by session ID, splices connections
5. Data flows end-to-end through the reliable stream

### HTTP Proxy (Web Apps, Kubernetes)

```
Browser ──HTTPS──▶ API (proxy) ──HTTP──▶ Bridge ──gRPC──▶ Agent ──HTTP──▶ Target
                  (auth, RBAC,          (relay)           (forward)
                   rewrite)
```

1. Browser hits `*.tunnel.bamf.example.com`
2. API authenticates (session cookie), checks RBAC
3. API rewrites headers, forwards to assigned bridge
4. Bridge relays to agent via gRPC stream
5. Agent forwards to target web app

## State Management

### PostgreSQL (Durable)

Stores identity and history: users, roles, role assignments, agents, join
tokens, audit logs, session recordings, CA backup.

### Redis (Ephemeral)

Stores runtime state: bridge registrations, agent heartbeats, resource catalog,
active sessions, web sessions, pub/sub for agent commands.

If Redis restarts, all runtime state is automatically rebuilt as components
reconnect and re-register.

## Security Boundaries

- **Public internet → Gateway**: Let's Encrypt TLS
- **Gateway → API/Web UI**: Cluster-internal HTTP
- **CLI/Agent → Bridge**: BAMF CA mTLS (session certs)
- **API → PostgreSQL/Redis**: Cluster-internal TCP
- **Agent → Target**: Direct TCP/HTTP (within agent's network)

Only API pods connect to the database and Redis. Bridges, agents, and CLI
communicate exclusively through the API and through mTLS tunnel connections.
