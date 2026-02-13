# TCP Tunnels

BAMF provides secure access to any TCP service through encrypted tunnels. The
`bamf tcp` command opens a local port that tunnels through the BAMF bridge to
the target — databases, Redis, HTTP APIs, message brokers, or any other TCP
protocol. The bridge is protocol-agnostic; it never interprets the tunneled
traffic.

## How It Works

```
bamf psql orders-db -U admin -d mydb
  └── opens tunnel ──▶ 127.0.0.1:15432 ──▶ bridge ──▶ agent ──▶ postgres:5432
  └── exec's ──▶ psql -h 127.0.0.1 -p 15432 -U admin -d mydb
```

The tunnel stays open while the client process runs. When it exits, the tunnel
closes.

## PostgreSQL

```zsh
# Interactive psql session
bamf psql orders-db -U admin -d mydb

# Run a query
bamf psql orders-db -U admin -d mydb -- -c "SELECT version();"

# With password (from environment)
export BAMF_DB_PASSWORD=secret
bamf psql orders-db -U admin -d mydb

# Specific local port
bamf psql orders-db -U admin -d mydb -p 15432
```

`bamf psql` is a convenience alias for:
```zsh
bamf tcp orders-db --exec "psql -h {host} -p {port} -U admin -d mydb"
```

## MySQL

```zsh
# Interactive mysql session
bamf mysql prod-mysql -u root -D mydb

# Run a query
bamf mysql prod-mysql -u root -D mydb -- -e "SHOW DATABASES;"
```

## Generic TCP Tunnels

For any TCP service — Redis, MongoDB, SMTP, custom protocols:

```zsh
# Open a tunnel with auto-assigned local port
bamf tcp redis-prod
# Prints: Listening on 127.0.0.1:54321

# Specify a local port
bamf tcp redis-prod -p 16379

# With exec template
bamf tcp redis-prod --exec "redis-cli -h {host} -p {port}"

# MongoDB
bamf tcp mongo-prod --exec "mongosh mongodb://{host}:{port}/mydb"
```

### Template Variables

When using `--exec`, these variables are substituted:

| Variable | Description | Source |
|----------|-------------|--------|
| `{host}` | Local listener address | Always `127.0.0.1` |
| `{port}` | Local listener port | Auto-assigned or `-p` flag |
| `{user}` | Username | `-U` / `--user` flag |
| `{password}` | Password | `--password` flag or `BAMF_DB_PASSWORD` env |
| `{dbname}` | Database name | `-d` / `--dbname` flag |

## Long-Running Tunnels

Without `--exec`, the tunnel stays open until you press Ctrl+C. This is useful
for GUI database tools:

```zsh
# Open tunnel in one terminal
bamf tcp orders-db -p 15432
# Listening on 127.0.0.1:15432

# Connect from any tool in another terminal
pgcli -h 127.0.0.1 -p 15432 -U admin -d mydb
# Or use DBeaver, DataGrip, pgAdmin, etc.
```

## Tunnel Resilience

TCP tunnels use a reliable stream protocol that survives bridge pod failures.
If the bridge dies during a database session, the tunnel transparently reconnects
through a different bridge. Your psql or mysql session experiences a brief stall
(1-2 seconds) but does not disconnect.

For details on the reliable stream protocol, see
[Tunnel Architecture](../architecture/tunnels.md).

## HTTP Services (Non-Browser)

`bamf tcp` works for HTTP services too. If you need CLI or programmatic access
to an internal HTTP API (not browser-based), use `bamf tcp` to open a local
port and point your HTTP client at it:

```zsh
# Open tunnel to an internal API
bamf tcp internal-api -p 18080

# In another terminal, use curl, httpie, or any HTTP client
curl http://127.0.0.1:18080/api/health
http GET http://127.0.0.1:18080/api/users

# Or with --exec for one-shot requests
bamf tcp internal-api --exec "curl -s http://{host}:{port}/api/status"
```

This is useful for:
- Internal REST APIs that don't need browser access
- Health checks and monitoring scripts
- CI/CD pipelines that need to reach internal services
- Any HTTP service where you want CLI access instead of browser access

For browser-based access to web applications (with session cookies, CORS
handling, and identity injection), use the [web app proxy](web-apps.md) instead.

## Troubleshooting

**"Connection refused on local port"** — The tunnel process may have exited.
Check for error messages and ensure the resource is accessible.

**"Tunnel timeout"** — The agent has 30 seconds to establish the tunnel. If
the agent is slow to respond, it may be under heavy load or experiencing
network issues.

**"Port already in use"** — Another process is using the requested local port.
Use a different port with `-p` or let BAMF auto-assign one.
