# TCP Tunnels

BAMF provides secure access to any TCP service through encrypted tunnels. The
`bamf tcp` command opens a local port that tunnels through the BAMF bridge to
the target — databases, Redis, message brokers, or any other non-HTTP TCP
protocol. The bridge is protocol-agnostic; it never interprets the tunneled
traffic.

For HTTP services, use the [HTTP proxy](web-apps.md) instead — it provides
per-request authentication, RBAC, audit logging, and header rewriting for both
browser and non-browser clients.

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

## Query Audit (`postgres-audit`, `mysql-audit`)

Database query audit is opt-in via the `-audit` resource types. When a resource
is configured as `postgres-audit` or `mysql-audit`, the bridge passively taps the
byte stream flowing through the tunnel and extracts SQL queries from the database
wire protocol. Queries are logged as structured audit events.

Unlike SSH session recording (which requires the bridge to terminate SSH), database
audit uses **passive tapping** — the bridge remains a transparent byte relay. This
means:

- The reliable stream still works (sessions survive bridge failure)
- The client authenticates directly with the database (no credential capture)
- `bamf psql` / `bamf mysql` work identically to non-audit tunnels
- The user experience is unchanged

### Configuration

```yaml
resources:
  # Regular database tunnel — no query logging
  - name: dev-db
    type: postgres
    hostname: dev-db.internal
    port: 5432

  # Audited database tunnel — queries logged
  - name: prod-db
    type: postgres-audit
    hostname: prod-db.internal
    port: 5432

  # MySQL equivalent
  - name: prod-mysql
    type: mysql-audit
    hostname: prod-mysql.internal
    port: 3306
```

### What Gets Logged

Each SQL query is logged as a structured audit event:

- **Query text** (including prepared statement templates)
- **Parameter values** (when using prepared statements)
- **Timestamp, user, resource, database user**
- **Duration and row count** (from server responses)

Logged queries appear in the audit log alongside other BAMF events (SSH sessions,
login events, etc.).

### Limitations

- **Client-initiated TLS is blocked** on `-audit` types. The BAMF tunnel is
  already mTLS-encrypted, so client-to-database TLS is redundant. If your
  database client insists on TLS (e.g., `sslmode=require` in psql), either
  switch to `sslmode=prefer` (which falls back gracefully) or use the non-audit
  resource type.
- **Binary protocol parameters** (PostgreSQL extended query with binary format
  codes) appear as hex in the audit log rather than decoded values.
- **Bulk operations** (PostgreSQL `COPY`, large batch inserts) may generate high
  audit log volume.

### Comparison of Audit Types

| Feature | `postgres` / `mysql` | `postgres-audit` / `mysql-audit` | `ssh` | `ssh-audit` | `http` | `http-audit` |
|---------|---------------------|----------------------------------|-------|-------------|--------|--------------|
| Recording | No | Yes (structured queries) | No | Yes (terminal) | No | Yes (HTTP exchanges) |
| Survives bridge failure | Yes | Yes | Yes | No | N/A | N/A |
| Client TLS to target | Yes | No (blocked) | N/A | N/A | N/A | N/A |
| User experience change | None | None | None | None | None | None |

## Browser-Based Database Access

If you don't have the BAMF CLI installed, you can access PostgreSQL and MySQL
resources directly from the web UI. Click the **Terminal** button on any database
resource card in the dashboard. You'll be prompted for database credentials, then
a `psql` or `mysql` interactive session opens in the browser.

For details, see the [Web Terminal guide](web-terminal.md).

## Troubleshooting

**"Connection refused on local port"** — The tunnel process may have exited.
Check for error messages and ensure the resource is accessible.

**"Tunnel timeout"** — The agent has 30 seconds to establish the tunnel. If
the agent is slow to respond, it may be under heavy load or experiencing
network issues.

**"Port already in use"** — Another process is using the requested local port.
Use a different port with `-p` or let BAMF auto-assign one.

