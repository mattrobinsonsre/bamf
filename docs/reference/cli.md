# CLI Reference

The `bamf` CLI is a single static binary for secure infrastructure access.

## Global Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `~/.bamf/config.yaml` | Config file path |
| `--api` | From config | BAMF API server URL |
| `--debug` | `false` | Enable debug logging |
| `--json` | `false` | Machine-readable JSON output |

## Authentication

### bamf login

Authenticate with a BAMF cluster. Opens browser for SSO or local login.

```
bamf login [--provider NAME]
```

| Flag | Default | Description |
|------|---------|-------------|
| `--provider` | From config (`default_provider`) | Auth provider name |

After login, credentials are stored in `~/.bamf/keys/`.

### bamf logout

Clear local credentials and end the session.

```
bamf logout
```

### bamf status

Show current authentication status, certificate expiry, and connection info.

```
bamf status
```

## SSH Access

### bamf ssh

SSH to a resource. Wraps the native `ssh` command via ProxyCommand.

```
bamf ssh [ssh-flags...] [user@]<resource> [command]
```

All standard `ssh` flags pass through unchanged. Examples:

```zsh
bamf ssh user@web-prod-01
bamf ssh -L 8080:localhost:80 user@web-prod-01
bamf ssh -i ~/.ssh/id_ed25519 user@web-prod-01 "uptime"
```

### bamf scp

Copy files via SCP. Wraps the native `scp` command.

```
bamf scp [scp-flags...] <source> <destination>
```

```zsh
bamf scp ./file.txt user@web-prod-01:/tmp/
bamf scp -r ./config/ user@web-prod-01:/etc/myapp/
```

### bamf sftp

SFTP to a resource. Wraps the native `sftp` command.

```
bamf sftp [sftp-flags...] [user@]<resource>
```

## TCP Tunnels

### bamf tcp

Open a TCP tunnel to a resource. For databases, Redis, or any TCP service.

```
bamf tcp <resource> [flags]
```

| Flag | Short | Description |
|------|-------|-------------|
| `--port` | `-p` | Local port to listen on (auto-assigned if omitted) |
| `--user` | `-U` | Username (for `--exec` template) |
| `--password` | | Password (or set `BAMF_DB_PASSWORD` env) |
| `--dbname` | `-d` | Database name (for `--exec` template) |
| `--exec` | | Command to execute with template variables |

Template variables for `--exec`:

| Variable | Description |
|----------|-------------|
| `{host}` | Local listener address (`127.0.0.1`) |
| `{port}` | Local listener port |
| `{user}` | From `--user` flag |
| `{password}` | From `--password` flag or env |
| `{dbname}` | From `--dbname` flag |

```zsh
# Open tunnel, print local port
bamf tcp redis-prod

# Specific port
bamf tcp redis-prod -p 16379

# With exec template
bamf tcp redis-prod --exec "redis-cli -h {host} -p {port}"
bamf tcp mongo-prod --exec "mongosh mongodb://{host}:{port}/mydb"
```

Without `--exec`, the tunnel stays open until Ctrl+C.

### bamf psql

Convenience alias for `bamf tcp --exec "psql ..."`.

```
bamf psql <resource> [-U user] [-d dbname] [-p port] [-- psql-args...]
```

```zsh
bamf psql orders-db -U admin -d mydb
bamf psql orders-db -U admin -d mydb -- -c "SELECT version();"
```

### bamf mysql

Convenience alias for `bamf tcp --exec "mysql ..."`.

```
bamf mysql <resource> [-u user] [-D dbname] [-p port] [-- mysql-args...]
```

```zsh
bamf mysql prod-mysql -u root -D mydb
bamf mysql prod-mysql -u root -D mydb -- -e "SHOW DATABASES;"
```

### bamf pipe

Pipe stdin/stdout through a tunnel. Used internally by ProxyCommand.

```
bamf pipe <resource>
```

## Kubernetes

### bamf kube login

Write a kubeconfig entry for a Kubernetes cluster accessed through BAMF.

```
bamf kube login <resource-name>
```

After this, `kubectl --context <resource-name>` routes through BAMF.

### bamf kube-credentials

Exec credential plugin invoked automatically by kubectl. Not typically called
directly.

```
bamf kube-credentials
```

## Resource Management

### bamf resources

List accessible resources.

```
bamf resources
```

### bamf agents

List registered agents (admin only).

```
bamf agents
```

## Token Management

### bamf tokens list

List join tokens (admin only).

```
bamf tokens list
```

### bamf tokens create

Create a new join token for agent registration.

```
bamf tokens create [flags]
```

| Flag | Description |
|------|-------------|
| `--name` | Token name (required) |
| `--expires-in` | Validity in hours (default: 24) |
| `--max-uses` | Maximum uses before expiry |
| `--labels` | Labels to apply to agents (key=value,...) |

### bamf tokens revoke

Revoke a join token.

```
bamf tokens revoke <token-name>
```

## Utility

### bamf version

Print version, git commit, and build time.

```
bamf version
```

## Configuration File

`~/.bamf/config.yaml`:

```yaml
api: https://bamf.example.com
# provider: auth0  # default auth provider
```

## Credential Storage

```
~/.bamf/
├── config.yaml      # CLI configuration
├── keys/            # User certificates (0700)
├── ca.crt           # BAMF CA public cert
└── known_hosts      # SSH host key cache
```
