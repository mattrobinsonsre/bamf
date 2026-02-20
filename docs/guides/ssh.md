# SSH Access

BAMF provides SSH access through encrypted tunnels with short-lived certificates.
Unlike Teleport, BAMF does not reimplement SSH — it wraps your system's native
`ssh`, `scp`, and `sftp` commands, so all flags and configuration work unchanged.

## How It Works

```
bamf ssh user@server
  └── internally exec's ──▶ ssh -o ProxyCommand="bamf pipe %h %r" \
                                -o UserKnownHostsFile=~/.bamf/known_hosts \
                                user@server
```

`bamf pipe` handles the BAMF-specific parts:
1. Reads your cached session credentials from `~/.bamf/credentials.json`
2. Connects to the assigned bridge via mTLS
3. Becomes a stdio pipe — stdin/stdout splice to the tunnel

The actual SSH session runs through your system's `ssh` binary.

## Prerequisites

- BAMF CLI installed and logged in (`bamf login`)
- An SSH resource registered by an agent
- Appropriate role granting access to the resource

## Basic Usage

```zsh
# SSH to a resource
bamf ssh user@web-prod-01

# With a specific identity file
bamf ssh -i ~/.ssh/id_ed25519 user@web-prod-01

# Run a remote command
bamf ssh user@web-prod-01 "uptime"
```

## SCP

```zsh
# Copy file to remote
bamf scp ./local-file.txt user@web-prod-01:/tmp/

# Copy file from remote
bamf scp user@web-prod-01:/var/log/app.log ./

# Recursive copy
bamf scp -r ./config/ user@web-prod-01:/etc/myapp/
```

## SFTP

```zsh
bamf sftp user@web-prod-01
```

## Port Forwarding

All SSH port forwarding flags pass through unchanged:

```zsh
# Local port forward
bamf ssh -L 8080:localhost:80 user@web-prod-01

# Remote port forward
bamf ssh -R 9090:localhost:3000 user@web-prod-01

# Dynamic SOCKS proxy
bamf ssh -D 1080 user@web-prod-01
```

## SSH Config Integration

You can use BAMF directly in your `~/.ssh/config`:

```
Host *.prod
  ProxyCommand bamf pipe %h %r
  UserKnownHostsFile ~/.bamf/known_hosts
```

After this, plain `ssh user@web-prod-01.prod` routes through BAMF automatically.

## Host Key Verification

Agents present host certificates signed by the BAMF CA. After `bamf login`,
the CA is added to `~/.bamf/known_hosts`:

```
@cert-authority * <BAMF CA public key>
```

This eliminates per-host TOFU (Trust On First Use) prompts while maintaining
cryptographic verification of host identity.

## Session Recording (`ssh-audit`)

SSH session recording is opt-in via the `ssh-audit` resource type. When an agent
resource is configured as `type: ssh-audit` (instead of `type: ssh`), the bridge
terminates the SSH connection and records terminal I/O in asciicast v2 format
before re-originating the connection to the target.

The user experience is identical to a normal SSH session — `bamf ssh` works the
same way regardless of resource type.

### Configuration

Configure per resource in the agent config:

```yaml
resources:
  # Regular SSH — end-to-end encrypted, reliable stream, no recording
  - name: dev-server
    type: ssh
    hostname: dev.internal

  # Recorded SSH — bridge terminates SSH, records session, no reliable stream
  - name: prod-server
    type: ssh-audit
    hostname: prod.internal
```

Both resource types can coexist on the same agent, even pointing at the same
target host. This lets administrators offer both options and choose per-resource
based on whether audit trail or connection resilience matters more.

### Authentication

`ssh-audit` supports two authentication methods to the target server:

**Key-based auth (recommended):** If the user has an SSH agent running
(`SSH_AUTH_SOCK`), the CLI sends the agent's public keys to the bridge during a
pre-flight phase. The bridge authenticates to the target by requesting signatures
from the CLI's SSH agent — the private key never leaves the user's machine. This
is transparent: the user runs `bamf ssh user@resource` and key auth happens
automatically.

**Password auth (fallback):** If no SSH agent is available (or it has no keys),
the bridge captures the password from the user's SSH client during the SSH
handshake and replays it to the target. This requires the user to type their
password interactively — piped or scripted sessions without an SSH agent will
fail.

**Requirement:** For key-based auth, the user must have an SSH agent running with
at least one key loaded, and the target server must have the corresponding public
key in its `authorized_keys`. On macOS, the system SSH agent is typically running
by default. On Linux, start one with `eval $(ssh-agent)` and add keys with
`ssh-add`.

### What Gets Recorded

- **Terminal output (stdout/stderr)** from the target is recorded in asciicast v2
  format (JSON-lines, compatible with [asciinema](https://asciinema.org/)).
- **User input (stdin) is NOT recorded** — this prevents passwords, tokens, and
  other secrets typed during the session from appearing in the recording.
- **PTY metadata** is captured: terminal dimensions, resize events, TERM value.
- Sessions without a PTY (e.g., `bamf ssh user@host "command"`) are also
  recorded — the command output is captured with default 80x24 dimensions.

### Limitations vs Regular `ssh`

| Feature | `ssh` | `ssh-audit` |
|---------|-------|-------------|
| Session recording | No | Yes (asciicast v2) |
| Survives bridge failure | Yes (reliable stream) | No (SSH state in bridge) |
| Port forwarding (`-L`, `-R`, `-D`) | Yes | **No** (blocked to prevent audit bypass) |
| Key-based auth | Yes (end-to-end) | Yes (via remote signing) |
| Password auth | Yes (end-to-end) | Yes (capture/replay) |
| SCP / SFTP | Yes | Yes (file transfers work, content not recorded) |
| Non-interactive / scripted | Yes | Requires SSH agent (no password prompt without terminal) |
| Agent forwarding (`-A`) | Yes | No (bridge terminates SSH) |

**Port forwarding is blocked** on `ssh-audit` sessions because a forwarded port
would allow users to tunnel an unrecorded connection through the audited session,
bypassing the recording entirely.

**Agent forwarding (`-A`) does not work** because the bridge terminates the SSH
connection — there is no end-to-end SSH session to forward the agent through.
The user's SSH agent is used only during the pre-flight authentication phase.

### Trade-offs

Choose the resource type based on your requirements:

- **Use `ssh`** for developer access, interactive debugging, and any scenario
  where connection resilience and full SSH features matter more than recording.
  The audit log still records who connected, when, and for how long.

- **Use `ssh-audit`** for production access, compliance-sensitive environments,
  and any scenario where a full terminal recording is required. Accept that
  sessions are tied to the bridge pod's lifetime and port forwarding is disabled.

## Browser-Based SSH

If you don't have the BAMF CLI installed, you can access SSH resources directly
from the web UI. Click the **Terminal** button on any SSH resource card in the
dashboard. You'll be prompted to upload your SSH private key (which is sent to
the bridge in memory and never stored) and enter a username.

For details, see the [Web Terminal guide](web-terminal.md).

## Troubleshooting

**"Permission denied"** — Check that your role grants access to the resource.
Run `bamf resources` to see which resources you can access.

**"No route to resource"** — The agent hosting the resource may be offline.
Check the Agents page in the web UI.

**"Certificate expired"** — Run `bamf login` to get a new certificate.
User certificates are valid for 12 hours by default.

**SSH flags not working** — BAMF passes all flags through to the native `ssh`
command. If a flag works with `ssh` directly, it works with `bamf ssh`. If
you're having trouble, try running with `--debug` to see the actual `ssh`
command being executed.

