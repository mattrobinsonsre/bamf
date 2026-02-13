# SSH Access

BAMF provides SSH access through encrypted tunnels with short-lived certificates.
Unlike Teleport, BAMF does not reimplement SSH — it wraps your system's native
`ssh`, `scp`, and `sftp` commands, so all flags and configuration work unchanged.

## How It Works

```
bamf ssh user@server
  └── internally exec's ──▶ ssh -o ProxyCommand="bamf tunnel %h %p" \
                                -o UserKnownHostsFile=~/.bamf/known_hosts \
                                user@server
```

`bamf tunnel` handles the BAMF-specific parts:
1. Reads your cached certificate from `~/.bamf/keys/`
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
  ProxyCommand bamf tunnel %h %p
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

## Session Recording

SSH sessions are recorded in asciicast v2 format and can be played back in the
web UI. Recording is transparent — the user experience is identical to a normal
SSH session.

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
