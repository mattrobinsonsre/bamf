# File Share Access (SMB/CIFS)

BAMF provides secure access to SMB/CIFS file shares through TCP tunnels. The
`bamf tcp` command opens a local port that tunnels to the target file server —
your SMB client connects to the local port as if it were the real server.

The bridge is protocol-agnostic; it relays SMB traffic as raw bytes. SMB
signing and encryption (SMB3) work end-to-end through the tunnel, unchanged.

## How It Works

```
mount_smbfs //user@127.0.0.1:1445/share /mnt/share
  └── local port 1445 ──▶ bridge ──▶ agent ──▶ file-server:445
```

The tunnel stays open until you press Ctrl+C or unmount the share.

## Agent Configuration

Register the file server as a `tcp` resource in the agent config:

```yaml
resources:
  - name: file-server
    type: tcp
    hostname: fs.internal.corp
    port: 445
    labels:
      env: prod
      team: engineering
```

> **Note:** There is no dedicated `smb` resource type. File shares use the
> generic `tcp` resource type, which tunnels raw bytes without interpreting
> the protocol. SMB signing and encryption work end-to-end through the tunnel.

## macOS

macOS natively supports SMB connections on custom ports.

### Using Finder

```zsh
# Open a tunnel to the file server
bamf tcp file-server -p 1445

# In Finder: Go → Connect to Server (⌘K)
# Enter: smb://username@127.0.0.1:1445/sharename
```

### Using the command line

```zsh
# Mount via tunnel (background the tunnel with -b)
bamf tcp file-server -p 1445 -b
mount_smbfs //user@127.0.0.1:1445/share /Volumes/share

# Or use smbutil
smbutil view //user@127.0.0.1:1445
```

### With `--exec`

```zsh
bamf tcp file-server -p 1445 \
  --exec "smbclient //{host}/share -p {port} -U {user}" -U admin
```

## Linux

Linux `mount.cifs` supports the `port=` mount option.

```bash
# Open the tunnel
bamf tcp file-server -p 1445

# Mount (requires root or CAP_SYS_ADMIN)
sudo mount -t cifs //127.0.0.1/share /mnt/share \
  -o port=1445,username=admin,password=secret

# Or use smbclient
smbclient //127.0.0.1/share -p 1445 -U admin
```

### Persistent mount

```bash
# Start the tunnel in background mode
bamf tcp file-server -p 1445 -b

# Add to /etc/fstab
# //127.0.0.1/share /mnt/share cifs port=1445,credentials=/etc/smbcreds 0 0
```

## Windows

Windows SMB access through a tunnel requires different approaches depending
on the Windows version, because the built-in SMB client historically only
connects to port 445 with no way to specify an alternative port.

### Windows 11 24H2+ / Server 2025

Windows 11 24H2 and later support custom SMB ports natively.

```powershell
# Open the tunnel (in a separate terminal)
bamf tcp file-server -p 1445

# Map a drive using the custom port
NET USE Z: \\127.0.0.1\share /TCPPORT:1445 /USER:admin

# Or with PowerShell
New-SmbMapping -LocalPath Z: -RemotePath \\127.0.0.1\share -TcpPort 1445
```

To disconnect:

```powershell
NET USE Z: /DELETE
```

### Older Windows Versions (Pre-24H2)

On older Windows, the SMB client cannot connect to non-standard ports. The
workaround uses `netsh portproxy` to redirect `127.0.0.1:445` to a higher
port where the BAMF tunnel listens. This requires a **one-time administrator
setup** that survives reboots.

#### One-time setup (as Administrator)

The Windows `LanmanServer` service binds `0.0.0.0:445` on startup, which
blocks all loopback addresses. The trick is to make the IP Helper service
(`iphlpsvc`) start before `LanmanServer` and claim the loopback port first
via a portproxy rule.

```powershell
# 1. Add iphlpsvc as a dependency of LanmanServer
sc.exe config lanmanserver depend= samss/srv2/iphlpsvc

# 2. Create a portproxy rule: 127.0.0.1:445 → 127.0.0.1:44445
netsh interface portproxy add v4tov4 `
  listenaddress=127.0.0.1 listenport=445 `
  connectaddress=127.0.0.1 connectport=44445

# 3. Reboot to apply the service dependency change
Restart-Computer
```

After reboot, `iphlpsvc` starts first and claims `127.0.0.1:445` for
portproxy. `LanmanServer` still binds `0.0.0.0:445` for real network
interfaces, so local file sharing continues to work on all other addresses.

#### Daily use (after one-time setup)

```powershell
# Open the tunnel on the portproxy target port
bamf tcp file-server -p 44445

# Access the share normally — portproxy routes 445 → 44445 → tunnel
NET USE Z: \\127.0.0.1\share /USER:admin
```

The user doesn't need to know about the portproxy — they use standard UNC
paths with `127.0.0.1`.

> **Limitation:** The portproxy approach only supports one file server at a
> time on older Windows, because `bamf tcp` always binds to `127.0.0.1` and
> there is only one portproxy rule for `127.0.0.1:445`. To access multiple
> file servers, upgrade to Windows 11 24H2+ which supports custom ports
> natively via `/TCPPORT:`, or disconnect and reconnect between servers.

#### Verify portproxy rules

```powershell
netsh interface portproxy show v4tov4
```

#### Remove portproxy rules

```powershell
netsh interface portproxy delete v4tov4 listenaddress=127.0.0.1 listenport=445
sc.exe config lanmanserver depend= samss/srv2
```

## SMB Protocol Considerations

### Authentication

When connecting through a tunnel to `127.0.0.1`, Windows uses **NTLM**
authentication (not Kerberos). Kerberos requires the client to construct a
service principal name (`cifs/hostname`) from the UNC path, and IP addresses
trigger NTLM fallback.

This is acceptable for tunnel scenarios — BAMF authenticates the user before
establishing the tunnel. The SMB authentication is between the client and
the file server through the encrypted tunnel.

If your environment requires Kerberos for SMB, a tunnel through BAMF is not
compatible. Consider accessing the file server through an RDP session on a
machine with native network access, where Kerberos works normally.

### SMB Multichannel

SMB3 Multichannel causes the client to discover and use multiple network paths
to the server. When connecting through a tunnel, the client should not find
alternative paths. However, if the server advertises its real IP addresses in
the multichannel negotiate response, the client might attempt direct connections
that bypass the tunnel.

To prevent this, disable multichannel on the client:

```powershell
# Windows (as Administrator)
Set-SmbClientConfiguration -EnableMultichannel $false
```

Or on the server:

```powershell
Set-SmbServerConfiguration -EnableMultichannel $false
```

On Linux, multichannel is controlled by the `multichannel` mount option
(disabled by default in most distributions).

### SMB Encryption (SMB3)

SMB3 encryption works end-to-end through the tunnel. The bridge sees only
encrypted bytes. This is fully compatible — the BAMF tunnel provides transport
encryption (mTLS), and SMB3 provides application-layer encryption on top.

### SMB Signing

SMB signing operates at the session level using keys derived during
authentication. A byte-level relay does not interfere with signing because
signatures are computed over message content that passes through the tunnel
unchanged.

## Tunnel Resilience

SMB file share tunnels use the same reliable stream protocol as database
tunnels. If the bridge pod dies during a file transfer, the tunnel
transparently reconnects through a different bridge. Active file transfers
experience a brief stall (1-2 seconds) but do not fail.

For details, see [Tunnel Architecture](../architecture/tunnels.md).

## Troubleshooting

**"Port already in use" on port 445 (Windows)** — The `LanmanServer` service
is holding port 445. Follow the [one-time setup](#one-time-setup-as-administrator)
instructions for the portproxy workaround, or upgrade to Windows 11 24H2+
which supports custom SMB ports natively.

**"Access denied" when mounting** — The SMB authentication is between your
client and the target file server. Verify your credentials are correct for the
target server. BAMF does not intercept or modify SMB authentication.

**Kerberos errors** — Tunnel connections use `127.0.0.1`, which forces NTLM
fallback. If the server requires Kerberos (`NTLMv2` disabled), the connection
will fail. See [Authentication](#authentication) above.

**Slow file transfers** — Check if SMB Multichannel is enabled and attempting
connections that bypass the tunnel. See [SMB Multichannel](#smb-multichannel).

**"The specified network name is no longer available"** — The tunnel may have
closed. Verify `bamf tcp` is still running in the other terminal. If the
tunnel was interrupted, unmount and remount after re-establishing the tunnel.

## Future: `bamf smb` Shorthand

If there is community interest, a `bamf smb` convenience command could be
added — similar to how `bamf psql` and `bamf mysql` wrap `bamf tcp --exec`.
A dedicated command could automate port selection, platform-specific mount
instructions, and the Windows portproxy setup. If this would be useful to you,
open an issue on the [GitHub repository](https://github.com/mattrobinsonsre/bamf/issues).
