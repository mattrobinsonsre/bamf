# Web Terminal

The BAMF web terminal provides browser-based interactive access to SSH servers
and databases directly from the web UI. No local SSH client, psql, or mysql
installation is required.

It is intended for users who need occasional access without a local toolchain:
Windows users, managers auditing a system, or anyone who does not have `bamf`
installed locally.

Supported resource types: `ssh`, `ssh-audit`, `postgres`, `postgres-audit`,
`mysql`, `mysql-audit`.

---

## SSH Access

1. Open the BAMF web UI and navigate to **Resources**.
2. Find the SSH resource and click **Terminal**.
3. In the connection dialog, enter a username and one of:
   - **Password** — typed directly in the form.
   - **Private key** — click **Upload key** and select a file. Accepted
     formats: `.pem`, `.key`, `.id_rsa`, `.id_ed25519` (OpenSSH or PEM-encoded
     RSA/Ed25519 private keys).
4. Click **Connect**. An xterm.js terminal opens in the browser.

**Key handling:** The private key is transmitted over TLS to the bridge, used
for the SSH handshake with the target, and then zeroed from memory. It is never
written to disk or persisted anywhere in the BAMF infrastructure.

**Session recording:** Web SSH sessions on `ssh-audit` resources are recorded in
asciicast v2 format, the same as CLI `ssh-audit` sessions. The recording is
uploaded to the audit log on session close and is playable from the **Audit**
section of the web UI. Sessions on plain `ssh` resources are not recorded — the
audit log captures connection metadata (who, when, duration) but not terminal
content.

---

## Database Access (PostgreSQL)

1. Find the postgres or postgres-audit resource and click **Terminal**.
2. Enter:
   - **Username** — the database user.
   - **Database** — the database name to connect to.
   - **Password** — the user's password.
3. Click **Connect**. A `psql` session opens in the browser terminal.

The password is passed to `psql` via the `PGPASSWORD` environment variable
inside the bridge container. The variable is cleared from the process
environment immediately after the connection is established.

**Query audit:** Resources of type `postgres-audit` automatically capture SQL
queries via passive wire protocol tapping, the same as CLI `bamf psql` sessions
on audit resources. Captured queries appear in the audit log alongside other
BAMF events.

---

## Database Access (MySQL)

The flow is identical to PostgreSQL. The bridge uses the `mysql` client
instead of `psql`, and the password is passed via the `MYSQL_PWD` environment
variable, which is cleared after the connection is established.

**Query audit:** Resources of type `mysql-audit` capture SQL queries the same
way as `postgres-audit` — see above.

---

## Reconnection

The browser WebSocket connection to the BAMF API will attempt to reconnect
automatically if the connection drops due to a brief network interruption or
an API pod restart. Reconnect attempts use exponential backoff and are capped
at three attempts. A status indicator in the terminal header shows the
reconnection state.

The bridge holds the session open with a 30-second reconnect timeout. If the
browser reconnects within that window, the session resumes without interruption.
If the timeout expires, the session is terminated and the terminal displays a
disconnect message.

If the bridge pod itself is replaced (crash, scale-in, spot termination), the
session cannot be recovered. This is the same limitation that applies to
`ssh-audit` sessions in the CLI — web terminal sessions do not use the reliable
stream protocol because the bridge must terminate the SSH or database connection
to run the client binary. The terminal will display escalating warnings if the
bridge pod is draining, giving you time to save any in-progress work.

---

## Limitations

- **No SSH agent forwarding.** Private keys must be uploaded directly in the
  connection dialog. Agent forwarding from the browser is not supported.
- **No reliable stream.** Bridge pod failure terminates the session. For
  long-running sessions where resilience matters, use `bamf ssh` from the
  CLI instead, which uses the reliable stream over a TCP tunnel.
- **Copy/paste is browser-controlled.** Use the browser's standard copy/paste
  shortcuts (Ctrl+Shift+C / Ctrl+Shift+V on Linux/Windows, Cmd+C / Cmd+V on
  macOS). Right-click paste may not work in all browsers.
- **Bridge image requires Alpine.** The bridge container must be built from
  the Alpine-based image (not the scratch-based image) so that the `psql` and
  `mysql` client binaries are available. The Helm chart defaults to the Alpine
  image when the web terminal feature is enabled.

---

## Security

**WebSocket authentication:** When the browser requests a terminal session,
the API issues a one-time WebSocket ticket stored in Redis with a 60-second
TTL. The ticket is consumed on first use (`GETDEL`) and cannot be reused. The
WebSocket connection is rejected if the ticket is absent, expired, or already
consumed.

**SSH keys:** The private key travels from the browser to the bridge over TLS
(the same public HTTPS certificate used for the rest of the BAMF API). Inside
the bridge, the key is held in memory only for the duration of the SSH
handshake. After the handshake, the key material is overwritten with zeros
before the memory is released. It is never written to disk, logged, or sent to
any other component.

**Database passwords:** Passwords are transmitted over TLS to the bridge and
injected into the client process via environment variable. The environment
variable is cleared from the bridge process's environment immediately after the
client process starts.

**Session recording:** The same audit classification applies to web terminals as
to CLI sessions. `ssh-audit` resources record the SSH terminal session
(asciicast v2). `postgres-audit` and `mysql-audit` resources capture SQL queries
via passive wire protocol tapping. In all cases the behaviour is identical
whether accessed from the CLI or the browser. The audit log entry identifies the
access method and the authenticated user.
