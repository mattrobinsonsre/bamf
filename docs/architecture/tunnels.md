# Tunnel Architecture

BAMF tunnels are protocol-agnostic encrypted channels between the CLI and target
resources. The bridge is a transparent byte relay — it never interprets the
tunneled protocol.

## Tunnel Setup

```
1. CLI calls API: POST /connect with resource name
2. API validates RBAC, selects bridge, issues session certs
3. API notifies agent via SSE: dial bridge with session cert
4. CLI connects to bridge via mTLS (session cert)
5. Agent connects to bridge via mTLS (session cert)
6. Bridge matches by session ID, splices connections
```

### Session Certificates

Each tunnel session uses short-lived x509 certificates that encode the
authorization decision:

```
SAN URIs:
  bamf://session/{session_id}       — pairs client and agent
  bamf://resource/{resource_name}   — target resource
  bamf://bridge/{bridge_id}         — which bridge to connect to
```

The bridge validates the cert chain against the BAMF CA, reads the SAN URIs,
and matches connections. No runtime API/Redis/database calls needed.

### Bridge Validation

1. Verify cert chain → BAMF CA (reject if invalid or expired)
2. Read `bamf://bridge/{id}` → reject if not this bridge
3. Read `bamf://session/{id}` → hold connection, wait for match
4. When both sides present matching session ID → splice
5. If no match within 30s → close connection

## Reliable Stream Protocol

TCP tunnels use an end-to-end reliable stream between CLI and agent that
survives bridge pod failure. The bridge remains a transparent byte relay.

### Frame Format

```
┌──────────────────────────────────────────────────┐
│  [8-byte sequence number][4-byte length][payload]│
└──────────────────────────────────────────────────┘
```

- Each write is immediately wrapped in a frame with a monotonically increasing
  sequence number. No buffering delay — interactive sessions stay responsive.
- Each side periodically sends the last contiguous sequence it received (ACKs).
- Unacknowledged data is kept in a ring buffer (default 4MB).

### Reconnection (Unplanned Bridge Failure)

```
psql ──TCP──▶ CLI ══reliable stream══▶ agent ──TCP──▶ postgres
               │    (survives bridge     │
               │     reconnection)       │
               └──TLS── bridge ──TLS────┘
                   (replaceable relay)
```

1. Bridge pod dies (crash, OOM, spot termination)
2. CLI and agent detect TLS connection break
3. CLI calls API: `POST /connect` with `reconnect_session_id`
4. API selects new bridge, issues new session certs (same session ID)
5. API notifies agent via SSE: dial new bridge
6. Both connect to new bridge, exchange "last received sequence"
7. Both retransmit unACK'd data from ring buffers
8. Stream resumes — application sees brief stall but no disconnect

### Graceful Migration (Planned Drain)

For scale-in, maintenance, or rebalancing:

1. API decides to drain bridge-X
2. API issues new certs for each tunnel, pinned to bridge-Y
3. Bridge-X sends migration command to both endpoints
4. Both sides ACK, pause, drain in-flight data
5. Both disconnect from bridge-X, connect to bridge-Y
6. Stream resumes — no retransmission needed

### Limitations

- **Ring buffer overflow**: If the 4MB buffer fills before ACK (sustained
  high-throughput during a long outage), the session cannot be recovered.
- **Endpoint failure**: The reliable stream only survives bridge failure. If
  the CLI or agent process dies, the session is lost. Use `tmux`/`screen` for
  endpoint persistence.
- **Reconnection timeout**: 30 seconds to reconnect through a new bridge.

## SNI Routing

Each bridge pod gets its own Service and TLSRoute:

```yaml
# TLSRoute for bridge-0
spec:
  hostnames:
    - "bridge-0.tunnel.bamf.example.com"
  rules:
    - backendRefs:
        - name: bamf-bridge-0
          port: 443
```

The Gateway uses TLS passthrough — it inspects the SNI hostname in the
ClientHello without terminating TLS. The bridge pod terminates TLS using its
BAMF CA-issued certificate.

## Infrastructure Requirements

- Wildcard DNS: `*.tunnel.bamf.example.com` → Gateway IP
- Istio Gateway with TLSRoute per bridge pod (SNI passthrough)
- Per-bridge-pod Services (created by Helm loop for 0 to `maxReplicas`)
- Bridges register in Redis on startup (heartbeat with TTL)
