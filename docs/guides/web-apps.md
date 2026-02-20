# HTTP Application Access

BAMF provides secure access to internal HTTP services — web applications,
REST APIs, and any HTTP endpoint — through an HTTP reverse proxy with
per-request authentication, RBAC, header rewriting, and audit logging.

This works for both browser-based access (web apps like Grafana, Jenkins,
ArgoCD) and non-browser access (curl, scripts, CI/CD pipelines).

## How It Works

```
Client ──▶ https://grafana.tunnel.bamf.example.com
  └── Traefik / Istio Gateway (TLS termination, wildcard cert)
  └── API proxy routes (auth, RBAC, header rewriting)
  └── Bridge (HTTP relay)
  └── Agent (forward to target)
  └── http://grafana.internal.corp:3000
```

Each HTTP resource gets a unique `*.tunnel.bamf.example.com` hostname.
The API proxy handles authentication, authorization, and header rewriting so
the target application is unaware of the tunnel. The same proxy serves both
browser clients (session cookies) and non-browser clients (bearer tokens).

## Resource Configuration

Register a web application as an HTTP resource in the agent config:

```yaml
# Agent config
resources:
  - name: grafana
    type: http                       # or http-audit for full request/response recording
    tunnel_hostname: grafana         # becomes grafana.tunnel.bamf.example.com
    host: grafana.internal.corp      # internal hostname the agent connects to
    port: 3000
    labels:
      env: prod
      team: platform
```

The `tunnel_hostname` must be unique across all resources and follows DNS label
rules: lowercase alphanumeric and hyphens, starting with a letter, max 63
characters.

## Browser Access

Once the resource is registered and accessible via your role:

1. Navigate to `https://grafana.tunnel.bamf.example.com` in your browser
2. If not authenticated, you'll be redirected to the BAMF login page
3. After login, a session cookie is set for `*.tunnel.bamf.example.com`
4. You're redirected back to the application

Subsequent requests use the session cookie — no additional authentication needed
until the session expires.

## Non-Browser Access (curl, scripts, CI/CD)

The same proxy URLs work for non-browser HTTP clients. Authenticate with a
bearer token instead of a session cookie:

```zsh
# Log in first
bamf login

# Use the tunnel URL with your session token from ~/.bamf/credentials.json
TOKEN=$(python3 -c "import json; print(json.load(open('$HOME/.bamf/credentials.json'))['session_token'])")
curl -H "Authorization: Bearer $TOKEN" \
  https://internal-api.tunnel.bamf.example.com/api/health
```

For CI/CD pipelines, set the `BAMF_TOKEN` environment variable with a
pre-issued API token, which is used automatically by all HTTP clients.

This is useful for:
- Scripts and automation that need to reach internal HTTP services
- CI/CD pipelines calling internal APIs
- Health checks and monitoring
- Any programmatic HTTP access to internal services

Every request is authenticated, authorized via RBAC, and audit-logged — the
same as browser access.

## Header Rewriting

The API proxy rewrites headers in both directions so the target application works
correctly through the tunnel:

### Request Headers (browser → target)

| Header | Rewrite |
|--------|---------|
| `Host` | `grafana.tunnel.bamf.example.com` → `grafana.internal.corp` |
| `Origin` | `https://grafana.tunnel.bamf.example.com` → `http://grafana.internal.corp:3000` |
| `X-Forwarded-User` | Injected with authenticated user's email |
| `X-Forwarded-Email` | Injected with authenticated user's email |
| `X-Forwarded-Roles` | Injected with user's BAMF roles |
| `X-Forwarded-Host` | Set to `grafana.tunnel.bamf.example.com` (real browser origin) |
| `X-Forwarded-Proto` | Set to `https` |

### Response Headers (target → browser)

| Header | Rewrite |
|--------|---------|
| `Location` | Target hostname → tunnel hostname (for redirects) |
| `Set-Cookie` | Domain rewritten to tunnel hostname |
| `Access-Control-Allow-Origin` | Rewritten to match browser origin |
| `Content-Security-Policy` | Passed through unchanged |

## Identity Injection

Many internal tools support identity injection via HTTP headers. Configure your
target application to trust the `X-Forwarded-Email` header from BAMF:

**Grafana** (`grafana.ini`):
```ini
[auth.proxy]
enabled = true
header_name = X-Forwarded-Email
header_property = email
auto_sign_up = true
```

**Other tools**: Check your application's documentation for proxy authentication
or header-based SSO support.

## HTTP Audit Recording (`http-audit`)

For resources that require full request/response audit trails, use the
`http-audit` resource type instead of `http`:

```yaml
resources:
  - name: admin-panel
    type: http-audit
    tunnel_hostname: admin-panel
    host: admin.internal.corp
    port: 8080
    labels:
      env: prod
```

`http-audit` behaves identically to `http` but additionally captures every HTTP
exchange (request + response headers and bodies) in `http-exchange-v1` format.
Recordings are stored in the `session_recordings` table and viewable in the
audit recordings UI.

**What's captured:**
- Request: method, path, query, headers, body (text up to 256KB; binary bodies
  store size only)
- Response: status, headers, body (same size/binary rules)
- Timing: request duration in milliseconds

**What's not captured:**
- WebSocket frames (only the initial upgrade request/response)
- Streaming responses are captured as a single body after completion

Both `http` and `http-audit` resources still log basic audit events (method,
URI, status code) in the `audit_logs` table. The `http-audit` type adds the
full exchange recording on top.

## Infrastructure Requirements

- **Wildcard DNS**: `*.tunnel.bamf.example.com` → Ingress controller IP
- **Wildcard TLS cert**: cert-manager with DNS-01 challenge for
  `*.tunnel.bamf.example.com`, referenced by the ingress route
- **Ingress routing**: Traefik IngressRoute or Istio HTTPRoute that routes
  `*.tunnel.bamf.example.com` to the API Service

## Troubleshooting

**"Redirect loop"** — The target app may be redirecting to its own login page.
Configure it to trust the identity headers from BAMF instead.

**"CORS errors"** — The proxy rewrites CORS headers, but if the target app
has strict CORS policies, you may need to configure it to allow the tunnel
hostname.

**"Mixed content warnings"** — The tunnel uses HTTPS, but the target app may
generate HTTP URLs. The proxy rewrites `Location` and `Set-Cookie` headers,
but inline URLs in HTML/JS are not modified. Configure the target app to use
relative URLs or to respect `X-Forwarded-Proto: https`.
