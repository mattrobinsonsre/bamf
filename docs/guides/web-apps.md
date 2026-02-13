# Web Application Access

BAMF provides secure browser-based access to internal web applications (Grafana,
Jenkins, ArgoCD, internal tools) through an HTTP reverse proxy with per-request
authentication, RBAC, header rewriting, and audit logging.

## How It Works

```
Browser ──▶ https://grafana.tunnel.bamf.example.com
  └── Istio Gateway (TLS termination, wildcard cert)
  └── API proxy routes (auth, RBAC, header rewriting)
  └── Bridge (HTTP relay)
  └── Agent (forward to target)
  └── http://grafana.internal.corp:3000
```

Each web application gets a unique `*.tunnel.bamf.example.com` hostname.
The API proxy handles authentication, authorization, and header rewriting so
the target application is unaware of the tunnel.

## Resource Configuration

Register a web application as an HTTP resource in the agent config:

```yaml
# Agent config
resources:
  http:
    name: grafana
    tunnel_hostname: grafana       # becomes grafana.tunnel.bamf.example.com
    host: grafana.internal.corp    # internal hostname the agent connects to
    port: 3000
    protocol: http                 # http or https (agent → target)
    labels:
      env: prod
      team: platform
```

The `tunnel_hostname` must be unique across all resources and follows DNS label
rules: lowercase alphanumeric and hyphens, starting with a letter, max 63
characters.

## Accessing Web Apps

Once the resource is registered and accessible via your role:

1. Navigate to `https://grafana.tunnel.bamf.example.com` in your browser
2. If not authenticated, you'll be redirected to the BAMF login page
3. After login, a session cookie is set for `*.tunnel.bamf.example.com`
4. You're redirected back to the application

Subsequent requests use the session cookie — no additional authentication needed
until the session expires.

## Header Rewriting

The API proxy rewrites headers in both directions so the target application works
correctly through the tunnel:

### Request Headers (browser → target)

| Header | Rewrite |
|--------|---------|
| `Host` | `grafana.tunnel.bamf.example.com` → `grafana.internal.corp` |
| `Origin` | `https://grafana.tunnel.bamf.example.com` → `http://grafana.internal.corp:3000` |
| `X-Forwarded-User` | Injected with authenticated user's display name |
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
| `Content-Security-Policy` | Absolute URLs rewritten from target to tunnel hostname |

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

## Infrastructure Requirements

- **Wildcard DNS**: `*.tunnel.bamf.example.com` → Istio Gateway IP
- **Wildcard TLS cert**: cert-manager with DNS-01 challenge for
  `*.tunnel.bamf.example.com`, referenced by the Gateway listener
- **Istio Gateway HTTPRoute**: Routes `*.tunnel.bamf.example.com` to the
  API Service (same service as the main API)

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
