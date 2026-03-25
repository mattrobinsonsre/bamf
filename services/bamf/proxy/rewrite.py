"""Header rewriting for HTTP proxy requests and responses.

Guide: docs/guides/web-apps.md (Header Rewriting section)

Request headers are rewritten before sending to the target (via bridge relay):
- Host, Origin → target's internal hostname
- Inject X-Forwarded-*, identity headers, X-Bamf-Target

Response headers are rewritten before returning to the browser:
- Location redirects → tunnel hostname
- Set-Cookie domain → tunnel hostname
- CORS origin → tunnel hostname
"""

from __future__ import annotations

# Hop-by-hop headers that should not be forwarded on requests.
# Note: "upgrade" is intentionally excluded — it must be preserved for
# WebSocket requests. The Connection header is also selectively preserved
# when it carries "Upgrade".
# content-length and content-encoding are NOT stripped from requests — the
# target needs them to correctly parse the request body.
# accept-encoding is stripped because the proxy chain cannot transparently
# handle all encodings (e.g., brotli). Target apps must return uncompressed
# bodies; the ingress controller handles browser-facing compression.
_HOP_BY_HOP_REQUEST = frozenset(
    {
        "accept-encoding",
        "connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "proxy-authorization",
        "proxy-authenticate",
    }
)

# Hop-by-hop headers that should not be forwarded on responses.
# Includes framing headers (content-length, content-encoding) that the
# ASGI server (uvicorn) sets automatically from the actual body.
_HOP_BY_HOP_RESPONSE = _HOP_BY_HOP_REQUEST | {"content-length", "content-encoding"}

# Cookie name used for BAMF session auth — strip from forwarded requests
_BAMF_COOKIE_NAME = "bamf_session"


def rewrite_request_headers(
    headers: dict[str, str],
    tunnel_hostname: str,
    tunnel_domain: str,
    target_host: str,
    target_port: int | None,
    target_protocol: str,
    user_email: str,
    user_roles: list[str],
    client_ip: str | None,
    display_name: str | None = None,
    kubernetes_groups: list[str] | None = None,
    session_token: str | None = None,
) -> dict[str, str]:
    """Rewrite HTTP request headers for proxying to the target.

    The result is sent to the bridge relay endpoint, which forwards it to
    the agent. The agent reads X-Bamf-Target to know where to forward.
    """
    out: dict[str, str] = {}

    # Detect upgrade request — preserve Upgrade and Connection headers
    is_upgrade = any(k.lower() == "upgrade" for k in headers)

    # Copy headers, skipping hop-by-hop, auth, and headers we rewrite below
    for k, v in headers.items():
        lower_k = k.lower()
        if lower_k in _HOP_BY_HOP_REQUEST:
            # For upgrade requests, preserve "connection" header
            if lower_k == "connection" and is_upgrade:
                out[k] = v
            continue
        # Skip headers we rewrite explicitly below
        if lower_k in ("host", "origin"):
            continue
        # Strip BAMF Bearer token — the target shouldn't see it
        if lower_k == "authorization":
            continue
        # Strip bamf_session cookie but keep other cookies
        if lower_k == "cookie":
            v = _strip_bamf_cookie(v)
            if not v:
                continue
        out[k] = v

    # Build target origin (e.g., "http://grafana.internal:3000")
    target_origin = f"{target_protocol}://{target_host}"
    if target_port and target_port not in (80, 443):
        target_origin += f":{target_port}"

    # Rewrite Host → target's internal hostname
    if target_port and target_port not in (80, 443):
        out["Host"] = f"{target_host}:{target_port}"
    else:
        out["Host"] = target_host

    # Rewrite Origin if present in original headers
    if any(k.lower() == "origin" for k in headers):
        out["Origin"] = target_origin

    # X-Forwarded headers
    out["X-Forwarded-Host"] = f"{tunnel_hostname}.{tunnel_domain}"
    out["X-Forwarded-Proto"] = "https"
    if client_ip:
        out["X-Forwarded-For"] = client_ip
    out["X-Forwarded-User"] = user_email
    out["X-Forwarded-Email"] = user_email
    if display_name:
        out["X-Forwarded-Preferred-Username"] = display_name
    out["X-Forwarded-Roles"] = ",".join(user_roles)
    if kubernetes_groups:
        out["X-Forwarded-Groups"] = ",".join(kubernetes_groups)

    # Disable content encoding negotiation — the proxy chain cannot handle
    # all encodings (brotli, zstd, etc.) transparently. Setting identity
    # explicitly prevents httpx and Go's http.Client from adding their own
    # Accept-Encoding defaults. Ingress-level compression (Traefik, etc.)
    # handles browser-facing encoding separately.
    out["Accept-Encoding"] = "identity"

    # BAMF internal headers (agent reads X-Bamf-Target to determine target)
    out["X-Bamf-Target"] = target_origin
    out["X-Bamf-Resource"] = tunnel_hostname

    # Forward session token so downstream apps (e.g., kubamf) can make
    # authenticated calls back to the BAMF API (kube proxy, etc.)
    if session_token:
        out["X-Bamf-Session-Token"] = session_token

    return out


def rewrite_webhook_request_headers(
    headers: dict[str, str],
    tunnel_hostname: str,
    tunnel_domain: str,
    target_host: str,
    target_port: int | None,
    target_protocol: str,
    client_ip: str | None,
) -> dict[str, str]:
    """Rewrite HTTP request headers for a webhook passthrough request.

    Like rewrite_request_headers() but does NOT inject user identity headers
    (X-Forwarded-User/Email/Roles/Groups/Preferred-Username) or the BAMF
    session token. Webhook requests are unauthenticated from BAMF's perspective.
    """
    out: dict[str, str] = {}

    # Detect upgrade request — preserve Upgrade and Connection headers
    is_upgrade = any(k.lower() == "upgrade" for k in headers)

    # Copy headers, skipping hop-by-hop and headers we rewrite below
    for k, v in headers.items():
        lower_k = k.lower()
        if lower_k in _HOP_BY_HOP_REQUEST:
            if lower_k == "connection" and is_upgrade:
                out[k] = v
            continue
        if lower_k in ("host", "origin"):
            continue
        # Keep Authorization — it belongs to the webhook provider, not BAMF
        # Strip bamf_session cookie but keep other cookies
        if lower_k == "cookie":
            v = _strip_bamf_cookie(v)
            if not v:
                continue
        out[k] = v

    # Build target origin
    target_origin = f"{target_protocol}://{target_host}"
    if target_port and target_port not in (80, 443):
        target_origin += f":{target_port}"

    # Rewrite Host → target's internal hostname
    if target_port and target_port not in (80, 443):
        out["Host"] = f"{target_host}:{target_port}"
    else:
        out["Host"] = target_host

    # Rewrite Origin if present
    if any(k.lower() == "origin" for k in headers):
        out["Origin"] = target_origin

    # Standard proxy headers (no identity headers)
    out["X-Forwarded-Host"] = f"{tunnel_hostname}.{tunnel_domain}"
    out["X-Forwarded-Proto"] = "https"
    if client_ip:
        out["X-Forwarded-For"] = client_ip

    # Disable content encoding negotiation
    out["Accept-Encoding"] = "identity"

    # BAMF internal headers (agent reads X-Bamf-Target to determine target)
    out["X-Bamf-Target"] = target_origin
    out["X-Bamf-Resource"] = tunnel_hostname

    return out


def rewrite_response_headers(
    headers: dict[str, str],
    tunnel_hostname: str,
    tunnel_domain: str,
    target_host: str,
    target_port: int | None,
    target_protocol: str,
    *,
    is_upgrade: bool = False,
) -> dict[str, str]:
    """Rewrite HTTP response headers before returning to the browser.

    Rewrites Location redirects, Set-Cookie domains, and CORS origins
    from the target's internal hostname to the tunnel hostname.

    When ``is_upgrade`` is True, Upgrade and Connection headers are
    preserved (needed for 101 Switching Protocols responses).
    """
    out: dict[str, str] = {}
    tunnel_origin = f"https://{tunnel_hostname}.{tunnel_domain}"

    # Build target origin variations for replacement.
    # More specific origins (with port) must come first to avoid partial matches
    # (e.g., replacing "http://host" in "http://host:3000/path" leaves ":3000").
    target_origins: list[str] = []
    if target_port and target_port not in (80, 443):
        target_origins.append(f"{target_protocol}://{target_host}:{target_port}")
    target_origins.append(f"{target_protocol}://{target_host}")
    # Also catch the opposite protocol
    if target_protocol == "http":
        target_origins.append(f"https://{target_host}")
    else:
        target_origins.append(f"http://{target_host}")

    for k, v in headers.items():
        lower_k = k.lower()

        # Skip hop-by-hop — but preserve connection/upgrade for 101 responses
        if lower_k in _HOP_BY_HOP_RESPONSE:
            if is_upgrade and lower_k == "connection":
                out[k] = v
            continue

        # Preserve Upgrade header for upgrade responses
        if lower_k == "upgrade" and not is_upgrade:
            continue

        if lower_k == "location":
            for origin in target_origins:
                v = v.replace(origin, tunnel_origin)

        elif lower_k == "set-cookie":
            v = v.replace(f"domain={target_host}", f"domain={tunnel_hostname}.{tunnel_domain}")

        elif lower_k == "access-control-allow-origin":
            for origin in target_origins:
                if origin in v:
                    v = tunnel_origin

        elif lower_k == "content-security-policy":
            for origin in target_origins:
                v = v.replace(origin, tunnel_origin)

        out[k] = v

    return out


def rewrite_set_cookie(
    value: str,
    target_host: str,
    tunnel_hostname: str,
    tunnel_domain: str,
) -> str:
    """Rewrite a single Set-Cookie header value.

    Replaces ``domain=<target_host>`` with the tunnel hostname so the
    browser stores the cookie on the correct domain.  Cookies without an
    explicit ``domain`` attribute pass through unchanged.
    """
    return value.replace(
        f"domain={target_host}",
        f"domain={tunnel_hostname}.{tunnel_domain}",
    )


def _strip_bamf_cookie(cookie_header: str) -> str:
    """Remove the bamf_session cookie from a Cookie header value.

    Preserves all other cookies. Returns empty string if no cookies remain.
    """
    # Cookie header format: "name1=val1; name2=val2; name3=val3"
    parts = [p.strip() for p in cookie_header.split(";")]
    filtered = [p for p in parts if not p.startswith(f"{_BAMF_COOKIE_NAME}=")]
    return "; ".join(filtered)
