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

# Headers that should not be forwarded (hop-by-hop)
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "transfer-encoding",
        "te",
        "trailer",
        "upgrade",
        "proxy-authorization",
        "proxy-authenticate",
    }
)

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
    client_ip: str,
) -> dict[str, str]:
    """Rewrite HTTP request headers for proxying to the target.

    The result is sent to the bridge relay endpoint, which forwards it to
    the agent. The agent reads X-Bamf-Target to know where to forward.
    """
    out: dict[str, str] = {}

    # Copy headers, skipping hop-by-hop, auth, and headers we rewrite below
    for k, v in headers.items():
        lower_k = k.lower()
        if lower_k in _HOP_BY_HOP:
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
    out["X-Forwarded-For"] = client_ip
    out["X-Forwarded-User"] = user_email
    out["X-Forwarded-Email"] = user_email
    out["X-Forwarded-Roles"] = ",".join(user_roles)

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
) -> dict[str, str]:
    """Rewrite HTTP response headers before returning to the browser.

    Rewrites Location redirects, Set-Cookie domains, and CORS origins
    from the target's internal hostname to the tunnel hostname.
    """
    out: dict[str, str] = {}
    tunnel_origin = f"https://{tunnel_hostname}.{tunnel_domain}"

    # Build target origin variations for replacement
    target_origins = [f"{target_protocol}://{target_host}"]
    if target_port and target_port not in (80, 443):
        target_origins.append(f"{target_protocol}://{target_host}:{target_port}")
    # Also catch the opposite protocol
    if target_protocol == "http":
        target_origins.append(f"https://{target_host}")
    else:
        target_origins.append(f"http://{target_host}")

    for k, v in headers.items():
        lower_k = k.lower()

        # Skip hop-by-hop
        if lower_k in _HOP_BY_HOP:
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

        out[k] = v

    return out


def _strip_bamf_cookie(cookie_header: str) -> str:
    """Remove the bamf_session cookie from a Cookie header value.

    Preserves all other cookies. Returns empty string if no cookies remain.
    """
    # Cookie header format: "name1=val1; name2=val2; name3=val3"
    parts = [p.strip() for p in cookie_header.split(";")]
    filtered = [p for p in parts if not p.startswith(f"{_BAMF_COOKIE_NAME}=")]
    return "; ".join(filtered)
