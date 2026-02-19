"""Sensitive data redaction for HTTP audit recordings.

Central redaction module used by both http-audit proxy recordings and API
self-audit middleware. Ensures bearer tokens, passwords, session cookies,
and other sensitive values are never persisted in audit storage.
"""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlencode

# Headers whose values are replaced entirely with "[REDACTED]"
REDACT_HEADERS: frozenset[str] = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "x-api-key",
        "x-auth-token",
    }
)

# Headers whose values are partially redacted (keep structure, hide values)
REDACT_COOKIE_HEADERS: frozenset[str] = frozenset({"cookie", "set-cookie"})

# JSON/form body field names whose values are replaced with "[REDACTED]"
REDACT_BODY_FIELDS: frozenset[str] = frozenset(
    {
        "password",
        "secret",
        "client_secret",
        "code_verifier",
        "samlresponse",
        "session_token",
        "key",
        "private_key",
    }
)

# Query parameter names to redact
REDACT_QUERY_PARAMS: frozenset[str] = frozenset(
    {
        "password",
        "secret",
        "token",
        "api_key",
        "key",
    }
)

_REDACTED = "[REDACTED]"


def redact_headers(headers: dict[str, str]) -> dict[str, str]:
    """Redact sensitive header values.

    - Full redaction: Authorization, Proxy-Authorization, X-Api-Key, X-Auth-Token
    - Cookie redaction: keep cookie names, replace values
    - Set-Cookie: redact the value portion but keep attributes
    - All other headers pass through unchanged
    """
    result = {}
    for name, value in headers.items():
        lower = name.lower()
        if lower in REDACT_HEADERS:
            result[name] = _REDACTED
        elif lower == "cookie":
            result[name] = _redact_cookie(value)
        elif lower == "set-cookie":
            result[name] = _redact_set_cookie(value)
        else:
            result[name] = value
    return result


def _redact_cookie(value: str) -> str:
    """Redact cookie values while preserving cookie names.

    'bamf_session=abc123; theme=dark' → 'bamf_session=[REDACTED]; theme=dark'
    """
    parts = []
    for pair in value.split(";"):
        pair = pair.strip()
        if "=" in pair:
            name, _ = pair.split("=", 1)
            parts.append(f"{name}={_REDACTED}")
        else:
            parts.append(pair)
    return "; ".join(parts)


def _redact_set_cookie(value: str) -> str:
    """Redact Set-Cookie value portion while keeping attributes.

    'bamf_session=abc123; Path=/; HttpOnly' → 'bamf_session=[REDACTED]; Path=/; HttpOnly'
    """
    parts = value.split(";")
    if not parts:
        return value

    # First part is name=value
    first = parts[0].strip()
    if "=" in first:
        name, _ = first.split("=", 1)
        parts[0] = f"{name}={_REDACTED}"

    return "; ".join(parts)


def redact_body(body: str, content_type: str) -> str:
    """Redact sensitive fields in request/response bodies.

    - application/json: parse, recursively redact matching fields, re-serialize
    - application/x-www-form-urlencoded: parse, redact matching fields, re-encode
    - Other content types: return unchanged
    - On parse failure: return body unchanged (don't break audit for malformed input)
    """
    if not body:
        return body

    ct = content_type.lower().split(";")[0].strip()

    if ct == "application/json":
        return _redact_json(body)
    if ct == "application/x-www-form-urlencoded":
        return _redact_form(body)

    return body


def _redact_json(body: str) -> str:
    """Recursively redact sensitive fields in JSON."""
    try:
        data = json.loads(body)
        redacted = _redact_value(data)
        return json.dumps(redacted)
    except (json.JSONDecodeError, TypeError, ValueError):
        return body


def _redact_value(obj: object) -> object:
    """Recursively walk a JSON structure and redact sensitive field values."""
    if isinstance(obj, dict):
        return {
            k: _REDACTED if k.lower() in REDACT_BODY_FIELDS else _redact_value(v)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_redact_value(item) for item in obj]
    return obj


def _redact_form(body: str) -> str:
    """Redact sensitive fields in URL-encoded form data."""
    try:
        parsed = parse_qs(body, keep_blank_values=True)
        redacted = {}
        for key, values in parsed.items():
            if key.lower() in REDACT_BODY_FIELDS:
                redacted[key] = [_REDACTED]
            else:
                redacted[key] = values
        return urlencode(redacted, doseq=True)
    except Exception:
        return body


def redact_query(query: str) -> str:
    """Redact sensitive parameter values in a query string.

    'password=secret&name=alice' → 'password=[REDACTED]&name=alice'
    """
    if not query:
        return query

    try:
        parsed = parse_qs(query, keep_blank_values=True)
        redacted = {}
        for key, values in parsed.items():
            if key.lower() in REDACT_QUERY_PARAMS:
                redacted[key] = [_REDACTED]
            else:
                redacted[key] = values
        return urlencode(redacted, doseq=True)
    except Exception:
        return query
