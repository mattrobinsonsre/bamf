"""JWT token utilities."""

import base64
import hashlib
import hmac
import json
from datetime import UTC, datetime
from typing import Any

from bamf.config import settings

# In production, this should be loaded from a secret
# For now, using a placeholder that should be overridden via BAMF_JWT_SECRET
JWT_SECRET = getattr(settings, "jwt_secret", "CHANGE-ME-IN-PRODUCTION")
JWT_ALGORITHM = "HS256"


def _b64_encode(data: bytes) -> str:
    """URL-safe base64 encode without padding."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64_decode(data: str) -> bytes:
    """URL-safe base64 decode with padding restoration."""
    padding = 4 - (len(data) % 4)
    if padding != 4:
        data += "=" * padding
    return base64.urlsafe_b64decode(data)


def create_access_token(
    email: str,
    expires_at: datetime,
    additional_claims: dict[str, Any] | None = None,
    *,
    roles: list[str] | None = None,
    provider: str | None = None,
) -> str:
    """
    Create a JWT access token.

    Args:
        email: User email (subject)
        expires_at: Token expiration time (must be timezone-aware UTC)
        additional_claims: Optional additional claims to include
        roles: Optional list of role names
        provider: Optional SSO provider name (None for local auth)

    Returns:
        JWT token string
    """
    if expires_at.tzinfo is None:
        raise ValueError("expires_at must be timezone-aware UTC")

    header = {"alg": JWT_ALGORITHM, "typ": "JWT"}
    payload: dict[str, Any] = {
        "sub": email,
        "exp": int(expires_at.timestamp()),
        "iat": int(datetime.now(UTC).timestamp()),
    }

    if roles is not None:
        payload["roles"] = roles
    if provider is not None:
        payload["provider"] = provider

    if additional_claims:
        payload.update(additional_claims)

    header_b64 = _b64_encode(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64_encode(json.dumps(payload, separators=(",", ":")).encode())

    message = f"{header_b64}.{payload_b64}"
    signature = hmac.new(
        JWT_SECRET.encode(),
        message.encode(),
        hashlib.sha256,
    ).digest()
    signature_b64 = _b64_encode(signature)

    return f"{message}.{signature_b64}"


def decode_access_token(token: str) -> dict[str, Any]:
    """
    Decode and validate a JWT access token.

    Args:
        token: JWT token string

    Returns:
        Token payload

    Raises:
        ValueError: If token is invalid or expired
    """
    try:
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid token format")

        header_b64, payload_b64, signature_b64 = parts

        # Verify signature
        message = f"{header_b64}.{payload_b64}"
        expected_signature = hmac.new(
            JWT_SECRET.encode(),
            message.encode(),
            hashlib.sha256,
        ).digest()
        actual_signature = _b64_decode(signature_b64)

        if not hmac.compare_digest(expected_signature, actual_signature):
            raise ValueError("Invalid signature")

        # Decode payload
        payload = json.loads(_b64_decode(payload_b64))

        # Check expiration
        exp = payload.get("exp")
        if exp and datetime.fromtimestamp(exp, tz=UTC) < datetime.now(UTC):
            raise ValueError("Token expired")

        return payload
    except (json.JSONDecodeError, KeyError) as e:
        raise ValueError(f"Invalid token: {e}") from e
