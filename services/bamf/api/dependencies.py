"""FastAPI dependencies for authentication and authorization.

Authentication is session-based. Clients send an opaque session token
(not a JWT) in the Authorization header. The server validates by looking
up the session in Redis. No database roundtrip needed — the session
stores email, roles, and provider.

For agents/bridges: certificate-based auth via X-Bamf-Client-Cert header.
The service sends its PEM-encoded certificate (base64) and we validate it
against the BAMF CA.
"""

import base64
from dataclasses import dataclass
from datetime import UTC, datetime

from cryptography import x509
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from bamf.auth.ca import get_ca
from bamf.auth.sessions import (
    Session,
    _should_refresh_session,
    get_session,
    refresh_session,
)
from bamf.logging_config import get_logger

logger = get_logger(__name__)
security = HTTPBearer()


@dataclass
class AgentIdentity:
    """Identity extracted from a validated agent certificate."""

    name: str  # CN from cert
    certificate: x509.Certificate
    expires_at: datetime


@dataclass
class BridgeIdentity:
    """Identity extracted from a validated bridge certificate."""

    bridge_id: str  # CN from cert (typically hostname or pod name)
    certificate: x509.Certificate
    expires_at: datetime


async def get_current_session(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> Session:
    """Dependency to get the current authenticated session.

    Validates the session token against Redis. Extends the session TTL
    on activity (sliding window) — at most once per 5 minutes to avoid
    hitting Redis on every request.
    """
    token = credentials.credentials
    session = await get_session(token)

    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Sliding window: refresh TTL on activity (rate-limited to every 5 min)
    if _should_refresh_session(session):
        await refresh_session(token, session)

    return session


async def get_current_user(
    session: Session = Depends(get_current_session),
) -> Session:
    """Dependency to get the current authenticated user's session.

    Returns the Redis session which has email, roles, and provider.
    No database lookup — the session is authoritative. For local users,
    is_active was checked at login time. To disable a user mid-session,
    revoke their sessions via the admin API.
    """
    return session


async def require_admin(
    session: Session = Depends(get_current_session),
) -> Session:
    """Dependency to require admin role.

    Checks the session's roles (resolved at login time) for 'admin'.
    """
    if "admin" not in session.roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return session


async def require_admin_or_audit(
    session: Session = Depends(get_current_session),
) -> Session:
    """Dependency to require admin or audit role.

    Audit users can read all platform data but cannot make changes.
    """
    if not ({"admin", "audit"} & set(session.roles)):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin or audit access required",
        )
    return session


def _validate_client_cert(header_value: str | None, entity_type: str) -> x509.Certificate:
    """Validate a client certificate from X-Bamf-Client-Cert header.

    Decodes base64 → PEM → certificate, verifies CA signature and expiry.
    Returns the validated certificate or raises HTTPException.
    """
    if not header_value:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing X-Bamf-Client-Cert header",
        )

    try:
        cert_pem = base64.b64decode(header_value)
        cert = x509.load_pem_x509_certificate(cert_pem)
    except Exception as e:
        logger.warning("Failed to parse %s certificate", entity_type, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid certificate format",
        ) from e

    # Validate certificate is signed by our CA
    ca = get_ca()
    try:
        ca.ca_cert.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
        )
    except Exception as e:
        logger.warning("%s certificate signature validation failed", entity_type, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Certificate not signed by BAMF CA",
        ) from e

    # Check expiry
    now = datetime.now(UTC)
    if cert.not_valid_after_utc < now:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Certificate has expired",
        )
    if cert.not_valid_before_utc > now:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Certificate not yet valid",
        )

    # Extract CN
    cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
    if not cn:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Certificate has no CN",
        )

    return cert


async def get_agent_identity(
    x_bamf_client_cert: str | None = Header(default=None, alias="X-Bamf-Client-Cert"),
) -> AgentIdentity:
    """Dependency to validate agent certificate from X-Bamf-Client-Cert header."""
    cert = _validate_client_cert(x_bamf_client_cert, "agent")
    cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    return AgentIdentity(name=cn, certificate=cert, expires_at=cert.not_valid_after_utc)


async def get_bridge_identity(
    x_bamf_client_cert: str | None = Header(default=None, alias="X-Bamf-Client-Cert"),
) -> BridgeIdentity:
    """Dependency to validate bridge certificate from X-Bamf-Client-Cert header."""
    cert = _validate_client_cert(x_bamf_client_cert, "bridge")
    cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)[0].value
    return BridgeIdentity(bridge_id=cn, certificate=cert, expires_at=cert.not_valid_after_utc)
