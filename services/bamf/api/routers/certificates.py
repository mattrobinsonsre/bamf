"""Certificates router for CA operations."""

from fastapi import APIRouter, Depends

from bamf.api.dependencies import get_current_session, get_current_user
from bamf.api.models.certificates import (
    CACertificateResponse,
    ServiceCertificateRequest,
    ServiceCertificateResponse,
    UserCertificateResponse,
)
from bamf.auth.ca import get_ca, serialize_certificate, serialize_private_key
from bamf.auth.sessions import Session
from bamf.logging_config import get_logger

router = APIRouter(prefix="/certificates", tags=["certificates"])
logger = get_logger(__name__)


@router.get("/ca", response_model=CACertificateResponse)
async def get_ca_certificate() -> CACertificateResponse:
    """Return the public CA certificate.

    Any component can fetch this to validate certificates issued by the BAMF CA.
    No authentication required.
    """
    ca = get_ca()
    return CACertificateResponse(ca_certificate=ca.ca_cert_pem)


@router.post("/user", response_model=UserCertificateResponse)
async def issue_user_certificate(
    session: Session = Depends(get_current_session),
) -> UserCertificateResponse:
    """Issue a user identity certificate for CLI-to-bridge authentication.

    The certificate embeds the user's roles (from session, resolved at login)
    as SAN URIs and is signed by the BAMF CA.
    """
    ca = get_ca()

    cert, key = ca.issue_user_certificate(
        email=session.email,
        roles=session.roles,
    )

    return UserCertificateResponse(
        certificate=serialize_certificate(cert).decode(),
        private_key=serialize_private_key(key).decode(),
        ca_certificate=ca.ca_cert_pem,
        expires_at=cert.not_valid_after_utc,
    )


@router.post("/service", response_model=ServiceCertificateResponse)
async def issue_service_certificate(
    request: ServiceCertificateRequest,
    current_user: Session = Depends(get_current_user),
) -> ServiceCertificateResponse:
    """Issue a service certificate for an agent or bridge.

    Called during agent/bridge registration. The service_type field determines
    the SAN URI prefix (bamf://agent/{name} or bamf://bridge/{name}).
    """
    ca = get_ca()

    cert, key = ca.issue_service_certificate(
        service_name=request.service_name,
        service_type=request.service_type,
        dns_names=request.dns_names if request.dns_names else None,
        ip_addresses=request.ip_addresses if request.ip_addresses else None,
    )

    logger.info(
        "Issued service certificate via API",
        service_name=request.service_name,
        service_type=request.service_type,
        requested_by=current_user.email,
    )

    return ServiceCertificateResponse(
        certificate=serialize_certificate(cert).decode(),
        private_key=serialize_private_key(key).decode(),
        ca_certificate=ca.ca_cert_pem,
        expires_at=cert.not_valid_after_utc,
    )
