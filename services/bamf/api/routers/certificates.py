"""Certificates router for CA operations."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.api.dependencies import (
    get_current_session,
    require_admin,
    require_admin_or_audit,
)
from bamf.api.models.certificates import (
    CACertificateResponse,
    RevokeCertificateRequest,
    RevokedCertificateResponse,
    ServiceCertificateRequest,
    ServiceCertificateResponse,
    UserCertificateResponse,
)
from bamf.auth.ca import get_ca, serialize_certificate, serialize_private_key
from bamf.auth.revocation import list_revoked_certificates, revoke_certificate
from bamf.auth.sessions import Session
from bamf.db.models import utc_now
from bamf.db.session import get_db
from bamf.logging_config import get_logger
from bamf.services.audit_service import log_audit_event

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
    current_user: Session = Depends(require_admin),
) -> ServiceCertificateResponse:
    """Issue a service certificate for an agent or bridge.

    Admin only. Called during agent/bridge registration. The service_type field
    determines the SAN URI prefix (bamf://agent/{name} or bamf://bridge/{name}).
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


@router.post("/revoke", response_model=RevokedCertificateResponse)
async def revoke_certificate_endpoint(
    body: RevokeCertificateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: Session = Depends(require_admin),
) -> RevokedCertificateResponse:
    """Revoke a certificate by fingerprint (admin).

    Durable (Postgres) + enforced at the API cert-auth layer for agent/bridge
    certs. Tunnel session certs are 30s TTL and won't be re-minted for a revoked
    identity, so the bridge keeps its zero-runtime-dependency design.
    """
    if not body.fingerprint:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="fingerprint is required"
        )
    await revoke_certificate(
        db, body.fingerprint, reason=body.reason, revoked_by=current_user.email
    )
    await log_audit_event(
        db,
        event_type="admin",
        action="certificate_revoked",
        actor_type="user",
        actor_id=current_user.email,
        target_type="certificate",
        target_id=body.fingerprint,
        success=True,
        details={"reason": body.reason},
    )
    return RevokedCertificateResponse(
        fingerprint=body.fingerprint,
        revoked_at=utc_now(),
        reason=body.reason,
        revoked_by=current_user.email,
    )


@router.get("/revoked", response_model=list[RevokedCertificateResponse])
async def list_revoked_certs(
    db: AsyncSession = Depends(get_db),
    _admin: Session = Depends(require_admin_or_audit),
) -> list[RevokedCertificateResponse]:
    """List revoked certificates (admin/audit)."""
    revoked = await list_revoked_certificates(db)
    return [
        RevokedCertificateResponse(
            fingerprint=r.fingerprint,
            revoked_at=r.revoked_at,
            reason=r.reason,
            revoked_by=r.revoked_by,
            subject_cn=r.subject_cn,
        )
        for r in revoked
    ]
