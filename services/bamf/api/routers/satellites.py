"""Satellite management routes.

Satellites are regional proxy+bridge clusters that register with the
central API. The join endpoint is unauthenticated (token in body),
management endpoints require admin access.
"""

import hashlib
import secrets
from datetime import UTC, datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.api.dependencies import require_admin, require_admin_or_audit
from bamf.api.models.common import CursorPage, PaginationParams, SuccessResponse
from bamf.api.models.satellites import (
    SatelliteJoinRequest,
    SatelliteJoinResponse,
    SatelliteResponse,
)
from bamf.auth.ca import get_ca
from bamf.auth.sessions import Session
from bamf.config import settings
from bamf.db.models import Satellite, SatelliteToken
from bamf.db.session import get_db, get_db_read
from bamf.logging_config import get_logger
from bamf.services.audit_service import log_audit_event

router = APIRouter(prefix="/satellites", tags=["satellites"])
logger = get_logger(__name__)


def _generate_internal_token() -> str:
    """Generate an internal proxy auth token.

    Format: sat_int_<32 random hex chars>.
    """
    return f"sat_int_{secrets.token_hex(16)}"


def _generate_bridge_bootstrap_token() -> str:
    """Generate a bridge bootstrap token.

    Format: sat_brg_<32 random hex chars>.
    """
    return f"sat_brg_{secrets.token_hex(16)}"


@router.post("/join", response_model=SatelliteJoinResponse, status_code=status.HTTP_201_CREATED)
async def join_satellite(
    request: SatelliteJoinRequest,
    db: AsyncSession = Depends(get_db),
) -> SatelliteJoinResponse:
    """Register a satellite using a join token.

    Validates the join token, creates or updates the satellite record,
    generates internal and bridge bootstrap tokens, and returns them
    along with the CA certificate.

    No authentication required — the join token IS the credential.
    """
    token_hash = hashlib.sha256(request.join_token.encode()).hexdigest()

    result = await db.execute(select(SatelliteToken).where(SatelliteToken.token_hash == token_hash))
    token = result.scalar_one_or_none()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid satellite join token",
        )

    now = datetime.now(UTC)

    if token.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Satellite join token has been revoked",
        )

    if token.expires_at < now:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Satellite join token has expired",
        )

    if token.max_uses is not None and token.use_count >= token.max_uses:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Satellite join token has reached maximum uses",
        )

    # Generate auth tokens
    internal_token = _generate_internal_token()
    bridge_bootstrap_token = _generate_bridge_bootstrap_token()
    internal_token_hash = hashlib.sha256(internal_token.encode()).hexdigest()
    bridge_bootstrap_token_hash = hashlib.sha256(bridge_bootstrap_token.encode()).hexdigest()

    # Check if satellite with this name already exists (re-join)
    existing_result = await db.execute(
        select(Satellite).where(Satellite.name == token.satellite_name)
    )
    satellite = existing_result.scalar_one_or_none()

    if satellite:
        # Re-join: regenerate both tokens (invalidates old deployment)
        satellite.internal_token_hash = internal_token_hash
        satellite.bridge_bootstrap_token_hash = bridge_bootstrap_token_hash
        satellite.region = token.region
        satellite.updated_at = now
        logger.info(
            "Satellite re-joined",
            satellite_name=satellite.name,
            satellite_id=str(satellite.id),
        )
    else:
        # New satellite
        satellite = Satellite(
            name=token.satellite_name,
            region=token.region,
            internal_token_hash=internal_token_hash,
            bridge_bootstrap_token_hash=bridge_bootstrap_token_hash,
        )
        db.add(satellite)
        logger.info(
            "Satellite registered",
            satellite_name=token.satellite_name,
        )

    # Increment token use count
    token.use_count += 1

    await db.commit()
    await db.refresh(satellite)

    # Get CA certificate
    ca = get_ca()

    await log_audit_event(
        db,
        event_type="admin",
        action="satellite_joined",
        actor_type="system",
        actor_id=token.satellite_name,
        target_type="satellite",
        target_id=str(satellite.id),
        success=True,
        details={
            "satellite_name": satellite.name,
            "region": satellite.region,
            "join_token_name": token.name,
        },
    )

    return SatelliteJoinResponse(
        satellite_id=satellite.id,
        satellite_name=satellite.name,
        region=satellite.region,
        internal_token=internal_token,
        bridge_bootstrap_token=bridge_bootstrap_token,
        ca_certificate=ca.ca_cert_pem,
        tunnel_domain=settings.tunnel_domain or "",
    )


@router.get("", response_model=CursorPage[SatelliteResponse])
async def list_satellites(
    pagination: PaginationParams = Depends(),
    include_inactive: bool = False,
    db: AsyncSession = Depends(get_db_read),
    current_user: Session = Depends(require_admin_or_audit),
) -> CursorPage[SatelliteResponse]:
    """List all registered satellites."""
    query = select(Satellite).order_by(Satellite.created_at.desc())

    if not include_inactive:
        query = query.where(Satellite.is_active == True)  # noqa: E712

    query = query.limit(pagination.limit + 1)

    if pagination.cursor:
        import base64

        cursor_name = base64.b64decode(pagination.cursor).decode()
        query = query.where(Satellite.name < cursor_name)

    result = await db.execute(query)
    satellites = list(result.scalars().all())

    has_more = len(satellites) > pagination.limit
    if has_more:
        satellites = satellites[: pagination.limit]

    items = [SatelliteResponse.from_db(s) for s in satellites]

    next_cursor = None
    if has_more and satellites:
        import base64

        next_cursor = base64.b64encode(satellites[-1].name.encode()).decode()

    return CursorPage(items=items, next_cursor=next_cursor, has_more=has_more)


@router.get("/{satellite_id}", response_model=SatelliteResponse)
async def get_satellite(
    satellite_id: UUID,
    db: AsyncSession = Depends(get_db_read),
    current_user: Session = Depends(require_admin_or_audit),
) -> SatelliteResponse:
    """Get a single satellite by ID."""
    result = await db.execute(select(Satellite).where(Satellite.id == satellite_id))
    satellite = result.scalar_one_or_none()

    if not satellite:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Satellite not found",
        )

    return SatelliteResponse.from_db(satellite)


@router.delete("/{satellite_id}", response_model=SuccessResponse)
async def deactivate_satellite(
    satellite_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: Session = Depends(require_admin),
) -> SuccessResponse:
    """Deactivate a satellite.

    Deactivated satellites cannot authenticate. Their proxy and bridge
    pods will fail auth and stop serving traffic. Bridge registrations
    expire via Redis TTL. Agent relay connections are disconnected.
    """
    result = await db.execute(select(Satellite).where(Satellite.id == satellite_id))
    satellite = result.scalar_one_or_none()

    if not satellite:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Satellite not found",
        )

    if not satellite.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Satellite is already deactivated",
        )

    satellite.is_active = False
    await db.commit()

    logger.info(
        "Satellite deactivated",
        satellite_name=satellite.name,
        deactivated_by=current_user.email,
    )

    await log_audit_event(
        db,
        event_type="admin",
        action="satellite_deactivated",
        actor_type="user",
        actor_id=current_user.email,
        target_type="satellite",
        target_id=str(satellite.id),
        success=True,
        details={"satellite_name": satellite.name},
    )

    return SuccessResponse(message=f"Satellite '{satellite.name}' has been deactivated")
