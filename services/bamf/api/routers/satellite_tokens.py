"""Satellite token management routes.

Satellite tokens are used for proxy+bridge cluster registration.
Only admins can create, revoke, and delete tokens. Admin and audit
users can list and view tokens.
"""

import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.api.dependencies import require_admin, require_admin_or_audit
from bamf.api.models.common import CursorPage, PaginationParams, SuccessResponse
from bamf.api.models.satellites import (
    SatelliteTokenCreate,
    SatelliteTokenCreateResponse,
    SatelliteTokenResponse,
)
from bamf.auth.sessions import Session
from bamf.db.models import SatelliteToken
from bamf.db.session import get_db, get_db_read
from bamf.logging_config import get_logger
from bamf.services.audit_service import log_audit_event

router = APIRouter(prefix="/satellite-tokens", tags=["satellite-tokens"])
logger = get_logger(__name__)


def generate_satellite_token() -> str:
    """Generate a secure random satellite token.

    Format: bamf_sat_<32 random hex chars> = 41 chars total.
    The prefix distinguishes satellite tokens from agent tokens.
    """
    return f"bamf_sat_{secrets.token_hex(16)}"


@router.get("", response_model=CursorPage[SatelliteTokenResponse])
async def list_satellite_tokens(
    pagination: PaginationParams = Depends(),
    include_revoked: bool = False,
    db: AsyncSession = Depends(get_db_read),
    current_user: Session = Depends(require_admin_or_audit),
) -> CursorPage[SatelliteTokenResponse]:
    """List all satellite tokens."""
    query = select(SatelliteToken).order_by(SatelliteToken.created_at.desc())

    if not include_revoked:
        query = query.where(SatelliteToken.is_revoked == False)  # noqa: E712

    query = query.limit(pagination.limit + 1)

    if pagination.cursor:
        import base64

        cursor_name = base64.b64decode(pagination.cursor).decode()
        query = query.where(SatelliteToken.name < cursor_name)

    result = await db.execute(query)
    tokens = list(result.scalars().all())

    has_more = len(tokens) > pagination.limit
    if has_more:
        tokens = tokens[: pagination.limit]

    items = [SatelliteTokenResponse.from_db(t) for t in tokens]

    next_cursor = None
    if has_more and tokens:
        import base64

        next_cursor = base64.b64encode(tokens[-1].name.encode()).decode()

    return CursorPage(items=items, next_cursor=next_cursor, has_more=has_more)


@router.post("", response_model=SatelliteTokenCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_satellite_token(
    body: SatelliteTokenCreate,
    db: AsyncSession = Depends(get_db),
    current_user: Session = Depends(require_admin),
) -> SatelliteTokenCreateResponse:
    """Create a new satellite join token.

    The secret token value is returned only once at creation time.
    """
    # Check for duplicate name
    existing = await db.execute(
        select(SatelliteToken).where(SatelliteToken.name == body.name)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Satellite token with name '{body.name}' already exists",
        )

    # Generate token and hash
    raw_token = generate_satellite_token()
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    token = SatelliteToken(
        token_hash=token_hash,
        name=body.name,
        satellite_name=body.satellite_name,
        region=body.region,
        expires_at=datetime.now(UTC) + timedelta(hours=body.expires_in_hours),
        max_uses=body.max_uses,
        created_by=current_user.email,
    )

    db.add(token)
    await db.commit()
    await db.refresh(token)

    logger.info(
        "Satellite token created",
        token_name=body.name,
        satellite_name=body.satellite_name,
        created_by=current_user.email,
    )

    await log_audit_event(
        db,
        event_type="admin",
        action="satellite_token_created",
        actor_type="user",
        actor_id=current_user.email,
        target_type="satellite_token",
        target_id=str(token.id),
        success=True,
        details={
            "token_name": body.name,
            "satellite_name": body.satellite_name,
            "region": body.region,
        },
    )

    return SatelliteTokenCreateResponse(
        id=token.id,
        name=token.name,
        satellite_name=token.satellite_name,
        region=token.region,
        expires_at=token.expires_at,
        max_uses=token.max_uses,
        use_count=token.use_count,
        is_revoked=token.is_revoked,
        created_at=token.created_at,
        created_by=token.created_by,
        token=raw_token,
    )


@router.get("/{token_id}", response_model=SatelliteTokenResponse)
async def get_satellite_token(
    token_id: UUID,
    db: AsyncSession = Depends(get_db_read),
    current_user: Session = Depends(require_admin_or_audit),
) -> SatelliteTokenResponse:
    """Get a single satellite token by ID."""
    result = await db.execute(
        select(SatelliteToken).where(SatelliteToken.id == token_id)
    )
    token = result.scalar_one_or_none()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Satellite token not found",
        )

    return SatelliteTokenResponse.from_db(token)


@router.delete("/{token_id}", response_model=SuccessResponse)
async def revoke_satellite_token(
    token_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: Session = Depends(require_admin),
) -> SuccessResponse:
    """Revoke a satellite token."""
    result = await db.execute(
        select(SatelliteToken).where(SatelliteToken.id == token_id)
    )
    token = result.scalar_one_or_none()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Satellite token not found",
        )

    if token.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token is already revoked",
        )

    token.is_revoked = True
    await db.commit()

    logger.info(
        "Satellite token revoked",
        token_name=token.name,
        revoked_by=current_user.email,
    )

    await log_audit_event(
        db,
        event_type="admin",
        action="satellite_token_revoked",
        actor_type="user",
        actor_id=current_user.email,
        target_type="satellite_token",
        target_id=str(token.id),
        success=True,
        details={"token_name": token.name, "satellite_name": token.satellite_name},
    )

    return SuccessResponse(message=f"Satellite token '{token.name}' has been revoked")


@router.post("/{token_name}/revoke", response_model=SuccessResponse)
async def revoke_satellite_token_by_name(
    token_name: str,
    db: AsyncSession = Depends(get_db),
    current_user: Session = Depends(require_admin),
) -> SuccessResponse:
    """Revoke a satellite token by name (CLI convenience)."""
    result = await db.execute(
        select(SatelliteToken).where(SatelliteToken.name == token_name)
    )
    token = result.scalar_one_or_none()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Satellite token not found: {token_name}",
        )

    if token.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token is already revoked",
        )

    token.is_revoked = True
    await db.commit()

    logger.info(
        "Satellite token revoked",
        token_name=token.name,
        revoked_by=current_user.email,
    )

    await log_audit_event(
        db,
        event_type="admin",
        action="satellite_token_revoked",
        actor_type="user",
        actor_id=current_user.email,
        target_type="satellite_token",
        target_id=str(token.id),
        success=True,
        details={"token_name": token.name, "satellite_name": token.satellite_name},
    )

    return SuccessResponse(message=f"Satellite token '{token.name}' has been revoked")
