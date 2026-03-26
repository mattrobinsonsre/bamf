"""Outpost token management routes.

Outpost tokens are used for proxy+bridge cluster registration.
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
from bamf.api.models.outposts import (
    OutpostTokenCreate,
    OutpostTokenCreateResponse,
    OutpostTokenResponse,
)
from bamf.auth.sessions import Session
from bamf.db.models import OutpostToken
from bamf.db.session import get_db, get_db_read
from bamf.logging_config import get_logger
from bamf.services.audit_service import log_audit_event

router = APIRouter(prefix="/outpost-tokens", tags=["outpost-tokens"])
logger = get_logger(__name__)


def generate_outpost_token() -> str:
    """Generate a secure random outpost token.

    Format: bamf_out_<32 random hex chars> = 41 chars total.
    The prefix distinguishes outpost tokens from agent tokens.
    """
    return f"bamf_out_{secrets.token_hex(16)}"


@router.get("", response_model=CursorPage[OutpostTokenResponse])
async def list_outpost_tokens(
    pagination: PaginationParams = Depends(),
    include_revoked: bool = False,
    db: AsyncSession = Depends(get_db_read),
    current_user: Session = Depends(require_admin_or_audit),
) -> CursorPage[OutpostTokenResponse]:
    """List all outpost tokens."""
    query = select(OutpostToken).order_by(OutpostToken.created_at.desc())

    if not include_revoked:
        query = query.where(OutpostToken.is_revoked == False)  # noqa: E712

    query = query.limit(pagination.limit + 1)

    if pagination.cursor:
        import base64

        cursor_name = base64.b64decode(pagination.cursor).decode()
        query = query.where(OutpostToken.name < cursor_name)

    result = await db.execute(query)
    tokens = list(result.scalars().all())

    has_more = len(tokens) > pagination.limit
    if has_more:
        tokens = tokens[: pagination.limit]

    items = [OutpostTokenResponse.from_db(t) for t in tokens]

    next_cursor = None
    if has_more and tokens:
        import base64

        next_cursor = base64.b64encode(tokens[-1].name.encode()).decode()

    return CursorPage(items=items, next_cursor=next_cursor, has_more=has_more)


@router.post("", response_model=OutpostTokenCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_outpost_token(
    body: OutpostTokenCreate,
    db: AsyncSession = Depends(get_db),
    current_user: Session = Depends(require_admin),
) -> OutpostTokenCreateResponse:
    """Create a new outpost join token.

    The secret token value is returned only once at creation time.
    """
    # Check for duplicate name
    existing = await db.execute(select(OutpostToken).where(OutpostToken.name == body.name))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Outpost token with name '{body.name}' already exists",
        )

    # Generate token and hash
    raw_token = generate_outpost_token()
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    token = OutpostToken(
        token_hash=token_hash,
        name=body.name,
        outpost_name=body.outpost_name,
        region=body.region,
        expires_at=datetime.now(UTC) + timedelta(hours=body.expires_in_hours),
        max_uses=body.max_uses,
        created_by=current_user.email,
    )

    db.add(token)
    await db.commit()
    await db.refresh(token)

    logger.info(
        "Outpost token created",
        token_name=body.name,
        outpost_name=body.outpost_name,
        created_by=current_user.email,
    )

    await log_audit_event(
        db,
        event_type="admin",
        action="outpost_token_created",
        actor_type="user",
        actor_id=current_user.email,
        target_type="outpost_token",
        target_id=str(token.id),
        success=True,
        details={
            "token_name": body.name,
            "outpost_name": body.outpost_name,
            "region": body.region,
        },
    )

    return OutpostTokenCreateResponse(
        id=token.id,
        name=token.name,
        outpost_name=token.outpost_name,
        region=token.region,
        expires_at=token.expires_at,
        max_uses=token.max_uses,
        use_count=token.use_count,
        is_revoked=token.is_revoked,
        created_at=token.created_at,
        created_by=token.created_by,
        token=raw_token,
    )


@router.get("/{token_id}", response_model=OutpostTokenResponse)
async def get_outpost_token(
    token_id: UUID,
    db: AsyncSession = Depends(get_db_read),
    current_user: Session = Depends(require_admin_or_audit),
) -> OutpostTokenResponse:
    """Get a single outpost token by ID."""
    result = await db.execute(select(OutpostToken).where(OutpostToken.id == token_id))
    token = result.scalar_one_or_none()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Outpost token not found",
        )

    return OutpostTokenResponse.from_db(token)


@router.delete("/{token_id}", response_model=SuccessResponse)
async def revoke_outpost_token(
    token_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: Session = Depends(require_admin),
) -> SuccessResponse:
    """Revoke an outpost token."""
    result = await db.execute(select(OutpostToken).where(OutpostToken.id == token_id))
    token = result.scalar_one_or_none()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Outpost token not found",
        )

    if token.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token is already revoked",
        )

    token.is_revoked = True
    await db.commit()

    logger.info(
        "Outpost token revoked",
        token_name=token.name,
        revoked_by=current_user.email,
    )

    await log_audit_event(
        db,
        event_type="admin",
        action="outpost_token_revoked",
        actor_type="user",
        actor_id=current_user.email,
        target_type="outpost_token",
        target_id=str(token.id),
        success=True,
        details={"token_name": token.name, "outpost_name": token.outpost_name},
    )

    return SuccessResponse(message=f"Outpost token '{token.name}' has been revoked")


@router.post("/{token_name}/revoke", response_model=SuccessResponse)
async def revoke_outpost_token_by_name(
    token_name: str,
    db: AsyncSession = Depends(get_db),
    current_user: Session = Depends(require_admin),
) -> SuccessResponse:
    """Revoke an outpost token by name (CLI convenience)."""
    result = await db.execute(select(OutpostToken).where(OutpostToken.name == token_name))
    token = result.scalar_one_or_none()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Outpost token not found: {token_name}",
        )

    if token.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token is already revoked",
        )

    token.is_revoked = True
    await db.commit()

    logger.info(
        "Outpost token revoked",
        token_name=token.name,
        revoked_by=current_user.email,
    )

    await log_audit_event(
        db,
        event_type="admin",
        action="outpost_token_revoked",
        actor_type="user",
        actor_id=current_user.email,
        target_type="outpost_token",
        target_id=str(token.id),
        success=True,
        details={"token_name": token.name, "outpost_name": token.outpost_name},
    )

    return SuccessResponse(message=f"Outpost token '{token.name}' has been revoked")
