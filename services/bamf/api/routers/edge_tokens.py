"""Edge token management routes.

Edge tokens are used for proxy+bridge cluster registration.
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
from bamf.api.models.edges import (
    EdgeTokenCreate,
    EdgeTokenCreateResponse,
    EdgeTokenResponse,
)
from bamf.auth.sessions import Session
from bamf.db.models import EdgeToken
from bamf.db.session import get_db, get_db_read
from bamf.logging_config import get_logger
from bamf.services.audit_service import log_audit_event

router = APIRouter(prefix="/edge-tokens", tags=["edge-tokens"])
logger = get_logger(__name__)


def generate_edge_token() -> str:
    """Generate a secure random edge token.

    Format: bamf_edge_<32 random hex chars> = 41 chars total.
    The prefix distinguishes edge tokens from agent tokens.
    """
    return f"bamf_edge_{secrets.token_hex(16)}"


@router.get("", response_model=CursorPage[EdgeTokenResponse])
async def list_edge_tokens(
    pagination: PaginationParams = Depends(),
    include_revoked: bool = False,
    db: AsyncSession = Depends(get_db_read),
    current_user: Session = Depends(require_admin_or_audit),
) -> CursorPage[EdgeTokenResponse]:
    """List all edge tokens."""
    query = select(EdgeToken).order_by(EdgeToken.created_at.desc())

    if not include_revoked:
        query = query.where(EdgeToken.is_revoked == False)  # noqa: E712

    query = query.limit(pagination.limit + 1)

    if pagination.cursor:
        import base64

        cursor_name = base64.b64decode(pagination.cursor).decode()
        query = query.where(EdgeToken.name < cursor_name)

    result = await db.execute(query)
    tokens = list(result.scalars().all())

    has_more = len(tokens) > pagination.limit
    if has_more:
        tokens = tokens[: pagination.limit]

    items = [EdgeTokenResponse.from_db(t) for t in tokens]

    next_cursor = None
    if has_more and tokens:
        import base64

        next_cursor = base64.b64encode(tokens[-1].name.encode()).decode()

    return CursorPage(items=items, next_cursor=next_cursor, has_more=has_more)


@router.post("", response_model=EdgeTokenCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_edge_token(
    body: EdgeTokenCreate,
    db: AsyncSession = Depends(get_db),
    current_user: Session = Depends(require_admin),
) -> EdgeTokenCreateResponse:
    """Create a new edge join token.

    The secret token value is returned only once at creation time.
    """
    # Check for duplicate name
    existing = await db.execute(select(EdgeToken).where(EdgeToken.name == body.name))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Edge token with name '{body.name}' already exists",
        )

    # Generate token and hash
    raw_token = generate_edge_token()
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    token = EdgeToken(
        token_hash=token_hash,
        name=body.name,
        edge_name=body.edge_name,
        region=body.region,
        expires_at=datetime.now(UTC) + timedelta(hours=body.expires_in_hours),
        max_uses=body.max_uses,
        created_by=current_user.email,
    )

    db.add(token)
    await db.commit()
    await db.refresh(token)

    logger.info(
        "Edge token created",
        token_name=body.name,
        edge_name=body.edge_name,
        created_by=current_user.email,
    )

    await log_audit_event(
        db,
        event_type="admin",
        action="edge_token_created",
        actor_type="user",
        actor_id=current_user.email,
        target_type="edge_token",
        target_id=str(token.id),
        success=True,
        details={
            "token_name": body.name,
            "edge_name": body.edge_name,
            "region": body.region,
        },
    )

    return EdgeTokenCreateResponse(
        id=token.id,
        name=token.name,
        edge_name=token.edge_name,
        region=token.region,
        expires_at=token.expires_at,
        max_uses=token.max_uses,
        use_count=token.use_count,
        is_revoked=token.is_revoked,
        created_at=token.created_at,
        created_by=token.created_by,
        token=raw_token,
    )


@router.get("/{token_id}", response_model=EdgeTokenResponse)
async def get_edge_token(
    token_id: UUID,
    db: AsyncSession = Depends(get_db_read),
    current_user: Session = Depends(require_admin_or_audit),
) -> EdgeTokenResponse:
    """Get a single edge token by ID."""
    result = await db.execute(select(EdgeToken).where(EdgeToken.id == token_id))
    token = result.scalar_one_or_none()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Edge token not found",
        )

    return EdgeTokenResponse.from_db(token)


@router.delete("/{token_id}", response_model=SuccessResponse)
async def revoke_edge_token(
    token_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: Session = Depends(require_admin),
) -> SuccessResponse:
    """Revoke an edge token."""
    result = await db.execute(select(EdgeToken).where(EdgeToken.id == token_id))
    token = result.scalar_one_or_none()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Edge token not found",
        )

    if token.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token is already revoked",
        )

    token.is_revoked = True
    await db.commit()

    logger.info(
        "Edge token revoked",
        token_name=token.name,
        revoked_by=current_user.email,
    )

    await log_audit_event(
        db,
        event_type="admin",
        action="edge_token_revoked",
        actor_type="user",
        actor_id=current_user.email,
        target_type="edge_token",
        target_id=str(token.id),
        success=True,
        details={"token_name": token.name, "edge_name": token.edge_name},
    )

    return SuccessResponse(message=f"Edge token '{token.name}' has been revoked")


@router.post("/{token_name}/revoke", response_model=SuccessResponse)
async def revoke_edge_token_by_name(
    token_name: str,
    db: AsyncSession = Depends(get_db),
    current_user: Session = Depends(require_admin),
) -> SuccessResponse:
    """Revoke an edge token by name (CLI convenience)."""
    result = await db.execute(select(EdgeToken).where(EdgeToken.name == token_name))
    token = result.scalar_one_or_none()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Edge token not found: {token_name}",
        )

    if token.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token is already revoked",
        )

    token.is_revoked = True
    await db.commit()

    logger.info(
        "Edge token revoked",
        token_name=token.name,
        revoked_by=current_user.email,
    )

    await log_audit_event(
        db,
        event_type="admin",
        action="edge_token_revoked",
        actor_type="user",
        actor_id=current_user.email,
        target_type="edge_token",
        target_id=str(token.id),
        success=True,
        details={"token_name": token.name, "edge_name": token.edge_name},
    )

    return SuccessResponse(message=f"Edge token '{token.name}' has been revoked")
