"""Join token management routes.

Join tokens are used for agent registration. Only admins can create,
revoke, and delete tokens. Admin and audit users can list and view tokens.

Consumers:
    Web UI (web/src/app/tokens/):
        GET    /api/v1/tokens          — list tokens
        POST   /api/v1/tokens          — create token
        GET    /api/v1/tokens/{id}     — get token details
        DELETE /api/v1/tokens/{id}     — revoke token
    CLI (cmd/bamf/cmd/tokens.go):
        Same endpoints for CLI token management
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
from bamf.api.models.tokens import (
    JoinTokenCreate,
    JoinTokenCreateResponse,
    JoinTokenResponse,
)
from bamf.auth.sessions import Session
from bamf.db.models import JoinToken
from bamf.db.session import get_db, get_db_read
from bamf.logging_config import get_logger
from bamf.services.audit_service import log_audit_event

router = APIRouter(prefix="/tokens", tags=["tokens"])
logger = get_logger(__name__)


def generate_token() -> str:
    """Generate a secure random token.

    Format: bamf_<32 random hex chars> = 37 chars total.
    The prefix makes tokens easily identifiable in logs/configs.
    """
    return f"bamf_{secrets.token_hex(16)}"


@router.get("", response_model=CursorPage[JoinTokenResponse])
async def list_tokens(
    pagination: PaginationParams = Depends(),
    include_revoked: bool = False,
    db: AsyncSession = Depends(get_db_read),
    current_user: Session = Depends(require_admin_or_audit),
) -> CursorPage[JoinTokenResponse]:
    """List all join tokens.

    Admin and audit users can view all tokens. By default, revoked tokens
    are hidden - use include_revoked=true to see them.
    """
    query = select(JoinToken).order_by(JoinToken.created_at.desc())

    if not include_revoked:
        query = query.where(JoinToken.is_revoked == False)  # noqa: E712

    query = query.limit(pagination.limit + 1)

    if pagination.cursor:
        import base64

        cursor_name = base64.b64decode(pagination.cursor).decode()
        query = query.where(JoinToken.name < cursor_name)

    result = await db.execute(query)
    tokens = list(result.scalars().all())

    has_more = len(tokens) > pagination.limit
    if has_more:
        tokens = tokens[: pagination.limit]

    items = [JoinTokenResponse.from_db(t) for t in tokens]

    next_cursor = None
    if has_more and tokens:
        import base64

        next_cursor = base64.b64encode(tokens[-1].name.encode()).decode()

    return CursorPage(items=items, next_cursor=next_cursor, has_more=has_more)


@router.post("", response_model=JoinTokenCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_token(
    body: JoinTokenCreate,
    db: AsyncSession = Depends(get_db),
    current_user: Session = Depends(require_admin),
) -> JoinTokenCreateResponse:
    """Create a new join token.

    Only admins can create tokens. The secret token value is returned
    only once - it cannot be retrieved later because only the hash
    is stored in the database.
    """
    # Check for duplicate name
    existing = await db.execute(select(JoinToken).where(JoinToken.name == body.name))
    if existing.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Token with name '{body.name}' already exists",
        )

    # Generate token and hash
    raw_token = generate_token()
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()

    # Create token record
    token = JoinToken(
        token_hash=token_hash,
        name=body.name,
        expires_at=datetime.now(UTC) + timedelta(hours=body.expires_in_hours),
        max_uses=body.max_uses,
        agent_labels=body.agent_labels,
        created_by=current_user.email,
    )

    db.add(token)
    await db.commit()
    await db.refresh(token)

    logger.info(
        "Join token created",
        token_name=body.name,
        created_by=current_user.email,
        expires_in_hours=body.expires_in_hours,
        max_uses=body.max_uses,
    )

    await log_audit_event(
        db,
        event_type="admin",
        action="token_created",
        actor_type="user",
        actor_id=current_user.email,
        target_type="join_token",
        target_id=str(token.id),
        success=True,
        details={"token_name": body.name, "max_uses": body.max_uses},
    )

    # Return response with the secret token (only time it's shown)
    response = JoinTokenCreateResponse(
        id=token.id,
        name=token.name,
        expires_at=token.expires_at,
        max_uses=token.max_uses,
        use_count=token.use_count,
        agent_labels=token.agent_labels,
        is_revoked=token.is_revoked,
        created_at=token.created_at,
        created_by=token.created_by,
        token=raw_token,
    )

    return response


@router.get("/{token_id}", response_model=JoinTokenResponse)
async def get_token(
    token_id: UUID,
    db: AsyncSession = Depends(get_db_read),
    current_user: Session = Depends(require_admin_or_audit),
) -> JoinTokenResponse:
    """Get a single join token by ID.

    Admin and audit users can view token details. Note that the secret
    token value is never returned - only metadata.
    """
    result = await db.execute(select(JoinToken).where(JoinToken.id == token_id))
    token = result.scalar_one_or_none()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token not found",
        )

    return JoinTokenResponse.from_db(token)


@router.delete("/{token_id}", response_model=SuccessResponse)
async def revoke_token(
    token_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: Session = Depends(require_admin),
) -> SuccessResponse:
    """Revoke a join token.

    Only admins can revoke tokens. Revoked tokens cannot be used for
    new agent registrations. Existing agents registered with this token
    are not affected.
    """
    result = await db.execute(select(JoinToken).where(JoinToken.id == token_id))
    token = result.scalar_one_or_none()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Token not found",
        )

    if token.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token is already revoked",
        )

    token.is_revoked = True
    await db.commit()

    logger.info(
        "Join token revoked",
        token_name=token.name,
        revoked_by=current_user.email,
    )

    await log_audit_event(
        db,
        event_type="admin",
        action="token_revoked",
        actor_type="user",
        actor_id=current_user.email,
        target_type="join_token",
        target_id=str(token.id),
        success=True,
        details={"token_name": token.name},
    )

    return SuccessResponse(message=f"Token '{token.name}' has been revoked")


@router.post("/{token_name}/revoke", response_model=SuccessResponse)
async def revoke_token_by_name(
    token_name: str,
    db: AsyncSession = Depends(get_db),
    current_user: Session = Depends(require_admin),
) -> SuccessResponse:
    """Revoke a join token by name.

    Convenience endpoint used by the CLI (which works with token names,
    not UUIDs). Equivalent to DELETE /tokens/{id}.
    """
    result = await db.execute(select(JoinToken).where(JoinToken.name == token_name))
    token = result.scalar_one_or_none()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Token not found: {token_name}",
        )

    if token.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Token is already revoked",
        )

    token.is_revoked = True
    await db.commit()

    logger.info(
        "Join token revoked",
        token_name=token.name,
        revoked_by=current_user.email,
    )

    await log_audit_event(
        db,
        event_type="admin",
        action="token_revoked",
        actor_type="user",
        actor_id=current_user.email,
        target_type="join_token",
        target_id=str(token.id),
        success=True,
        details={"token_name": token.name},
    )

    return SuccessResponse(message=f"Token '{token.name}' has been revoked")
