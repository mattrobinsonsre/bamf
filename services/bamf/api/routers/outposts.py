"""Outpost management routes.

Outposts are regional proxy+bridge clusters that register with the
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
from bamf.api.models.outposts import (
    OutpostJoinRequest,
    OutpostJoinResponse,
    OutpostResponse,
)
from bamf.auth.ca import get_ca
from bamf.auth.sessions import Session
from bamf.config import settings
from bamf.db.models import Outpost, OutpostToken
from bamf.db.session import get_db, get_db_read
from bamf.logging_config import get_logger
from bamf.services.audit_service import log_audit_event

router = APIRouter(prefix="/outposts", tags=["outposts"])
logger = get_logger(__name__)


def _generate_internal_token() -> str:
    """Generate an internal proxy auth token.

    Format: out_int_<32 random hex chars>.
    """
    return f"out_int_{secrets.token_hex(16)}"


def _generate_bridge_bootstrap_token() -> str:
    """Generate a bridge bootstrap token.

    Format: out_brg_<32 random hex chars>.
    """
    return f"out_brg_{secrets.token_hex(16)}"


@router.post("/join", response_model=OutpostJoinResponse, status_code=status.HTTP_201_CREATED)
async def join_outpost(
    request: OutpostJoinRequest,
    db: AsyncSession = Depends(get_db),
) -> OutpostJoinResponse:
    """Register an outpost using a join token.

    Validates the join token, creates or updates the outpost record,
    generates internal and bridge bootstrap tokens, and returns them
    along with the CA certificate.

    No authentication required — the join token IS the credential.
    """
    token_hash = hashlib.sha256(request.join_token.encode()).hexdigest()

    result = await db.execute(select(OutpostToken).where(OutpostToken.token_hash == token_hash))
    token = result.scalar_one_or_none()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid outpost join token",
        )

    now = datetime.now(UTC)

    if token.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Outpost join token has been revoked",
        )

    if token.expires_at < now:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Outpost join token has expired",
        )

    if token.max_uses is not None and token.use_count >= token.max_uses:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Outpost join token has reached maximum uses",
        )

    # Generate auth tokens
    internal_token = _generate_internal_token()
    bridge_bootstrap_token = _generate_bridge_bootstrap_token()
    internal_token_hash = hashlib.sha256(internal_token.encode()).hexdigest()
    bridge_bootstrap_token_hash = hashlib.sha256(bridge_bootstrap_token.encode()).hexdigest()

    # Check if outpost with this name already exists (re-join)
    existing_result = await db.execute(select(Outpost).where(Outpost.name == token.outpost_name))
    outpost = existing_result.scalar_one_or_none()

    if outpost:
        # Re-join: regenerate both tokens (invalidates old deployment)
        outpost.internal_token_hash = internal_token_hash
        outpost.bridge_bootstrap_token_hash = bridge_bootstrap_token_hash
        outpost.region = token.region
        outpost.updated_at = now
        logger.info(
            "Outpost re-joined",
            outpost_name=outpost.name,
            outpost_id=str(outpost.id),
        )
    else:
        # New outpost
        outpost = Outpost(
            name=token.outpost_name,
            region=token.region,
            internal_token_hash=internal_token_hash,
            bridge_bootstrap_token_hash=bridge_bootstrap_token_hash,
        )
        db.add(outpost)
        logger.info(
            "Outpost registered",
            outpost_name=token.outpost_name,
        )

    # Increment token use count
    token.use_count += 1

    await db.commit()
    await db.refresh(outpost)

    # Get CA certificate
    ca = get_ca()

    await log_audit_event(
        db,
        event_type="admin",
        action="outpost_joined",
        actor_type="system",
        actor_id=token.outpost_name,
        target_type="outpost",
        target_id=str(outpost.id),
        success=True,
        details={
            "outpost_name": outpost.name,
            "region": outpost.region,
            "join_token_name": token.name,
        },
    )

    return OutpostJoinResponse(
        outpost_id=outpost.id,
        outpost_name=outpost.name,
        region=outpost.region,
        internal_token=internal_token,
        bridge_bootstrap_token=bridge_bootstrap_token,
        ca_certificate=ca.ca_cert_pem,
        tunnel_domain=settings.tunnel_domain or "",
    )


@router.get("", response_model=CursorPage[OutpostResponse])
async def list_outposts(
    pagination: PaginationParams = Depends(),
    include_inactive: bool = False,
    db: AsyncSession = Depends(get_db_read),
    current_user: Session = Depends(require_admin_or_audit),
) -> CursorPage[OutpostResponse]:
    """List all registered outposts."""
    query = select(Outpost).order_by(Outpost.created_at.desc())

    if not include_inactive:
        query = query.where(Outpost.is_active == True)  # noqa: E712

    query = query.limit(pagination.limit + 1)

    if pagination.cursor:
        import base64

        cursor_name = base64.b64decode(pagination.cursor).decode()
        query = query.where(Outpost.name < cursor_name)

    result = await db.execute(query)
    outposts = list(result.scalars().all())

    has_more = len(outposts) > pagination.limit
    if has_more:
        outposts = outposts[: pagination.limit]

    items = [OutpostResponse.from_db(s) for s in outposts]

    next_cursor = None
    if has_more and outposts:
        import base64

        next_cursor = base64.b64encode(outposts[-1].name.encode()).decode()

    return CursorPage(items=items, next_cursor=next_cursor, has_more=has_more)


@router.get("/{outpost_id}", response_model=OutpostResponse)
async def get_outpost(
    outpost_id: UUID,
    db: AsyncSession = Depends(get_db_read),
    current_user: Session = Depends(require_admin_or_audit),
) -> OutpostResponse:
    """Get a single outpost by ID."""
    result = await db.execute(select(Outpost).where(Outpost.id == outpost_id))
    outpost = result.scalar_one_or_none()

    if not outpost:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Outpost not found",
        )

    return OutpostResponse.from_db(outpost)


@router.delete("/{outpost_id}", response_model=SuccessResponse)
async def deactivate_outpost(
    outpost_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: Session = Depends(require_admin),
) -> SuccessResponse:
    """Deactivate an outpost.

    Deactivated outposts cannot authenticate. Their proxy and bridge
    pods will fail auth and stop serving traffic. Bridge registrations
    expire via Redis TTL. Agent relay connections are disconnected.
    """
    result = await db.execute(select(Outpost).where(Outpost.id == outpost_id))
    outpost = result.scalar_one_or_none()

    if not outpost:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Outpost not found",
        )

    if not outpost.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Outpost is already deactivated",
        )

    outpost.is_active = False
    await db.commit()

    logger.info(
        "Outpost deactivated",
        outpost_name=outpost.name,
        deactivated_by=current_user.email,
    )

    await log_audit_event(
        db,
        event_type="admin",
        action="outpost_deactivated",
        actor_type="user",
        actor_id=current_user.email,
        target_type="outpost",
        target_id=str(outpost.id),
        success=True,
        details={"outpost_name": outpost.name},
    )

    return SuccessResponse(message=f"Outpost '{outpost.name}' has been deactivated")
