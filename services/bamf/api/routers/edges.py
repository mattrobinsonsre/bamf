"""Edge management routes.

Edges are regional proxy+bridge clusters that register with the
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
from bamf.api.models.edges import (
    EdgeJoinRequest,
    EdgeJoinResponse,
    EdgeResponse,
)
from bamf.auth.ca import get_ca
from bamf.auth.sessions import Session
from bamf.config import settings
from bamf.db.models import Edge, EdgeToken
from bamf.db.session import get_db, get_db_read
from bamf.logging_config import get_logger
from bamf.services.audit_service import log_audit_event

router = APIRouter(prefix="/edges", tags=["edges"])
logger = get_logger(__name__)


def _generate_internal_token() -> str:
    """Generate an internal proxy auth token.

    Format: edge_int_<32 random hex chars>.
    """
    return f"edge_int_{secrets.token_hex(16)}"


def _generate_bridge_bootstrap_token() -> str:
    """Generate a bridge bootstrap token.

    Format: edge_brg_<32 random hex chars>.
    """
    return f"edge_brg_{secrets.token_hex(16)}"


@router.post("/join", response_model=EdgeJoinResponse, status_code=status.HTTP_201_CREATED)
async def join_edge(
    request: EdgeJoinRequest,
    db: AsyncSession = Depends(get_db),
) -> EdgeJoinResponse:
    """Register an edge using a join token.

    Validates the join token, creates or updates the edge record,
    generates internal and bridge bootstrap tokens, and returns them
    along with the CA certificate.

    No authentication required — the join token IS the credential.
    """
    token_hash = hashlib.sha256(request.join_token.encode()).hexdigest()

    result = await db.execute(select(EdgeToken).where(EdgeToken.token_hash == token_hash))
    token = result.scalar_one_or_none()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid edge join token",
        )

    now = datetime.now(UTC)

    if token.is_revoked:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Edge join token has been revoked",
        )

    if token.expires_at < now:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Edge join token has expired",
        )

    if token.max_uses is not None and token.use_count >= token.max_uses:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Edge join token has reached maximum uses",
        )

    # Generate auth tokens
    internal_token = _generate_internal_token()
    bridge_bootstrap_token = _generate_bridge_bootstrap_token()
    internal_token_hash = hashlib.sha256(internal_token.encode()).hexdigest()
    bridge_bootstrap_token_hash = hashlib.sha256(bridge_bootstrap_token.encode()).hexdigest()

    # Check if edge with this name already exists (re-join)
    existing_result = await db.execute(select(Edge).where(Edge.name == token.edge_name))
    edge = existing_result.scalar_one_or_none()

    if edge:
        # Re-join: regenerate both tokens (invalidates old deployment)
        edge.internal_token_hash = internal_token_hash
        edge.bridge_bootstrap_token_hash = bridge_bootstrap_token_hash
        edge.region = token.region
        edge.updated_at = now
        logger.info(
            "Edge re-joined",
            edge_name=edge.name,
            edge_id=str(edge.id),
        )
    else:
        # New edge
        edge = Edge(
            name=token.edge_name,
            region=token.region,
            internal_token_hash=internal_token_hash,
            bridge_bootstrap_token_hash=bridge_bootstrap_token_hash,
        )
        db.add(edge)
        logger.info(
            "Edge registered",
            edge_name=token.edge_name,
        )

    # Increment token use count
    token.use_count += 1

    await db.commit()
    await db.refresh(edge)

    # Get CA certificate
    ca = get_ca()

    await log_audit_event(
        db,
        event_type="admin",
        action="edge_joined",
        actor_type="system",
        actor_id=token.edge_name,
        target_type="edge",
        target_id=str(edge.id),
        success=True,
        details={
            "edge_name": edge.name,
            "region": edge.region,
            "join_token_name": token.name,
        },
    )

    return EdgeJoinResponse(
        edge_id=edge.id,
        edge_name=edge.name,
        region=edge.region,
        internal_token=internal_token,
        bridge_bootstrap_token=bridge_bootstrap_token,
        ca_certificate=ca.ca_cert_pem,
        tunnel_domain=settings.tunnel_domain or "",
    )


@router.get("", response_model=CursorPage[EdgeResponse])
async def list_edges(
    pagination: PaginationParams = Depends(),
    include_inactive: bool = False,
    db: AsyncSession = Depends(get_db_read),
    current_user: Session = Depends(require_admin_or_audit),
) -> CursorPage[EdgeResponse]:
    """List all registered edges."""
    query = select(Edge).order_by(Edge.created_at.desc())

    if not include_inactive:
        query = query.where(Edge.is_active == True)  # noqa: E712

    query = query.limit(pagination.limit + 1)

    if pagination.cursor:
        import base64

        cursor_name = base64.b64decode(pagination.cursor).decode()
        query = query.where(Edge.name < cursor_name)

    result = await db.execute(query)
    edges = list(result.scalars().all())

    has_more = len(edges) > pagination.limit
    if has_more:
        edges = edges[: pagination.limit]

    items = [EdgeResponse.from_db(s) for s in edges]

    next_cursor = None
    if has_more and edges:
        import base64

        next_cursor = base64.b64encode(edges[-1].name.encode()).decode()

    return CursorPage(items=items, next_cursor=next_cursor, has_more=has_more)


@router.get("/{edge_id}", response_model=EdgeResponse)
async def get_edge(
    edge_id: UUID,
    db: AsyncSession = Depends(get_db_read),
    current_user: Session = Depends(require_admin_or_audit),
) -> EdgeResponse:
    """Get a single edge by ID."""
    result = await db.execute(select(Edge).where(Edge.id == edge_id))
    edge = result.scalar_one_or_none()

    if not edge:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Edge not found",
        )

    return EdgeResponse.from_db(edge)


@router.delete("/{edge_id}", response_model=SuccessResponse)
async def deactivate_edge(
    edge_id: UUID,
    db: AsyncSession = Depends(get_db),
    current_user: Session = Depends(require_admin),
) -> SuccessResponse:
    """Deactivate an edge.

    Deactivated edges cannot authenticate. Their proxy and bridge
    pods will fail auth and stop serving traffic. Bridge registrations
    expire via Redis TTL. Agent relay connections are disconnected.
    """
    result = await db.execute(select(Edge).where(Edge.id == edge_id))
    edge = result.scalar_one_or_none()

    if not edge:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Edge not found",
        )

    if not edge.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Edge is already deactivated",
        )

    edge.is_active = False
    await db.commit()

    logger.info(
        "Edge deactivated",
        edge_name=edge.name,
        deactivated_by=current_user.email,
    )

    await log_audit_event(
        db,
        event_type="admin",
        action="edge_deactivated",
        actor_type="user",
        actor_id=current_user.email,
        target_type="edge",
        target_id=str(edge.id),
        success=True,
        details={"edge_name": edge.name},
    )

    return SuccessResponse(message=f"Edge '{edge.name}' has been deactivated")
