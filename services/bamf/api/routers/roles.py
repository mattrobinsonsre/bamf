"""Roles router."""

import base64
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.api.dependencies import get_current_user, require_admin
from bamf.api.models.common import CursorPage, PaginationParams
from bamf.api.models.roles import RoleCreate, RoleResponse, RoleUpdate
from bamf.auth.builtin_roles import BUILTIN_ROLES, is_builtin_role
from bamf.auth.sessions import Session
from bamf.db.models import Role, RoleAssignment
from bamf.db.session import get_db, get_db_read
from bamf.logging_config import get_logger
from bamf.services.audit_service import log_audit_event

router = APIRouter(prefix="/roles", tags=["roles"])
logger = get_logger(__name__)

# Pre-built responses for built-in roles (timestamps are epoch — they always existed)
_EPOCH = datetime(2025, 1, 1, tzinfo=UTC)
_BUILTIN_RESPONSES = [
    RoleResponse.builtin(name=name, description=info["description"], now=_EPOCH)
    for name, info in BUILTIN_ROLES.items()
]


@router.get("", response_model=CursorPage[RoleResponse])
async def list_roles(
    pagination: PaginationParams = Depends(),
    db: AsyncSession = Depends(get_db_read),
    current_user: Session = Depends(get_current_user),
) -> CursorPage[RoleResponse]:
    """List all roles (built-in + custom) with pagination."""
    query = select(Role).order_by(Role.name).limit(pagination.limit + 1)

    if pagination.cursor:
        cursor_name = base64.b64decode(pagination.cursor).decode()
        query = query.where(Role.name > cursor_name)

    result = await db.execute(query)
    roles = list(result.scalars().all())

    has_more = len(roles) > pagination.limit
    if has_more:
        roles = roles[: pagination.limit]

    next_cursor = None
    if has_more and roles:
        next_cursor = base64.b64encode(roles[-1].name.encode()).decode()

    # Prepend built-in roles on first page (no cursor)
    items: list[RoleResponse] = []
    if not pagination.cursor:
        items.extend(_BUILTIN_RESPONSES)

    items.extend(RoleResponse.from_db(r) for r in roles)

    return CursorPage(
        items=items,
        next_cursor=next_cursor,
        has_more=has_more,
    )


@router.post("", response_model=RoleResponse, status_code=status.HTTP_201_CREATED)
async def create_role(
    role_data: RoleCreate,
    db: AsyncSession = Depends(get_db),
    current_user: Session = Depends(require_admin),
) -> RoleResponse:
    """Create a new custom role. Requires admin."""
    if is_builtin_role(role_data.name):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"'{role_data.name}' is a built-in role name",
        )

    # Check if name already exists
    existing = await db.get(Role, role_data.name)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Role with this name already exists",
        )

    role = Role(
        name=role_data.name,
        description=role_data.description,
        allow_labels=role_data.allow.labels,
        allow_names=role_data.allow.names,
        deny_labels=role_data.deny.labels,
        deny_names=role_data.deny.names,
        kubernetes_groups=role_data.kubernetes_groups,
    )
    db.add(role)
    await db.flush()
    await db.refresh(role)

    logger.info("Role created", role_name=role.name, created_by=current_user.email)
    await log_audit_event(
        db,
        event_type="admin",
        action="role_created",
        actor_type="user",
        actor_id=current_user.email,
        target_type="role",
        target_id=role.name,
        success=True,
    )

    return RoleResponse.from_db(role)


@router.get("/{role_name}", response_model=RoleResponse)
async def get_role(
    role_name: str,
    db: AsyncSession = Depends(get_db_read),
    current_user: Session = Depends(get_current_user),
) -> RoleResponse:
    """Get a role by name."""
    # Check built-in roles first
    if role_name in BUILTIN_ROLES:
        return RoleResponse.builtin(
            name=role_name,
            description=BUILTIN_ROLES[role_name]["description"],
            now=_EPOCH,
        )

    role = await db.get(Role, role_name)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found",
        )

    return RoleResponse.from_db(role)


@router.patch("/{role_name}", response_model=RoleResponse)
async def update_role(
    role_name: str,
    role_data: RoleUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: Session = Depends(require_admin),
) -> RoleResponse:
    """Update a custom role. Requires admin."""
    if is_builtin_role(role_name):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot modify built-in roles",
        )

    role = await db.get(Role, role_name)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found",
        )

    if role_data.description is not None:
        role.description = role_data.description
    if role_data.allow is not None:
        role.allow_labels = role_data.allow.labels
        role.allow_names = role_data.allow.names
    if role_data.deny is not None:
        role.deny_labels = role_data.deny.labels
        role.deny_names = role_data.deny.names
    if role_data.kubernetes_groups is not None:
        role.kubernetes_groups = role_data.kubernetes_groups

    await db.flush()
    await db.refresh(role)

    logger.info("Role updated", role_name=role.name, updated_by=current_user.email)
    await log_audit_event(
        db,
        event_type="admin",
        action="role_updated",
        actor_type="user",
        actor_id=current_user.email,
        target_type="role",
        target_id=role.name,
        success=True,
    )

    return RoleResponse.from_db(role)


@router.delete("/{role_name}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_role(
    role_name: str,
    db: AsyncSession = Depends(get_db),
    current_user: Session = Depends(require_admin),
) -> None:
    """Delete a custom role. Requires admin."""
    if is_builtin_role(role_name):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Cannot delete built-in roles",
        )

    role = await db.get(Role, role_name)
    if not role:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role not found",
        )

    # Clean up role assignments (no FK cascade)
    await db.execute(delete(RoleAssignment).where(RoleAssignment.role_name == role_name))
    await db.delete(role)

    logger.info("Role deleted", role_name=role_name, deleted_by=current_user.email)
    await log_audit_event(
        db,
        event_type="admin",
        action="role_deleted",
        actor_type="user",
        actor_id=current_user.email,
        target_type="role",
        target_id=role_name,
        success=True,
    )
