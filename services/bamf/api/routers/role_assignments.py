"""Role assignments router.

Manages role assignments for any (provider, email) pair — works for both
local users (in the users table) and SSO users (not in the users table).

Key endpoints:
    GET  /role-assignments/identities — merged list of known identities
         from three sources: users table, Redis recent-login cache, and
         role assignment tables. Used by admin UX for the role assignment form.
    GET  /role-assignments/stale      — (provider, email) pairs that have
         role assignments in the DB but no recent login in Redis.
    GET  /role-assignments             — list all role assignments
    PUT  /role-assignments             — set roles for a (provider, email) pair
    DELETE /role-assignments/{provider}/{email}/{role} — remove one assignment
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import delete, select, union_all
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.api.dependencies import require_admin, require_admin_or_audit
from bamf.api.models.role_assignments import (
    IdentityResponse,
    RoleAssignmentResponse,
    RoleAssignmentUpdate,
)
from bamf.auth.builtin_roles import is_platform_role
from bamf.auth.recent_users import list_recent_users
from bamf.auth.sessions import Session
from bamf.db.models import PlatformRoleAssignment, Role, RoleAssignment, User
from bamf.db.session import get_db, get_db_read
from bamf.logging_config import get_logger
from bamf.services.audit_service import log_audit_event

router = APIRouter(prefix="/role-assignments", tags=["role-assignments"])
logger = get_logger(__name__)


async def _get_roles_for_identity(db: AsyncSession, provider_name: str, email: str) -> list[str]:
    """Load all role names for a (provider, email) pair from both tables."""
    roles: list[str] = []

    result = await db.execute(
        select(RoleAssignment.role_name).where(
            RoleAssignment.provider_name == provider_name,
            RoleAssignment.email == email,
        )
    )
    roles.extend(result.scalars().all())

    result = await db.execute(
        select(PlatformRoleAssignment.role_name).where(
            PlatformRoleAssignment.provider_name == provider_name,
            PlatformRoleAssignment.email == email,
        )
    )
    roles.extend(result.scalars().all())

    return sorted(roles)


async def _get_assigned_identity_keys(
    db: AsyncSession,
) -> set[tuple[str, str]]:
    """Get all distinct (provider_name, email) pairs from both assignment tables."""
    q = union_all(
        select(RoleAssignment.provider_name, RoleAssignment.email),
        select(PlatformRoleAssignment.provider_name, PlatformRoleAssignment.email),
    )
    result = await db.execute(q)
    return {(row[0], row[1]) for row in result.all()}


@router.get("/identities", response_model=list[IdentityResponse])
async def list_identities(
    db: AsyncSession = Depends(get_db_read),
    _admin: Session = Depends(require_admin_or_audit),
) -> list[IdentityResponse]:
    """List known identities for role assignment.

    Merges three sources:
    1. Local users from the users table (provider_name="local")
    2. Recent logins from the Redis cache (any provider)
    3. (provider, email) pairs that have role assignments in the DB but
       aren't in either of the above sources (pre-provisioned or stale)

    Each identity includes its current role assignments from the DB.
    Deduplicated by (provider_name, email).
    """
    seen: dict[tuple[str, str], IdentityResponse] = {}

    # Source 1: local users from DB
    result = await db.execute(select(User).order_by(User.email))
    for user in result.scalars().all():
        key = ("local", user.email)
        roles = await _get_roles_for_identity(db, "local", user.email)
        seen[key] = IdentityResponse(
            provider_name="local",
            email=user.email,
            display_name=user.display_name,
            roles=roles,
        )

    # Source 2: recent logins from Redis
    recent = await list_recent_users()
    for ru in recent:
        key = (ru.provider_name, ru.email)
        if key in seen:
            # Already have this identity from users table; update display_name
            # if Redis has one and DB didn't
            if ru.display_name and not seen[key].display_name:
                seen[key].display_name = ru.display_name
            continue

        roles = await _get_roles_for_identity(db, ru.provider_name, ru.email)

        # For local provider users not in the users table (Source 1), only
        # include them if they have role assignments. External SSO users are
        # always included — they authenticated via their IDP, so they're real
        # users even without roles. Local users not in the DB with no roles
        # are likely stale cache entries from test/bootstrap.
        if ru.provider_name == "local" and not roles:
            continue

        seen[key] = IdentityResponse(
            provider_name=ru.provider_name,
            email=ru.email,
            display_name=ru.display_name,
            roles=roles,
        )

    # Source 3: assigned identities not in sources 1 or 2
    assigned_keys = await _get_assigned_identity_keys(db)
    for provider_name, email in assigned_keys:
        key = (provider_name, email)
        if key in seen:
            continue
        roles = await _get_roles_for_identity(db, provider_name, email)
        seen[key] = IdentityResponse(
            provider_name=provider_name,
            email=email,
            display_name=None,
            roles=roles,
        )

    # Sort: local first, then by email
    items = sorted(
        seen.values(),
        key=lambda i: (0 if i.provider_name == "local" else 1, i.email),
    )
    return items


@router.get("/stale", response_model=list[IdentityResponse])
async def list_stale_assignments(
    db: AsyncSession = Depends(get_db_read),
    _admin: Session = Depends(require_admin_or_audit),
) -> list[IdentityResponse]:
    """List (provider, email) pairs that have role assignments but no recent login.

    These are identities in the role_assignments / platform_role_assignments
    tables that do NOT appear in the Redis recent-login cache. Useful for
    identifying pre-provisioned assignments or cleaning up stale ones.
    """
    # Get all (provider, email) pairs with assignments
    assigned_keys = await _get_assigned_identity_keys(db)

    # Get recent logins from Redis
    recent = await list_recent_users()
    recent_keys = {(ru.provider_name, ru.email) for ru in recent}

    # Stale = assigned but not recently seen
    stale_keys = assigned_keys - recent_keys

    items: list[IdentityResponse] = []
    for provider_name, email in stale_keys:
        roles = await _get_roles_for_identity(db, provider_name, email)
        items.append(
            IdentityResponse(
                provider_name=provider_name,
                email=email,
                display_name=None,
                roles=roles,
            )
        )

    items.sort(key=lambda i: (0 if i.provider_name == "local" else 1, i.email))
    return items


@router.get("", response_model=list[RoleAssignmentResponse])
async def list_role_assignments(
    db: AsyncSession = Depends(get_db_read),
    _admin: Session = Depends(require_admin_or_audit),
) -> list[RoleAssignmentResponse]:
    """List all role assignments from both tables."""
    items: list[RoleAssignmentResponse] = []

    result = await db.execute(
        select(RoleAssignment).order_by(
            RoleAssignment.provider_name, RoleAssignment.email, RoleAssignment.role_name
        )
    )
    for ra in result.scalars().all():
        items.append(
            RoleAssignmentResponse(
                provider_name=ra.provider_name,
                email=ra.email,
                role_name=ra.role_name,
                is_platform_role=False,
                created_at=ra.created_at,
            )
        )

    result = await db.execute(
        select(PlatformRoleAssignment).order_by(
            PlatformRoleAssignment.provider_name,
            PlatformRoleAssignment.email,
            PlatformRoleAssignment.role_name,
        )
    )
    for pra in result.scalars().all():
        items.append(
            RoleAssignmentResponse(
                provider_name=pra.provider_name,
                email=pra.email,
                role_name=pra.role_name,
                is_platform_role=True,
                created_at=pra.created_at,
            )
        )

    return items


@router.put("", response_model=list[str])
async def set_role_assignments(
    body: RoleAssignmentUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: Session = Depends(require_admin),
) -> list[str]:
    """Set the full list of roles for a (provider, email) pair.

    Replaces all existing role assignments for this identity.
    Returns the final list of assigned role names.
    """
    provider = body.provider_name
    email = body.email

    # Validate: 'everyone' is implicit
    for role_name in body.roles:
        if role_name == "everyone":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="'everyone' is implicit and cannot be assigned",
            )

    # Validate non-platform roles exist in the roles table
    for role_name in body.roles:
        if not is_platform_role(role_name):
            role = await db.get(Role, role_name)
            if not role:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Role '{role_name}' not found",
                )

    # Delete existing assignments for this (provider, email)
    await db.execute(
        delete(RoleAssignment).where(
            RoleAssignment.provider_name == provider,
            RoleAssignment.email == email,
        )
    )
    await db.execute(
        delete(PlatformRoleAssignment).where(
            PlatformRoleAssignment.provider_name == provider,
            PlatformRoleAssignment.email == email,
        )
    )

    # Insert new assignments, routing to correct table by role type
    for role_name in body.roles:
        if is_platform_role(role_name):
            db.add(
                PlatformRoleAssignment(
                    provider_name=provider,
                    email=email,
                    role_name=role_name,
                )
            )
        else:
            db.add(
                RoleAssignment(
                    provider_name=provider,
                    email=email,
                    role_name=role_name,
                )
            )

    await db.flush()

    logger.info(
        "Role assignments updated",
        provider=provider,
        email=email,
        roles=body.roles,
        updated_by=current_user.email,
    )
    await log_audit_event(
        db,
        event_type="admin",
        action="role_assignments_updated",
        actor_type="user",
        actor_id=current_user.email,
        target_type="identity",
        target_id=f"{provider}:{email}",
        success=True,
        details={"roles": body.roles},
    )

    return sorted(body.roles)


@router.delete(
    "/{provider_name}/{email}/{role_name}",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_role_assignment(
    provider_name: str,
    email: str,
    role_name: str,
    db: AsyncSession = Depends(get_db),
    current_user: Session = Depends(require_admin),
) -> None:
    """Remove a single role assignment."""
    deleted = False

    if is_platform_role(role_name):
        result = await db.execute(
            delete(PlatformRoleAssignment).where(
                PlatformRoleAssignment.provider_name == provider_name,
                PlatformRoleAssignment.email == email,
                PlatformRoleAssignment.role_name == role_name,
            )
        )
        deleted = result.rowcount > 0
    else:
        result = await db.execute(
            delete(RoleAssignment).where(
                RoleAssignment.provider_name == provider_name,
                RoleAssignment.email == email,
                RoleAssignment.role_name == role_name,
            )
        )
        deleted = result.rowcount > 0

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Role assignment not found",
        )

    logger.info(
        "Role assignment deleted",
        provider=provider_name,
        email=email,
        role_name=role_name,
        deleted_by=current_user.email,
    )
    await log_audit_event(
        db,
        event_type="admin",
        action="role_assignment_deleted",
        actor_type="user",
        actor_id=current_user.email,
        target_type="identity",
        target_id=f"{provider_name}:{email}",
        success=True,
        details={"role_name": role_name},
    )
