"""Users router."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.api.dependencies import get_current_user, require_admin, require_admin_or_audit
from bamf.api.models.common import BAMFBaseModel, CursorPage, PaginationParams
from bamf.api.models.users import UserCreate, UserResponse, UserUpdate
from bamf.auth.builtin_roles import is_platform_role
from bamf.auth.passwords import hash_password
from bamf.auth.recent_users import list_recent_users
from bamf.auth.sessions import Session
from bamf.db.models import PlatformRoleAssignment, Role, RoleAssignment, User
from bamf.db.session import get_db, get_db_read
from bamf.logging_config import get_logger
from bamf.services.audit_service import log_audit_event

router = APIRouter(prefix="/users", tags=["users"])
logger = get_logger(__name__)


async def _load_role_assignments(
    db: AsyncSession, email: str
) -> list[RoleAssignment | PlatformRoleAssignment]:
    """Load all role assignments for an email from both tables."""
    result = await db.execute(
        select(RoleAssignment)
        .where(RoleAssignment.email == email)
        .order_by(RoleAssignment.provider_name, RoleAssignment.created_at)
    )
    assignments: list[RoleAssignment | PlatformRoleAssignment] = list(result.scalars().all())

    result = await db.execute(
        select(PlatformRoleAssignment)
        .where(PlatformRoleAssignment.email == email)
        .order_by(PlatformRoleAssignment.provider_name, PlatformRoleAssignment.created_at)
    )
    assignments.extend(result.scalars().all())
    return assignments


@router.get("", response_model=CursorPage[UserResponse])
async def list_users(
    pagination: PaginationParams = Depends(),
    db: AsyncSession = Depends(get_db_read),
    current_user: Session = Depends(get_current_user),
) -> CursorPage[UserResponse]:
    """List all users with pagination."""
    query = select(User).order_by(User.created_at.desc()).limit(pagination.limit + 1)

    if pagination.cursor:
        # Decode cursor (base64 encoded email)
        import base64

        cursor_email = base64.b64decode(pagination.cursor).decode()
        cursor_user = await db.get(User, cursor_email)
        if cursor_user:
            query = query.where(User.created_at < cursor_user.created_at)

    result = await db.execute(query)
    users = list(result.scalars().all())

    has_more = len(users) > pagination.limit
    if has_more:
        users = users[: pagination.limit]

    next_cursor = None
    if has_more and users:
        import base64

        next_cursor = base64.b64encode(users[-1].email.encode()).decode()

    # Load role assignments for each user by email
    items = []
    for u in users:
        assignments = await _load_role_assignments(db, u.email)
        items.append(UserResponse.from_db(u, assignments))

    return CursorPage(
        items=items,
        next_cursor=next_cursor,
        has_more=has_more,
    )


class RecentUserResponse(BAMFBaseModel):
    """A recently-seen user identity."""

    provider_name: str
    email: str
    display_name: str | None
    last_seen: str


@router.get("/recent", response_model=list[RecentUserResponse])
async def get_recent_users(
    _admin: Session = Depends(require_admin_or_audit),
) -> list[RecentUserResponse]:
    """List recently-seen users for admin/audit UX.

    Returns (provider, email) pairs seen in the last 7 days.
    Requires admin or audit role.
    """
    recent = await list_recent_users()
    return [
        RecentUserResponse(
            provider_name=u.provider_name,
            email=u.email,
            display_name=u.display_name,
            last_seen=u.last_seen,
        )
        for u in recent
    ]


@router.post("", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    user_data: UserCreate,
    db: AsyncSession = Depends(get_db),
    current_user: Session = Depends(require_admin),
) -> UserResponse:
    """Create a new user. Requires admin."""
    # Check if email already exists
    existing = await db.get(User, user_data.email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="User with this email already exists",
        )

    # Create user
    user = User(
        email=user_data.email,
        password_hash=hash_password(user_data.password) if user_data.password else None,
        is_active=user_data.is_active,
    )
    db.add(user)

    # Assign roles (internal/local assignments)
    if user_data.roles:
        for role_name in user_data.roles:
            if role_name == "everyone":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="'everyone' is implicit and cannot be assigned",
                )
            if is_platform_role(role_name):
                pra = PlatformRoleAssignment(
                    provider_name="local", email=user.email, role_name=role_name
                )
                db.add(pra)
            else:
                role = await db.get(Role, role_name)
                if not role:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Role '{role_name}' not found",
                    )
                ra = RoleAssignment(provider_name="local", email=user.email, role_name=role_name)
                db.add(ra)

    await db.flush()

    logger.info("User created", email=user.email, created_by=current_user.email)
    await log_audit_event(
        db,
        event_type="admin",
        action="user_created",
        actor_type="user",
        actor_id=current_user.email,
        target_type="user",
        target_id=user.email,
        success=True,
    )

    assignments = await _load_role_assignments(db, user.email)
    return UserResponse.from_db(user, assignments)


@router.get("/{email}", response_model=UserResponse)
async def get_user(
    email: str,
    db: AsyncSession = Depends(get_db_read),
    current_user: Session = Depends(get_current_user),
) -> UserResponse:
    """Get a user by email."""
    user = await db.get(User, email)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    assignments = await _load_role_assignments(db, user.email)
    return UserResponse.from_db(user, assignments)


@router.patch("/{email}", response_model=UserResponse)
async def update_user(
    email: str,
    user_data: UserUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: Session = Depends(require_admin),
) -> UserResponse:
    """Update a user. Requires admin."""
    user = await db.get(User, email)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    # Update fields
    if user_data.is_active is not None:
        user.is_active = user_data.is_active
    if user_data.password is not None:
        user.password_hash = hash_password(user_data.password)

    # Update local role assignments if provided
    if user_data.roles is not None:
        # Remove existing local role assignments from both tables
        existing_custom = await db.execute(
            select(RoleAssignment).where(
                RoleAssignment.provider_name == "local",
                RoleAssignment.email == user.email,
            )
        )
        for ra in existing_custom.scalars().all():
            await db.delete(ra)

        existing_platform = await db.execute(
            select(PlatformRoleAssignment).where(
                PlatformRoleAssignment.provider_name == "local",
                PlatformRoleAssignment.email == user.email,
            )
        )
        for pra in existing_platform.scalars().all():
            await db.delete(pra)

        # Add new local role assignments, split by type
        for role_name in user_data.roles:
            if role_name == "everyone":
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="'everyone' is implicit and cannot be assigned",
                )
            if is_platform_role(role_name):
                pra = PlatformRoleAssignment(
                    provider_name="local", email=user.email, role_name=role_name
                )
                db.add(pra)
            else:
                role = await db.get(Role, role_name)
                if not role:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Role '{role_name}' not found",
                    )
                ra = RoleAssignment(provider_name="local", email=user.email, role_name=role_name)
                db.add(ra)

    await db.flush()

    logger.info("User updated", email=user.email, updated_by=current_user.email)
    await log_audit_event(
        db,
        event_type="admin",
        action="user_updated",
        actor_type="user",
        actor_id=current_user.email,
        target_type="user",
        target_id=user.email,
        success=True,
    )

    assignments = await _load_role_assignments(db, user.email)
    return UserResponse.from_db(user, assignments)


@router.delete("/{email}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(
    email: str,
    db: AsyncSession = Depends(get_db),
    current_user: Session = Depends(require_admin),
) -> None:
    """Delete a user. Requires admin."""
    user = await db.get(User, email)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    await db.delete(user)

    logger.info("User deleted", email=email, deleted_by=current_user.email)
    await log_audit_event(
        db,
        event_type="admin",
        action="user_deleted",
        actor_type="user",
        actor_id=current_user.email,
        target_type="user",
        target_id=email,
        success=True,
    )
