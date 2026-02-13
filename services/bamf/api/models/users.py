"""User-related Pydantic models."""

from datetime import datetime
from typing import Any

from pydantic import EmailStr, Field, field_validator

from bamf.auth.passwords import validate_password_strength

from .common import BAMFBaseModel, TimestampMixin


class UserBase(BAMFBaseModel):
    """Base user model."""

    email: str
    is_active: bool = True


class UserCreate(UserBase):
    """Model for creating a user."""

    email: EmailStr  # Validate email format on creation only
    password: str | None = Field(
        default=None,
        description="Password for local auth (not required for SSO-only users)",
    )
    roles: list[str] = Field(default_factory=list, description="Role names to assign")

    @field_validator("password")
    @classmethod
    def check_password_strength(cls, v: str | None) -> str | None:
        if v is not None:
            validate_password_strength(v)
        return v


class UserUpdate(BAMFBaseModel):
    """Model for updating a user."""

    is_active: bool | None = None
    password: str | None = Field(default=None)
    roles: list[str] | None = None

    @field_validator("password")
    @classmethod
    def check_password_strength(cls, v: str | None) -> str | None:
        if v is not None:
            validate_password_strength(v)
        return v


class UserRoleResponse(BAMFBaseModel):
    """Role assignment in user response."""

    name: str
    provider_name: str
    assigned_at: datetime


class UserResponse(UserBase, TimestampMixin):
    """User response model."""

    roles: list[UserRoleResponse] = Field(default_factory=list)

    @classmethod
    def from_db(cls, user: Any, role_assignments: list[Any] | None = None) -> "UserResponse":
        """Create response from database model.

        Args:
            user: User DB model.
            role_assignments: List of RoleAssignment objects (with .role loaded).
        """
        role_responses = []
        if role_assignments:
            for ra in role_assignments:
                role_responses.append(
                    UserRoleResponse(
                        name=ra.role_name,
                        provider_name=ra.provider_name,
                        assigned_at=ra.created_at,
                    )
                )

        return cls(
            email=user.email,
            is_active=user.is_active,
            roles=role_responses,
            created_at=user.created_at,
            updated_at=user.updated_at,
        )
