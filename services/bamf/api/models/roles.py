"""Role-related Pydantic models."""

from datetime import datetime
from typing import Any

from pydantic import Field

from .common import BAMFBaseModel, NamedModel, TimestampMixin


class PermissionsBlock(BAMFBaseModel):
    """Allow/deny permission block for roles."""

    labels: dict[str, list[str]] = Field(default_factory=dict)
    names: list[str] = Field(default_factory=list)


class RoleBase(NamedModel):
    """Base role model."""

    description: str | None = None


class RoleCreate(RoleBase):
    """Model for creating a role."""

    allow: PermissionsBlock = Field(default_factory=PermissionsBlock)
    deny: PermissionsBlock = Field(default_factory=PermissionsBlock)
    kubernetes_groups: list[str] = Field(default_factory=list)


class RoleUpdate(BAMFBaseModel):
    """Model for updating a role."""

    description: str | None = None
    allow: PermissionsBlock | None = None
    deny: PermissionsBlock | None = None
    kubernetes_groups: list[str] | None = None


class RoleResponse(RoleBase, TimestampMixin):
    """Role response model."""

    is_builtin: bool
    allow: PermissionsBlock
    deny: PermissionsBlock
    kubernetes_groups: list[str] = Field(default_factory=list)

    @classmethod
    def from_db(cls, role: Any) -> "RoleResponse":
        """Create response from a custom database role."""
        return cls(
            name=role.name,
            description=role.description,
            is_builtin=False,
            allow=PermissionsBlock(labels=role.allow_labels, names=role.allow_names),
            deny=PermissionsBlock(labels=role.deny_labels, names=role.deny_names),
            kubernetes_groups=role.kubernetes_groups,
            created_at=role.created_at,
            updated_at=role.updated_at,
        )

    @classmethod
    def builtin(cls, name: str, description: str, now: datetime) -> "RoleResponse":
        """Create response for a built-in role."""
        return cls(
            name=name,
            description=description,
            is_builtin=True,
            allow=PermissionsBlock(),
            deny=PermissionsBlock(),
            kubernetes_groups=[],
            created_at=now,
            updated_at=now,
        )
