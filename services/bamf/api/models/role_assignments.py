"""Role assignment models for managing (provider, email) → role mappings."""

from datetime import datetime

from pydantic import Field

from .common import BAMFBaseModel


class IdentityResponse(BAMFBaseModel):
    """A known identity that roles can be assigned to.

    Built by merging local users (from DB) with recent SSO logins (from Redis).
    """

    provider_name: str
    email: str
    display_name: str | None = None
    roles: list[str] = Field(default_factory=list)


class RoleAssignmentResponse(BAMFBaseModel):
    """A single role assignment."""

    provider_name: str
    email: str
    role_name: str
    is_platform_role: bool
    created_at: datetime


class RoleAssignmentUpdate(BAMFBaseModel):
    """Set the full list of roles for a (provider, email) pair.

    Replaces all existing assignments for that identity.
    """

    provider_name: str
    email: str
    roles: list[str] = Field(description="Role names to assign (replaces existing)")
