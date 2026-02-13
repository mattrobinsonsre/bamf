"""Join token API models.

Join tokens are used for agent registration. Admins create tokens,
agents use them to join the cluster and receive certificates.
"""

from datetime import datetime
from typing import TYPE_CHECKING
from uuid import UUID

from pydantic import Field

from bamf.api.models.common import BAMFBaseModel, NamedModel

if TYPE_CHECKING:
    from bamf.db.models import JoinToken


class JoinTokenCreate(NamedModel):
    """Request to create a join token.

    Web UI contract: web/src/app/tokens/ uses this for token creation.
    """

    expires_in_hours: int = Field(
        default=24,
        ge=1,
        le=8760,  # 1 year max
        description="Hours until token expires",
    )
    max_uses: int | None = Field(
        default=None,
        ge=1,
        description="Maximum number of times the token can be used (null = unlimited)",
    )
    agent_labels: dict[str, str] = Field(
        default_factory=dict,
        description="Labels to apply to agents that use this token",
    )


class JoinTokenResponse(BAMFBaseModel):
    """Join token response (without the secret token value).

    Web UI contract: web/src/app/tokens/ displays token list using this.
    """

    id: UUID
    name: str
    expires_at: datetime
    max_uses: int | None
    use_count: int
    agent_labels: dict[str, str]
    is_revoked: bool
    created_at: datetime
    created_by: str

    @classmethod
    def from_db(cls, token: "JoinToken") -> "JoinTokenResponse":
        """Create response from database model."""
        return cls(
            id=token.id,
            name=token.name,
            expires_at=token.expires_at,
            max_uses=token.max_uses,
            use_count=token.use_count,
            agent_labels=token.agent_labels,
            is_revoked=token.is_revoked,
            created_at=token.created_at,
            created_by=token.created_by,
        )


class JoinTokenCreateResponse(JoinTokenResponse):
    """Response when creating a join token - includes the secret token value.

    IMPORTANT: The token value is only returned once at creation time.
    It cannot be retrieved later - the database only stores the hash.

    Web UI contract: web/src/app/tokens/ shows this token value once
    and instructs the user to copy it.
    """

    token: str = Field(description="The secret token value - only shown once!")
