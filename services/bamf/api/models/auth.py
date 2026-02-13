"""Authentication-related Pydantic models."""

from datetime import datetime

from pydantic import Field

from .common import BAMFBaseModel


class LoginRequest(BAMFBaseModel):
    """Local authentication login request (POST /auth/local/login form data)."""

    email: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class LocalAuthorizeRequest(BAMFBaseModel):
    """Local auth request combining credentials + PKCE in a single JSON call.

    Used by the Web UI to authenticate without redirects. The Web UI collects
    credentials inline and submits them with PKCE parameters directly.
    """

    email: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)
    code_challenge: str = Field(..., description="PKCE S256 code challenge")
    code_challenge_method: str = Field(default="S256")
    state: str = Field(..., description="Client-generated state parameter")


class LocalAuthorizeResponse(BAMFBaseModel):
    """Response from POST /auth/local/authorize.

    Returns a one-time bamf_code that the client exchanges for a session
    via POST /auth/token with the PKCE code_verifier.
    """

    code: str
    state: str


class TokenExchangeResponse(BAMFBaseModel):
    """Response from POST /auth/token (bamf_code exchange).

    Returns an opaque session token, not a JWT.
    """

    session_token: str
    expires_at: datetime
    email: str
    roles: list[str] = Field(default_factory=list)


class ProviderInfo(BAMFBaseModel):
    """Public information about a configured auth provider."""

    name: str
    type: str  # 'local', 'oidc', or 'saml'


class ProvidersResponse(BAMFBaseModel):
    """Response from GET /auth/providers."""

    providers: list[ProviderInfo]
    default_provider: str | None = None


class SessionInfo(BAMFBaseModel):
    """Information about an active session."""

    email: str
    roles: list[str] = Field(default_factory=list)
    provider_name: str
    created_at: datetime
    expires_at: datetime
    last_active_at: datetime
    token_hint: str = Field(description="Last 8 chars of session token")
    is_current: bool = Field(default=False, description="Whether this is the requester's session")
