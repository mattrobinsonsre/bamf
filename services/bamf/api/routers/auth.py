"""Authentication router.

All authentication — local password, OIDC, SAML — goes through the same
/authorize → login → /callback → /token pipeline. The API server is the
single gateway for all IDP communication. Clients never talk directly to
identity providers.

Consumers:
    Web UI (web/src/lib/auth.ts, web/src/app/login/):
        GET  /api/v1/auth/providers         — login page provider list
        POST /api/v1/auth/local/authorize   — direct JSON login (no redirect)
        POST /api/v1/auth/token             — exchange bamf_code for session
        POST /api/v1/auth/logout            — revoke current session
        GET  /api/v1/auth/sessions          — sessions management page
        GET  /api/v1/auth/sessions/all      — admin sessions view
        DELETE /api/v1/auth/sessions/user/{email} — admin revoke
    Go CLI (planned):
        GET  /api/v1/auth/authorize         — start SSO flow (redirect-based)
        POST /api/v1/auth/token             — exchange bamf_code for session
        POST /api/v1/auth/logout            — revoke session
        GET  /api/v1/auth/ca/public         — download BAMF CA cert

Changes to response shapes must be coordinated with web UI auth code.
"""

import base64
import hashlib
from datetime import datetime

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.api.models.auth import (
    LocalAuthorizeRequest,
    LocalAuthorizeResponse,
    ProviderInfo,
    ProvidersResponse,
    SessionInfo,
    TokenExchangeResponse,
)
from bamf.auth.auth_state import (
    AuthCode,
    AuthState,
    consume_auth_code,
    consume_auth_state,
    generate_code,
    generate_state,
    store_auth_code,
    store_auth_state,
)
from bamf.auth.connectors import get_connector, get_default_connector, list_connectors
from bamf.auth.sessions import (
    create_session,
    get_session,
    list_all_sessions,
    list_user_sessions,
    revoke_all_user_sessions,
    revoke_session,
)
from bamf.config import settings
from bamf.db.session import get_db
from bamf.logging_config import get_logger
from bamf.services.audit_service import log_audit_event
from bamf.services.sso_service import process_login

router = APIRouter(prefix="/auth", tags=["auth"])
logger = get_logger(__name__)


@router.get("/providers", response_model=ProvidersResponse)
async def list_providers() -> ProvidersResponse:
    """List configured auth providers.

    Returns provider names and types for clients to display in login UI.
    """
    providers = [ProviderInfo(**p) for p in list_connectors()]
    return ProvidersResponse(
        providers=providers,
        default_provider=settings.auth.sso.default_provider or None,
    )


@router.get("/authorize")
async def authorize(
    redirect_uri: str = Query(..., description="Client callback URL"),
    code_challenge: str = Query(..., description="PKCE S256 code challenge"),
    state: str = Query(..., description="Client-generated state parameter"),
    response_type: str = Query("code"),
    provider: str = Query("", description="Provider name (default if empty)"),
    code_challenge_method: str = Query("S256"),
) -> RedirectResponse:
    """Start the auth flow.

    Stores auth state in Redis, then redirects (302) to the provider's
    login: an external IDP authorize URL, or BAMF's own local login form.
    """
    if response_type != "code":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only response_type=code is supported",
        )

    if code_challenge_method != "S256":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only S256 code_challenge_method is supported",
        )

    # Resolve provider
    if provider:
        connector = get_connector(provider)
    else:
        connector = get_default_connector()

    if connector is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Provider not found: {provider or '(default)'}",
        )

    # Generate IDP-facing state
    idp_state = generate_state()

    # Build BAMF's callback URL for the IDP
    bamf_callback_url = f"{settings.auth.callback_base_url}{settings.api_prefix}/auth/callback"

    # Build authorization request to the provider
    auth_request = await connector.build_authorization_request(
        callback_url=bamf_callback_url,
        state=idp_state,
    )

    # Store auth state in Redis
    auth_state = AuthState(
        provider_name=connector.name,
        client_redirect_uri=redirect_uri,
        client_state=state,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        idp_state=idp_state,
        nonce=auth_request.nonce,
    )
    await store_auth_state(auth_state)

    logger.info(
        "Authorize: redirecting to provider",
        provider=connector.name,
        client_redirect_uri=redirect_uri,
    )

    return RedirectResponse(url=auth_request.authorize_url, status_code=302)


@router.post("/local/authorize", response_model=LocalAuthorizeResponse)
async def local_authorize(
    body: LocalAuthorizeRequest,
    db: AsyncSession = Depends(get_db),
) -> LocalAuthorizeResponse:
    """Authenticate with local credentials + PKCE in a single JSON call.

    Used by the Web UI to avoid the redirect dance. Combines the work of
    GET /authorize + POST /local/login into one step: validates credentials,
    processes login, and returns a bamf_code that the client exchanges for
    a session via POST /auth/token.

    External IDPs still use the redirect-based GET /authorize flow.
    """
    if body.code_challenge_method != "S256":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only S256 code_challenge_method is supported",
        )

    # Get the local connector
    connector = get_connector("local")
    if connector is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Local authentication is not enabled",
        )

    # Validate credentials
    try:
        identity = await connector.handle_callback(
            callback_url="",
            db=db,
            email=body.email,
            password=body.password,
        )
    except ValueError as e:
        logger.info("Local login failed", email=body.email, error=str(e))
        await log_audit_event(
            db,
            event_type="auth",
            action="login_failed",
            actor_type="user",
            actor_id=body.email,
            success=False,
            error_message=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        ) from e

    # Process login (role resolution — no role writes, no user creation for SSO)
    claims_rules = _get_claims_rules("local")
    login = await process_login(db, identity, claims_rules)

    # Enforce external SSO requirement for restricted roles
    _enforce_external_sso_requirement("local", login.roles)

    await log_audit_event(
        db,
        event_type="auth",
        action="login",
        actor_type="user",
        actor_id=login.email,
        success=True,
        details={"provider": "local", "roles": login.roles},
    )

    # Generate one-time bamf_code
    bamf_code = generate_code()
    auth_code = AuthCode(
        email=login.email,
        roles=login.roles,
        provider_name="local",
        code_challenge=body.code_challenge,
        code_challenge_method=body.code_challenge_method,
        kubernetes_groups=login.kubernetes_groups,
    )
    await store_auth_code(bamf_code, auth_code)

    logger.info("Local authorize: issued code", email=login.email)
    return LocalAuthorizeResponse(code=bamf_code, state=body.state)


@router.post("/local/login")
async def local_login_submit(
    state: str = Form(...),
    email: str = Form(...),
    password: str = Form(...),
    db: AsyncSession = Depends(get_db),
) -> RedirectResponse:
    """Handle local login form submission.

    Validates credentials via the LocalConnector, then follows the same
    callback flow as external IDPs: process login, generate bamf_code,
    redirect to client.
    """
    # Consume auth state (one-time use)
    auth_state = await consume_auth_state(state)
    if auth_state is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired auth state",
        )

    if auth_state.provider_name != "local":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Auth state is not for local provider",
        )

    # Get the local connector
    connector = get_connector("local")
    if connector is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Local provider not configured",
        )

    # Validate credentials
    try:
        identity = await connector.handle_callback(
            callback_url="",
            db=db,
            email=email,
            password=password,
        )
    except ValueError as e:
        logger.info("Local login failed", email=email, error=str(e))
        await log_audit_event(
            db,
            event_type="auth",
            action="login_failed",
            actor_type="user",
            actor_id=email,
            success=False,
            error_message=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        ) from e

    # Process login (role resolution — no role writes, no user creation for SSO)
    claims_rules = _get_claims_rules(auth_state.provider_name)
    login = await process_login(db, identity, claims_rules)

    # Enforce external SSO requirement for restricted roles
    _enforce_external_sso_requirement("local", login.roles)

    await log_audit_event(
        db,
        event_type="auth",
        action="login",
        actor_type="user",
        actor_id=login.email,
        success=True,
        details={"provider": "local", "roles": login.roles},
    )

    # Generate one-time bamf_code
    bamf_code = generate_code()
    auth_code = AuthCode(
        email=login.email,
        roles=login.roles,
        provider_name="local",
        code_challenge=auth_state.code_challenge,
        code_challenge_method=auth_state.code_challenge_method,
        kubernetes_groups=login.kubernetes_groups,
    )
    await store_auth_code(bamf_code, auth_code)

    # Redirect to client with bamf_code + original state
    separator = "&" if "?" in auth_state.client_redirect_uri else "?"
    redirect_url = (
        f"{auth_state.client_redirect_uri}{separator}"
        f"code={bamf_code}&state={auth_state.client_state}"
    )

    logger.info("Local login: redirecting to client", email=login.email)
    return RedirectResponse(url=redirect_url, status_code=302)


@router.get("/callback")
async def callback(
    code: str = Query(..., description="Authorization code from IDP"),
    state: str = Query(..., description="State parameter from IDP"),
    db: AsyncSession = Depends(get_db),
) -> RedirectResponse:
    """Handle the OIDC IDP callback.

    Validates the IDP response, exchanges the code for tokens, processes the
    login, generates a one-time bamf_code, and redirects to the client's
    original redirect_uri.
    """
    # Consume auth state (one-time use)
    auth_state = await consume_auth_state(state)
    if auth_state is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired auth state",
        )

    # Get the connector for this provider
    connector = get_connector(auth_state.provider_name)
    if connector is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Provider {auth_state.provider_name} no longer configured",
        )

    # Exchange code with IDP
    bamf_callback_url = f"{settings.auth.callback_base_url}{settings.api_prefix}/auth/callback"

    try:
        identity = await connector.handle_callback(
            callback_url=bamf_callback_url,
            code=code,
            state=state,
        )
    except ValueError as e:
        logger.error("SSO callback failed", provider=auth_state.provider_name, error=str(e))
        await log_audit_event(
            db,
            event_type="auth",
            action="login_failed",
            actor_type="user",
            success=False,
            error_message=str(e),
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Authentication failed: {e}",
        ) from e

    # Process login (role resolution — no role writes, no user creation for SSO)
    claims_rules = _get_claims_rules(auth_state.provider_name)
    login = await process_login(db, identity, claims_rules)

    # Enforce external SSO requirement for restricted roles
    _enforce_external_sso_requirement(auth_state.provider_name, login.roles)

    await log_audit_event(
        db,
        event_type="auth",
        action="login",
        actor_type="user",
        actor_id=login.email,
        success=True,
        details={"provider": auth_state.provider_name, "roles": login.roles},
    )

    # Cap session TTL at id_token expiry if shorter than configured TTL
    max_session_ttl = _compute_max_session_ttl(identity.id_token_expires_at)

    # Generate one-time bamf_code
    bamf_code = generate_code()
    auth_code = AuthCode(
        email=login.email,
        roles=login.roles,
        provider_name=auth_state.provider_name,
        code_challenge=auth_state.code_challenge,
        code_challenge_method=auth_state.code_challenge_method,
        kubernetes_groups=login.kubernetes_groups,
        max_session_ttl=max_session_ttl,
    )
    await store_auth_code(bamf_code, auth_code)

    # Redirect to client with bamf_code + original state
    separator = "&" if "?" in auth_state.client_redirect_uri else "?"
    redirect_url = (
        f"{auth_state.client_redirect_uri}{separator}"
        f"code={bamf_code}&state={auth_state.client_state}"
    )

    logger.info(
        "Callback: redirecting to client",
        provider=auth_state.provider_name,
        email=login.email,
    )

    return RedirectResponse(url=redirect_url, status_code=302)


@router.post("/saml/acs")
async def saml_acs(
    request: Request,
    db: AsyncSession = Depends(get_db),
) -> RedirectResponse:
    """SAML Assertion Consumer Service endpoint.

    Receives the SAML response via HTTP POST, validates it, processes the
    login, and redirects to the client.
    """
    form = await request.form()
    saml_response = form.get("SAMLResponse")
    relay_state = form.get("RelayState", "")

    if not saml_response:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing SAMLResponse",
        )

    # RelayState contains the IDP state we stored
    auth_state = await consume_auth_state(str(relay_state))
    if auth_state is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired auth state",
        )

    connector = get_connector(auth_state.provider_name)
    if connector is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Provider {auth_state.provider_name} no longer configured",
        )

    bamf_acs_url = f"{settings.auth.callback_base_url}{settings.api_prefix}/auth/saml/acs"

    try:
        identity = await connector.handle_callback(
            callback_url=bamf_acs_url,
            saml_response=str(saml_response),
            relay_state=str(relay_state),
        )
    except ValueError as e:
        logger.error("SAML callback failed", provider=auth_state.provider_name, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"SAML authentication failed: {e}",
        ) from e

    claims_rules = _get_claims_rules(auth_state.provider_name)
    login = await process_login(db, identity, claims_rules)

    # Enforce external SSO requirement for restricted roles
    _enforce_external_sso_requirement(auth_state.provider_name, login.roles)

    await log_audit_event(
        db,
        event_type="auth",
        action="login",
        actor_type="user",
        actor_id=login.email,
        success=True,
        details={"provider": auth_state.provider_name, "roles": login.roles},
    )

    bamf_code = generate_code()
    auth_code = AuthCode(
        email=login.email,
        roles=login.roles,
        provider_name=auth_state.provider_name,
        code_challenge=auth_state.code_challenge,
        code_challenge_method=auth_state.code_challenge_method,
        kubernetes_groups=login.kubernetes_groups,
    )
    await store_auth_code(bamf_code, auth_code)

    separator = "&" if "?" in auth_state.client_redirect_uri else "?"
    redirect_url = (
        f"{auth_state.client_redirect_uri}{separator}"
        f"code={bamf_code}&state={auth_state.client_state}"
    )

    return RedirectResponse(url=redirect_url, status_code=302)


@router.post("/token", response_model=TokenExchangeResponse)
async def exchange_token(
    grant_type: str = Form(...),
    code: str = Form(...),
    code_verifier: str = Form(...),
) -> JSONResponse:
    """Exchange a bamf_code + PKCE verifier for a session.

    This is the final step of the auth flow. The client sends the one-time
    bamf_code and the PKCE code_verifier to prove it initiated the flow.
    Returns an opaque session token backed by Redis.

    Also sets a ``bamf_session`` HTTP cookie on the tunnel parent domain so
    that browser requests to ``*.tunnel.{domain}`` are authenticated
    automatically.
    """
    if grant_type != "authorization_code":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only grant_type=authorization_code is supported",
        )

    # Consume the one-time auth code
    auth_code = await consume_auth_code(code)
    if auth_code is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired authorization code",
        )

    # Verify PKCE: S256(code_verifier) must equal stored code_challenge
    if not _verify_pkce(code_verifier, auth_code.code_challenge, auth_code.code_challenge_method):
        logger.warning("PKCE verification failed", email=auth_code.email)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="PKCE verification failed",
        )

    # Create session in Redis (cap TTL at id_token expiry if set)
    session = await create_session(
        email=auth_code.email,
        display_name=None,
        roles=auth_code.roles,
        provider_name=auth_code.provider_name,
        kubernetes_groups=auth_code.kubernetes_groups,
        max_ttl=auth_code.max_session_ttl,
    )

    logger.info(
        "Session created via auth flow",
        email=auth_code.email,
        provider=auth_code.provider_name,
    )

    body = TokenExchangeResponse(
        session_token=session.token,
        expires_at=session.expires_at,
        email=auth_code.email,
        roles=auth_code.roles,
    )
    response = JSONResponse(content=body.model_dump(mode="json"))

    # Set bamf_session cookie on the parent domain so it covers both the
    # main hostname (bamf.local) and proxy subdomains (*.tunnel.bamf.local).
    # tunnel_domain is "tunnel.bamf.local"; strip the first label to get
    # the parent domain "bamf.local", then prepend dot for the cookie scope.
    tunnel_domain = settings.tunnel_domain
    if tunnel_domain:
        parts = tunnel_domain.split(".", 1)
        parent_domain = parts[1] if len(parts) > 1 else tunnel_domain
        cookie_domain = f".{parent_domain}"
        # Use the capped TTL if the session was shortened by id_token expiry
        max_age = int(settings.auth.session_ttl_hours * 3600)
        if auth_code.max_session_ttl is not None and auth_code.max_session_ttl < max_age:
            max_age = auth_code.max_session_ttl
        response.set_cookie(
            key="bamf_session",
            value=session.token,
            domain=cookie_domain,
            path="/",
            secure=True,
            httponly=True,
            samesite="lax",
            max_age=max_age,
        )

    return response


# --- Session management endpoints ---


@router.get("/sessions", response_model=list[SessionInfo])
async def list_sessions(
    request: Request,
) -> list[SessionInfo]:
    """List active sessions for the current user.

    Requires a valid session token in the Authorization header.
    """
    session = await _require_session(request)
    sessions = await list_user_sessions(session.email)
    return [
        SessionInfo(
            email=s.email,
            roles=s.roles,
            provider_name=s.provider_name,
            created_at=s.created_at,
            expires_at=s.expires_at,
            last_active_at=s.last_active_at,
            token_hint=s.token[-8:],
            is_current=(s.token == session.token),
        )
        for s in sessions
    ]


@router.get("/sessions/all", response_model=list[SessionInfo])
async def list_all_sessions_endpoint(
    request: Request,
) -> list[SessionInfo]:
    """List all active sessions across the platform (admin only)."""
    session = await _require_session(request)
    if "admin" not in session.roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    sessions = await list_all_sessions()
    return [
        SessionInfo(
            email=s.email,
            roles=s.roles,
            provider_name=s.provider_name,
            created_at=s.created_at,
            expires_at=s.expires_at,
            last_active_at=s.last_active_at,
            token_hint=s.token[-8:],
            is_current=(s.token == session.token),
        )
        for s in sessions
    ]


@router.delete("/sessions/user/{email}")
async def revoke_user_sessions(
    email: str,
    request: Request,
) -> dict[str, int]:
    """Revoke all sessions for a specific user (admin only)."""
    session = await _require_session(request)
    if "admin" not in session.roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )

    count = await revoke_all_user_sessions(email)
    logger.info("Admin revoked user sessions", admin=session.email, target=email, count=count)
    return {"revoked": count}


@router.post("/logout")
async def logout(request: Request) -> JSONResponse:
    """Revoke the current session."""
    session = await _require_session(request)
    await revoke_session(session.token)
    logger.info("Session revoked via logout", email=session.email)
    response = JSONResponse(content={"status": "logged_out"})
    _clear_session_cookie(response)
    return response


@router.post("/logout/all")
async def logout_all(request: Request) -> JSONResponse:
    """Revoke all sessions for the current user."""
    session = await _require_session(request)
    count = await revoke_all_user_sessions(session.email)
    logger.info("All sessions revoked", email=session.email, count=count)
    response = JSONResponse(content={"revoked": count})
    _clear_session_cookie(response)
    return response


# --- CA public key ---


@router.get("/ca/public")
async def get_ca_certificate() -> dict[str, str]:
    """Get the BAMF CA public certificate.

    Used by CLI and agents to bootstrap trust for tunnel connections.
    """
    from bamf.auth.ca import get_ca

    try:
        ca = get_ca()
        return {"certificate": ca.ca_cert_pem}
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="CA not initialized",
        ) from e


# --- Helpers ---


def _clear_session_cookie(response: JSONResponse) -> None:
    """Delete the bamf_session cookie by setting max_age=0."""
    tunnel_domain = settings.tunnel_domain
    if tunnel_domain:
        parts = tunnel_domain.split(".", 1)
        parent_domain = parts[1] if len(parts) > 1 else tunnel_domain
        response.delete_cookie(
            key="bamf_session",
            domain=f".{parent_domain}",
            path="/",
        )


async def _require_session(request: Request):
    """Extract and validate the session token from the Authorization header."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = auth_header[7:]
    session = await get_session(token)
    if session is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return session


def _verify_pkce(code_verifier: str, code_challenge: str, method: str) -> bool:
    """Verify PKCE code_verifier against stored code_challenge."""
    if method != "S256":
        return False

    # S256: BASE64URL(SHA256(code_verifier)) == code_challenge
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    computed_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    return computed_challenge == code_challenge


def _enforce_external_sso_requirement(provider_name: str, roles: list[str]) -> None:
    """Enforce require_external_sso_for_roles policy.

    If any of the user's resolved roles are in require_external_sso_for_roles
    and the provider is "local", deny the login.
    """
    restricted_roles = settings.auth.require_external_sso_for_roles
    if not restricted_roles or provider_name != "local":
        return

    violations = [r for r in roles if r in restricted_roles]
    if violations:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Roles {violations} require external SSO login. "
                "Local authentication is not permitted for these roles."
            ),
        )


def _compute_max_session_ttl(id_token_expires_at: datetime | None) -> int | None:
    """Compute max session TTL from id_token expiry.

    Returns the remaining id_token lifetime in seconds if it's shorter than
    the configured session TTL, otherwise None.
    """
    if id_token_expires_at is None:
        return None

    from bamf.db.models import utc_now

    remaining = (id_token_expires_at - utc_now()).total_seconds()
    configured = settings.auth.session_ttl_hours * 3600

    if 0 < remaining < configured:
        return int(remaining)
    return None


def _get_claims_rules(provider_name: str) -> list:
    """Get claims_to_roles rules for a provider from config."""
    for oidc in settings.auth.sso.oidc:
        if oidc.name == provider_name:
            return oidc.claims_to_roles
    for saml in settings.auth.sso.saml:
        if saml.name == provider_name:
            return saml.claims_to_roles
    return []
