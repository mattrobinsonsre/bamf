"""OIDC identity provider connector.

Uses authlib for OIDC discovery, token exchange, and JWKS-based ID token validation.
"""

import secrets
from typing import Any
from urllib.parse import urlencode

import httpx
from authlib.jose import JsonWebKey
from authlib.jose import jwt as authlib_jwt
from authlib.jose.errors import JoseError

from bamf.auth.sso import AuthenticatedIdentity, AuthorizationRequest, SSOConnector
from bamf.config import OIDCProviderConfig
from bamf.logging_config import get_logger

logger = get_logger(__name__)


class OIDCConnector(SSOConnector):
    """OIDC identity provider connector using authlib."""

    def __init__(self, config: OIDCProviderConfig) -> None:
        self._config = config
        self._discovery: dict[str, Any] | None = None
        self._jwks: Any | None = None

    @property
    def name(self) -> str:
        return self._config.name

    @property
    def provider_type(self) -> str:
        return "oidc"

    async def _ensure_discovery(self) -> dict[str, Any]:
        """Fetch and cache OIDC discovery document."""
        if self._discovery is not None:
            return self._discovery

        discovery_url = self._config.issuer_url.rstrip("/") + "/.well-known/openid-configuration"
        async with httpx.AsyncClient() as client:
            resp = await client.get(discovery_url)
            resp.raise_for_status()
            self._discovery = resp.json()

        logger.info("OIDC discovery loaded", provider=self.name, issuer=self._config.issuer_url)
        return self._discovery

    async def _ensure_jwks(self) -> Any:
        """Fetch and cache JWKS for token verification."""
        if self._jwks is not None:
            return self._jwks

        discovery = await self._ensure_discovery()
        jwks_uri = discovery["jwks_uri"]

        async with httpx.AsyncClient() as client:
            resp = await client.get(jwks_uri)
            resp.raise_for_status()
            self._jwks = JsonWebKey.import_key_set(resp.json())

        return self._jwks

    async def build_authorization_request(
        self,
        callback_url: str,
        state: str,
    ) -> AuthorizationRequest:
        """Build the OIDC authorization URL."""
        discovery = await self._ensure_discovery()
        authorization_endpoint = discovery["authorization_endpoint"]
        nonce = secrets.token_urlsafe(32)

        params = {
            "response_type": "code",
            "client_id": self._config.client_id,
            "redirect_uri": callback_url,
            "scope": " ".join(self._config.scopes),
            "state": state,
            "nonce": nonce,
        }

        authorize_url = f"{authorization_endpoint}?{urlencode(params)}"
        return AuthorizationRequest(
            authorize_url=authorize_url,
            state=state,
            nonce=nonce,
        )

    async def handle_callback(
        self,
        callback_url: str,
        **kwargs: Any,
    ) -> AuthenticatedIdentity:
        """Exchange authorization code for tokens and extract identity."""
        code = kwargs["code"]

        discovery = await self._ensure_discovery()
        token_endpoint = discovery["token_endpoint"]

        # Exchange code for tokens (server-to-server with client_secret)
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": callback_url,
            "client_id": self._config.client_id,
            "client_secret": self._config.client_secret,
        }

        async with httpx.AsyncClient() as client:
            resp = await client.post(token_endpoint, data=token_data)
            resp.raise_for_status()
            token_response = resp.json()

        id_token_raw = token_response.get("id_token")
        if not id_token_raw:
            raise ValueError(f"No id_token in response from {self.name}")

        # Validate ID token with JWKS
        jwks = await self._ensure_jwks()
        try:
            claims = authlib_jwt.decode(
                id_token_raw,
                jwks,
                claims_options={
                    "iss": {"essential": True, "value": self._config.issuer_url.rstrip("/")},
                    "aud": {"essential": True, "value": self._config.client_id},
                },
            )
            claims.validate()
        except JoseError as e:
            raise ValueError(f"ID token validation failed for {self.name}: {e}") from e

        # Extract identity
        subject = claims.get("sub", "")
        email = claims.get("email", "")
        display_name = claims.get("name") or claims.get("preferred_username")
        groups = claims.get("groups", [])
        if isinstance(groups, str):
            groups = [groups]

        logger.info(
            "OIDC authentication successful",
            provider=self.name,
            subject=subject,
            email=email,
        )

        return AuthenticatedIdentity(
            provider_name=self.name,
            subject=subject,
            email=email,
            display_name=display_name,
            groups=groups,
            raw_claims=dict(claims),
        )
