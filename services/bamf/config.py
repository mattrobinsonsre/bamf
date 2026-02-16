"""
Configuration management for BAMF API server.

Non-secret configuration loaded from YAML file, secrets from environment variables.
"""

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field, PostgresDsn, RedisDsn
from pydantic_settings import BaseSettings, SettingsConfigDict


def yaml_config_settings_source() -> dict[str, Any]:
    """Load configuration from YAML file."""
    config_path = Path("/etc/bamf/config.yaml")
    if config_path.exists():
        with open(config_path) as f:
            return yaml.safe_load(f) or {}
    return {}


# --- SSO Configuration Models ---


class ClaimsToRolesMapping(BaseModel):
    """Maps an IDP claim value to BAMF roles."""

    claim: str = Field(description="Claim name (e.g., 'groups', 'https://myorg.com/roles')")
    value: str = Field(description="Claim value to match")
    roles: list[str] = Field(description="BAMF roles to assign when matched")


class OIDCProviderConfig(BaseModel):
    """Configuration for a single OIDC identity provider."""

    name: str = Field(description="Unique provider name (e.g., 'auth0', 'okta')")
    issuer_url: str = Field(description="OIDC issuer URL for discovery")
    client_id: str = Field(description="OAuth2 client ID")
    client_secret: str = Field(default="", description="OAuth2 client secret (from env)")
    scopes: list[str] = Field(
        default=["openid", "profile", "email"],
        description="OAuth2 scopes to request",
    )
    claims_to_roles: list[ClaimsToRolesMapping] = Field(
        default_factory=list,
        description="Rules mapping IDP claims to BAMF roles",
    )


class SAMLProviderConfig(BaseModel):
    """Configuration for a single SAML identity provider."""

    name: str = Field(description="Unique provider name (e.g., 'azure-ad')")
    metadata_url: str = Field(description="IDP metadata URL")
    entity_id: str = Field(default="", description="SP entity ID")
    acs_url: str = Field(default="", description="Assertion consumer service URL")
    claims_to_roles: list[ClaimsToRolesMapping] = Field(
        default_factory=list,
        description="Rules mapping SAML attributes to BAMF roles",
    )


class SSOConfig(BaseModel):
    """SSO configuration with multiple providers."""

    default_provider: str = Field(
        default="",
        description="Default provider for 'bamf login' when no --provider given",
    )
    oidc: list[OIDCProviderConfig] = Field(
        default_factory=list,
        description="OIDC identity providers",
    )
    saml: list[SAMLProviderConfig] = Field(
        default_factory=list,
        description="SAML identity providers",
    )


class AuthConfig(BaseSettings):
    """Authentication configuration."""

    local_enabled: bool = Field(default=True, description="Enable local username/password auth")
    callback_base_url: str = Field(
        default="http://localhost:8000",
        description="Base URL for IDP callbacks (BAMF's externally-reachable URL)",
    )
    sso: SSOConfig = Field(default_factory=SSOConfig)
    session_ttl_hours: int = Field(
        default=12,
        description="Session TTL in hours",
    )
    require_external_sso_for_roles: list[str] = Field(
        default_factory=list,
        description="Roles that require external SSO login (excludes local provider)",
    )


class CertificateConfig(BaseSettings):
    """Certificate authority configuration."""

    user_ttl_hours: int = Field(default=12, description="User certificate TTL in hours")
    agent_ttl_hours: int = Field(
        default=8760, description="Agent certificate TTL in hours (1 year)"
    )
    bridge_ttl_hours: int = Field(default=24, description="Bridge certificate TTL in hours")


class AuditConfig(BaseSettings):
    """Audit log configuration."""

    retention_days: int = Field(default=90, description="Audit log retention in days")


class Settings(BaseSettings):
    """Main application settings."""

    model_config = SettingsConfigDict(
        env_prefix="BAMF_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    # Application
    app_name: str = Field(default="bamf-api")
    debug: bool = Field(default=False)
    log_level: str = Field(default="INFO")
    json_logs: bool = Field(default=True, description="JSON logging in production")

    # Database - URL from environment (contains secrets)
    database_url: PostgresDsn = Field(
        default="postgresql+asyncpg://bamf:bamf@localhost:5432/bamf",
        description="PostgreSQL connection URL (read-write primary)",
    )

    # Read replica - optional, falls back to database_url if not set
    database_read_url: PostgresDsn | None = Field(
        default=None,
        description="PostgreSQL read replica URL. Falls back to database_url if not set.",
    )

    # Redis - URL from environment (may contain secrets)
    redis_url: RedisDsn = Field(
        default="redis://localhost:6379",
        description="Redis connection URL",
    )

    # Certificate Authority data directory (CA key + cert stored here)
    ca_data_dir: Path = Field(
        default=Path("/var/lib/bamf/ca"),
        description="Directory for CA certificate and key storage",
    )

    # Authentication
    auth: AuthConfig = Field(default_factory=AuthConfig)

    # Certificates
    certificates: CertificateConfig = Field(default_factory=CertificateConfig)

    # Audit
    audit: AuditConfig = Field(default_factory=AuditConfig)

    # API
    api_prefix: str = Field(default="/api/v1")

    # Bridge bootstrap token (for bridges to get their initial certificate)
    bridge_bootstrap_token: str | None = Field(
        default=None,
        description="Token for bridge bootstrap authentication. Set via BAMF_BRIDGE_BOOTSTRAP_TOKEN env var.",
    )

    # Bridge tunnel port — the external port clients use to reach bridge tunnels
    # via the Gateway. In production this is 443, in local dev 8443.
    bridge_tunnel_port: int = Field(
        default=443,
        description="External port for mTLS tunnel connections (Gateway listener port).",
    )

    # Bridge internal tunnel port — the K8s Service port for agent-to-bridge
    # connections within the cluster. This is bridge.tunnelPort in the Helm chart.
    bridge_internal_tunnel_port: int = Field(
        default=8443,
        description="Internal K8s Service port for bridge tunnel connections.",
    )

    # Tunnel domain for web app proxy hostnames (e.g., "tunnel.bamf.local").
    # Resources with tunnel_hostname "grafana" become "grafana.tunnel.bamf.local".
    tunnel_domain: str = Field(
        default="",
        description="Base domain for tunnel hostnames (e.g., 'tunnel.bamf.local').",
    )

    # Bridge headless service name — used to construct internal FQDNs for
    # relay communication (pod-name.headless-svc.namespace.svc.cluster.local).
    bridge_headless_service: str = Field(
        default="",
        description="Bridge headless service name for internal relay communication.",
    )

    # Kubernetes namespace (for constructing in-cluster service FQDNs)
    kubernetes_namespace: str = Field(
        default="",
        description="Kubernetes namespace. Auto-detected from service account if empty.",
    )

    @property
    def namespace(self) -> str:
        """Return the Kubernetes namespace, auto-detecting from service account if needed."""
        if self.kubernetes_namespace:
            return self.kubernetes_namespace
        try:
            return (
                Path("/var/run/secrets/kubernetes.io/serviceaccount/namespace").read_text().strip()
            )
        except OSError:
            return "default"

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: Any,
        env_settings: Any,
        dotenv_settings: Any,
        file_secret_settings: Any,
    ) -> tuple[Any, ...]:
        """Customize settings sources: env vars override YAML config."""
        return (
            init_settings,
            env_settings,
            yaml_config_settings_source,
            dotenv_settings,
            file_secret_settings,
        )


# Global settings instance
settings = Settings()
