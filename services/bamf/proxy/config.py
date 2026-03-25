"""Configuration for the standalone proxy service.

Minimal config — the proxy only needs to know how to reach the API
and the tunnel domain for host-header matching.
"""

from typing import Any

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ProxySettings(BaseSettings):
    """Proxy service settings."""

    model_config = SettingsConfigDict(
        env_prefix="BAMF_PROXY_",
        env_nested_delimiter="__",
        extra="ignore",
    )

    # API URL for internal proxy endpoints
    api_url: str = Field(
        default="http://bamf-api:8000",
        description="Base URL of the BAMF API server (internal).",
    )

    # Shared secret for authenticating with the API's internal proxy endpoints
    internal_token: str = Field(
        default="",
        description="Shared secret for proxy→API auth. Must match BAMF_PROXY_INTERNAL_TOKEN on API.",
    )

    # Tunnel domain for host-header matching (e.g., "tunnel.bamf.local")
    tunnel_domain: str = Field(
        default="",
        description="Base domain for tunnel hostnames.",
    )

    # Auth callback base URL for login redirects
    callback_base_url: str = Field(
        default="https://bamf.local",
        description="BAMF login page base URL for auth redirects.",
    )

    # Bridge headless service name — needed for building relay URLs
    bridge_headless_service: str = Field(
        default="",
        description="Bridge headless service name for relay communication.",
    )

    # Kubernetes namespace
    namespace: str = Field(
        default="",
        description="Kubernetes namespace for constructing service FQDNs.",
    )

    # Bridge internal port
    bridge_internal_port: int = Field(
        default=8080,
        description="Bridge internal relay HTTP port.",
    )

    # Logging
    log_level: str = Field(default="INFO")
    json_logs: bool = Field(default=True)

    # App
    app_name: str = Field(default="bamf-proxy")


settings = ProxySettings()
