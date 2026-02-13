"""SSO connector registry.

Manages initialized SSO connectors, keyed by provider name.
"""

from bamf.auth.sso import SSOConnector
from bamf.config import settings
from bamf.logging_config import get_logger

logger = get_logger(__name__)

# Registry of initialized connectors
_connectors: dict[str, SSOConnector] = {}


def init_connectors() -> None:
    """Initialize all configured auth connectors.

    Called during application startup (lifespan handler).
    Registers local, OIDC, and SAML connectors based on config.
    """
    from bamf.auth.connectors.local import LocalConnector
    from bamf.auth.connectors.oidc import OIDCConnector
    from bamf.auth.connectors.saml import SAMLConnector

    _connectors.clear()

    # Register local connector when local auth is enabled
    if settings.auth.local_enabled:
        connector = LocalConnector()
        _connectors[connector.name] = connector
        logger.info("Registered local provider")

    for oidc_config in settings.auth.sso.oidc:
        connector = OIDCConnector(oidc_config)
        _connectors[connector.name] = connector
        logger.info("Registered OIDC provider", provider=connector.name)

    for saml_config in settings.auth.sso.saml:
        connector = SAMLConnector(saml_config)
        _connectors[connector.name] = connector
        logger.info("Registered SAML provider", provider=connector.name)

    logger.info("Auth connectors initialized", count=len(_connectors))


def get_connector(name: str) -> SSOConnector | None:
    """Get a connector by provider name."""
    return _connectors.get(name)


def list_connectors() -> list[dict[str, str]]:
    """List all configured providers (name + type)."""
    return [{"name": c.name, "type": c.provider_type} for c in _connectors.values()]


def get_default_connector() -> SSOConnector | None:
    """Get the default SSO connector, if configured."""
    default_name = settings.auth.sso.default_provider
    if default_name:
        return _connectors.get(default_name)
    # Fall back to first configured connector
    if _connectors:
        return next(iter(_connectors.values()))
    return None
