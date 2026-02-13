"""Certificate-related Pydantic models."""

from datetime import datetime

from pydantic import Field

from .common import BAMFBaseModel


class UserCertificateResponse(BAMFBaseModel):
    """Response from issuing a user identity certificate."""

    certificate: str = Field(description="PEM-encoded x509 certificate")
    private_key: str = Field(description="PEM-encoded Ed25519 private key")
    ca_certificate: str = Field(description="PEM-encoded CA certificate")
    expires_at: datetime


class ServiceCertificateRequest(BAMFBaseModel):
    """Request to issue a service certificate (agent or bridge)."""

    service_name: str = Field(..., min_length=1, max_length=63)
    service_type: str = Field(..., pattern="^(agent|bridge)$")
    dns_names: list[str] = Field(default_factory=list)
    ip_addresses: list[str] = Field(default_factory=list)


class ServiceCertificateResponse(BAMFBaseModel):
    """Response from issuing a service certificate."""

    certificate: str = Field(description="PEM-encoded x509 certificate")
    private_key: str = Field(description="PEM-encoded Ed25519 private key")
    ca_certificate: str = Field(description="PEM-encoded CA certificate")
    expires_at: datetime


class CACertificateResponse(BAMFBaseModel):
    """Response containing the public CA certificate."""

    ca_certificate: str = Field(description="PEM-encoded CA certificate")
