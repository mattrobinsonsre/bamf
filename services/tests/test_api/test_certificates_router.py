"""Tests for certificates endpoints.

Tests /api/v1/certificates endpoints for CA public cert retrieval
and certificate issuance.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from bamf.api.dependencies import get_current_session, require_admin
from bamf.api.routers.certificates import router
from bamf.auth.sessions import Session

# ── Fixtures ──────────────────────────────────────────────────────────────

_NOW = datetime.now(UTC).isoformat()

ADMIN_SESSION = Session(
    email="admin@example.com",
    display_name="Admin",
    roles=["admin"],
    provider_name="local",
    created_at=_NOW,
    expires_at=_NOW,
    last_active_at=_NOW,
)

USER_SESSION = Session(
    email="user@example.com",
    display_name="User",
    roles=[],
    provider_name="local",
    created_at=_NOW,
    expires_at=_NOW,
    last_active_at=_NOW,
)


class FakeCert:
    """Minimal fake x509 certificate."""

    def __init__(self):
        self.not_valid_after_utc = datetime.now(UTC) + timedelta(hours=12)


class FakeCA:
    """Minimal fake CA for test purposes."""

    def __init__(self):
        self.ca_cert_pem = "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n"

    def issue_user_certificate(self, email, roles):
        return FakeCert(), b"fake-key"

    def issue_service_certificate(
        self, service_name, service_type, dns_names=None, ip_addresses=None
    ):
        return FakeCert(), b"fake-key"


@pytest.fixture
def certs_app():
    app = FastAPI()
    app.include_router(router, prefix="/api/v1")

    async def override_admin() -> Session:
        return ADMIN_SESSION

    async def override_session() -> Session:
        return USER_SESSION

    app.dependency_overrides[require_admin] = override_admin
    app.dependency_overrides[get_current_session] = override_session
    return app


@pytest.fixture
async def certs_client(certs_app):
    async with AsyncClient(
        transport=ASGITransport(app=certs_app),
        base_url="http://test",
    ) as client:
        yield client


def _patch_ca():
    fake_ca = FakeCA()
    return patch("bamf.api.routers.certificates.get_ca", return_value=fake_ca)


def _patch_serialize():
    """Patch serialization functions to return mock PEM strings."""
    return (
        patch(
            "bamf.api.routers.certificates.serialize_certificate",
            return_value=b"-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----\n",
        ),
        patch(
            "bamf.api.routers.certificates.serialize_private_key",
            return_value=b"-----BEGIN PRIVATE KEY-----\nMOCK\n-----END PRIVATE KEY-----\n",
        ),
    )


# ── Tests ─────────────────────────────────────────────────────────────────


class TestGetCACertificate:
    @pytest.mark.asyncio
    async def test_returns_ca_cert(self, certs_client):
        with _patch_ca():
            resp = await certs_client.get("/api/v1/certificates/ca")
        assert resp.status_code == 200
        data = resp.json()
        assert "BEGIN CERTIFICATE" in data["ca_certificate"]


class TestIssueUserCertificate:
    @pytest.mark.asyncio
    async def test_issues_user_cert(self, certs_client):
        ser_cert, ser_key = _patch_serialize()
        with _patch_ca(), ser_cert, ser_key:
            resp = await certs_client.post("/api/v1/certificates/user")
        assert resp.status_code == 200
        data = resp.json()
        assert "BEGIN CERTIFICATE" in data["certificate"]
        assert "BEGIN PRIVATE KEY" in data["private_key"]
        assert "BEGIN CERTIFICATE" in data["ca_certificate"]
        assert "expires_at" in data


class TestIssueServiceCertificate:
    @pytest.mark.asyncio
    async def test_issues_service_cert(self, certs_client):
        ser_cert, ser_key = _patch_serialize()
        with _patch_ca(), ser_cert, ser_key:
            resp = await certs_client.post(
                "/api/v1/certificates/service",
                json={
                    "service_name": "my-agent",
                    "service_type": "agent",
                },
            )
        assert resp.status_code == 200
        data = resp.json()
        assert "BEGIN CERTIFICATE" in data["certificate"]

    @pytest.mark.asyncio
    async def test_issues_bridge_cert_with_dns(self, certs_client):
        ser_cert, ser_key = _patch_serialize()
        with _patch_ca(), ser_cert, ser_key:
            resp = await certs_client.post(
                "/api/v1/certificates/service",
                json={
                    "service_name": "bridge-0",
                    "service_type": "bridge",
                    "dns_names": ["0.bridge.tunnel.bamf.local"],
                },
            )
        assert resp.status_code == 200

    @pytest.mark.asyncio
    async def test_invalid_service_type(self, certs_client):
        ser_cert, ser_key = _patch_serialize()
        with _patch_ca(), ser_cert, ser_key:
            resp = await certs_client.post(
                "/api/v1/certificates/service",
                json={
                    "service_name": "test",
                    "service_type": "invalid",
                },
            )
        assert resp.status_code == 422  # Pydantic validation
