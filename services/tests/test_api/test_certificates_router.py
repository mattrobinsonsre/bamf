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


# ── Certificate revocation endpoints (RBAC + errors) ──────────────────────


def _revoke_app(session: Session) -> FastAPI:
    """Build an app that runs the REAL require_admin/require_admin_or_audit
    gates against the given session, with a fake DB and no real Redis/PG."""
    from bamf.api.dependencies import get_current_session as real_get_current_session
    from bamf.db.session import get_db

    app = FastAPI()
    app.include_router(router, prefix="/api/v1")

    async def override_session() -> Session:
        return session

    async def override_db():
        from unittest.mock import AsyncMock

        yield AsyncMock()

    app.dependency_overrides[real_get_current_session] = override_session
    app.dependency_overrides[get_db] = override_db
    return app


async def _revoke_client(app: FastAPI) -> AsyncClient:
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


class TestRevokeCertificate:
    @pytest.mark.asyncio
    async def test_admin_can_revoke(self):
        from unittest.mock import AsyncMock

        app = _revoke_app(ADMIN_SESSION)
        async with await _revoke_client(app) as client:
            with (
                patch(
                    "bamf.api.routers.certificates.revoke_certificate",
                    new_callable=AsyncMock,
                ) as mock_revoke,
                patch(
                    "bamf.api.routers.certificates.log_audit_event",
                    new_callable=AsyncMock,
                ),
            ):
                resp = await client.post(
                    "/api/v1/certificates/revoke",
                    json={"fingerprint": "aa:bb:cc", "reason": "leaked"},
                )
        assert resp.status_code == 200
        mock_revoke.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_non_admin_forbidden(self):
        app = _revoke_app(USER_SESSION)
        async with await _revoke_client(app) as client:
            resp = await client.post(
                "/api/v1/certificates/revoke",
                json={"fingerprint": "aa:bb:cc"},
            )
        assert resp.status_code == 403

    @pytest.mark.asyncio
    async def test_empty_fingerprint_rejected(self):
        from unittest.mock import AsyncMock

        app = _revoke_app(ADMIN_SESSION)
        async with await _revoke_client(app) as client:
            with (
                patch(
                    "bamf.api.routers.certificates.revoke_certificate",
                    new_callable=AsyncMock,
                ),
                patch(
                    "bamf.api.routers.certificates.log_audit_event",
                    new_callable=AsyncMock,
                ),
            ):
                resp = await client.post(
                    "/api/v1/certificates/revoke",
                    json={"fingerprint": ""},
                )
        assert resp.status_code == 400


class TestListRevokedCertificates:
    @pytest.mark.asyncio
    async def test_audit_can_list(self):
        from unittest.mock import AsyncMock

        audit_session = Session(
            email="audit@example.com",
            display_name="Auditor",
            roles=["audit"],
            provider_name="local",
            created_at=_NOW,
            expires_at=_NOW,
            last_active_at=_NOW,
        )
        app = _revoke_app(audit_session)
        async with await _revoke_client(app) as client:
            with patch(
                "bamf.api.routers.certificates.list_revoked_certificates",
                new_callable=AsyncMock,
                return_value=[],
            ):
                resp = await client.get("/api/v1/certificates/revoked")
        assert resp.status_code == 200
        assert resp.json() == []

    @pytest.mark.asyncio
    async def test_plain_user_forbidden(self):
        app = _revoke_app(USER_SESSION)
        async with await _revoke_client(app) as client:
            resp = await client.get("/api/v1/certificates/revoked")
        assert resp.status_code == 403
