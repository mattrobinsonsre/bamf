"""Tests for satellite management and join flow.

Tests /api/v1/satellites endpoints including the unauthenticated join
flow and admin management endpoints.
"""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from bamf.api.routers.satellite_tokens import router as token_router
from bamf.api.routers.satellites import router as satellite_router
from bamf.auth.sessions import Session
from bamf.db.session import get_db


# ── Fixtures ──────────────────────────────────────────────────────────────


ADMIN_SESSION = Session(
    email="admin@example.com",
    display_name="Admin",
    roles=["admin"],
    provider_name="local",
)


@pytest.fixture
def sat_app(db_session: AsyncSession):
    """Minimal app with both satellite and token routers."""
    app = FastAPI()
    app.include_router(token_router, prefix="/api/v1")
    app.include_router(satellite_router, prefix="/api/v1")

    async def override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = override_get_db
    return app


@pytest.fixture
async def sat_client(sat_app):
    async with AsyncClient(
        transport=ASGITransport(app=sat_app),
        base_url="http://test",
    ) as client:
        yield client


def _patch_admin():
    return patch(
        "bamf.api.routers.satellite_tokens.require_admin",
        return_value=ADMIN_SESSION,
    )


def _patch_admin_satellites():
    return patch(
        "bamf.api.routers.satellites.require_admin",
        return_value=ADMIN_SESSION,
    )


def _patch_audit():
    return patch(
        "bamf.api.routers.satellite_tokens.require_admin_or_audit",
        return_value=ADMIN_SESSION,
    )


def _patch_audit_satellites():
    return patch(
        "bamf.api.routers.satellites.require_admin_or_audit",
        return_value=ADMIN_SESSION,
    )


def _patch_audit_log_tokens():
    return patch(
        "bamf.api.routers.satellite_tokens.log_audit_event",
        new_callable=AsyncMock,
    )


def _patch_audit_log_satellites():
    return patch(
        "bamf.api.routers.satellites.log_audit_event",
        new_callable=AsyncMock,
    )


def _mock_ca():
    """Mock the CA to return a fake cert PEM."""
    mock = MagicMock()
    mock.ca_cert_pem = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----"
    return mock


async def _create_token(client, name="test-token", satellite_name="eu"):
    """Helper: create a satellite token and return the raw token string."""
    with _patch_admin(), _patch_audit_log_tokens():
        resp = await client.post(
            "/api/v1/satellite-tokens",
            json={
                "name": name,
                "satellite_name": satellite_name,
                "expires_in_hours": 24,
            },
        )
    assert resp.status_code == 201
    return resp.json()["token"]


# ── Tests ─────────────────────────────────────────────────────────────────


class TestSatelliteJoin:
    @pytest.mark.asyncio
    async def test_join_creates_satellite(self, sat_client, db_session):
        raw_token = await _create_token(sat_client, "join-test", "us-east")

        with (
            patch("bamf.api.routers.satellites.get_ca", return_value=_mock_ca()),
            patch("bamf.api.routers.satellites.settings") as mock_settings,
            _patch_audit_log_satellites(),
        ):
            mock_settings.tunnel_domain = "tunnel.bamf.example.com"
            resp = await sat_client.post(
                "/api/v1/satellites/join",
                json={"join_token": raw_token},
            )

        assert resp.status_code == 201
        data = resp.json()
        assert data["satellite_name"] == "us-east"
        assert data["internal_token"].startswith("sat_int_")
        assert data["bridge_bootstrap_token"].startswith("sat_brg_")
        assert "BEGIN CERTIFICATE" in data["ca_certificate"]
        assert data["tunnel_domain"] == "tunnel.bamf.example.com"

    @pytest.mark.asyncio
    async def test_join_invalid_token_fails(self, sat_client):
        with (
            patch("bamf.api.routers.satellites.get_ca", return_value=_mock_ca()),
            patch("bamf.api.routers.satellites.settings") as mock_settings,
            _patch_audit_log_satellites(),
        ):
            mock_settings.tunnel_domain = ""
            resp = await sat_client.post(
                "/api/v1/satellites/join",
                json={"join_token": "bamf_sat_invalid_token_value"},
            )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_join_revoked_token_fails(self, sat_client, db_session):
        raw_token = await _create_token(sat_client, "revoke-join", "eu")

        # Revoke the token
        with _patch_admin(), _patch_audit_log_tokens():
            await sat_client.post("/api/v1/satellite-tokens/revoke-join/revoke")

        with (
            patch("bamf.api.routers.satellites.get_ca", return_value=_mock_ca()),
            patch("bamf.api.routers.satellites.settings") as mock_settings,
            _patch_audit_log_satellites(),
        ):
            mock_settings.tunnel_domain = ""
            resp = await sat_client.post(
                "/api/v1/satellites/join",
                json={"join_token": raw_token},
            )
        assert resp.status_code == 401
        assert "revoked" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_rejoin_regenerates_tokens(self, sat_client, db_session):
        """Re-joining with the same satellite name regenerates tokens."""
        raw_token1 = await _create_token(sat_client, "rejoin-1", "eu")
        raw_token2 = await _create_token(sat_client, "rejoin-2", "eu")

        with (
            patch("bamf.api.routers.satellites.get_ca", return_value=_mock_ca()),
            patch("bamf.api.routers.satellites.settings") as mock_settings,
            _patch_audit_log_satellites(),
        ):
            mock_settings.tunnel_domain = ""
            resp1 = await sat_client.post(
                "/api/v1/satellites/join",
                json={"join_token": raw_token1},
            )
            resp2 = await sat_client.post(
                "/api/v1/satellites/join",
                json={"join_token": raw_token2},
            )

        data1 = resp1.json()
        data2 = resp2.json()
        assert data1["satellite_id"] == data2["satellite_id"]  # Same satellite
        assert data1["internal_token"] != data2["internal_token"]  # New tokens
        assert data1["bridge_bootstrap_token"] != data2["bridge_bootstrap_token"]

    @pytest.mark.asyncio
    async def test_join_increments_use_count(self, sat_client, db_session):
        raw_token = await _create_token(sat_client, "count-test", "apac")

        with (
            patch("bamf.api.routers.satellites.get_ca", return_value=_mock_ca()),
            patch("bamf.api.routers.satellites.settings") as mock_settings,
            _patch_audit_log_satellites(),
        ):
            mock_settings.tunnel_domain = ""
            await sat_client.post(
                "/api/v1/satellites/join",
                json={"join_token": raw_token},
            )

        # Check token use_count was incremented
        with _patch_audit():
            resp = await sat_client.get("/api/v1/satellite-tokens")
        tokens = resp.json()["items"]
        token = next(t for t in tokens if t["name"] == "count-test")
        assert token["use_count"] == 1

    @pytest.mark.asyncio
    async def test_join_max_uses_exceeded_fails(self, sat_client, db_session):
        """Token with max_uses=1 should fail on second use."""
        with _patch_admin(), _patch_audit_log_tokens():
            resp = await sat_client.post(
                "/api/v1/satellite-tokens",
                json={
                    "name": "max-use-test",
                    "satellite_name": "eu",
                    "expires_in_hours": 24,
                    "max_uses": 1,
                },
            )
        raw_token = resp.json()["token"]

        with (
            patch("bamf.api.routers.satellites.get_ca", return_value=_mock_ca()),
            patch("bamf.api.routers.satellites.settings") as mock_settings,
            _patch_audit_log_satellites(),
        ):
            mock_settings.tunnel_domain = ""
            # First join should succeed
            resp1 = await sat_client.post(
                "/api/v1/satellites/join",
                json={"join_token": raw_token},
            )
            assert resp1.status_code == 201

            # Second join should fail
            resp2 = await sat_client.post(
                "/api/v1/satellites/join",
                json={"join_token": raw_token},
            )
            assert resp2.status_code == 401
            assert "maximum uses" in resp2.json()["detail"].lower()


class TestListSatellites:
    @pytest.mark.asyncio
    async def test_list_empty(self, sat_client):
        with _patch_audit_satellites():
            resp = await sat_client.get("/api/v1/satellites")
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    @pytest.mark.asyncio
    async def test_list_includes_joined_satellite(self, sat_client, db_session):
        raw_token = await _create_token(sat_client, "list-sat", "eu-west")

        with (
            patch("bamf.api.routers.satellites.get_ca", return_value=_mock_ca()),
            patch("bamf.api.routers.satellites.settings") as mock_settings,
            _patch_audit_log_satellites(),
        ):
            mock_settings.tunnel_domain = ""
            await sat_client.post(
                "/api/v1/satellites/join",
                json={"join_token": raw_token},
            )

        with _patch_audit_satellites():
            resp = await sat_client.get("/api/v1/satellites")
        data = resp.json()
        assert len(data["items"]) >= 1
        names = [s["name"] for s in data["items"]]
        assert "eu-west" in names


class TestDeactivateSatellite:
    @pytest.mark.asyncio
    async def test_deactivate(self, sat_client, db_session):
        raw_token = await _create_token(sat_client, "deactivate-test", "apac")

        with (
            patch("bamf.api.routers.satellites.get_ca", return_value=_mock_ca()),
            patch("bamf.api.routers.satellites.settings") as mock_settings,
            _patch_audit_log_satellites(),
        ):
            mock_settings.tunnel_domain = ""
            join_resp = await sat_client.post(
                "/api/v1/satellites/join",
                json={"join_token": raw_token},
            )
        sat_id = join_resp.json()["satellite_id"]

        with _patch_admin_satellites(), _patch_audit_log_satellites():
            resp = await sat_client.delete(f"/api/v1/satellites/{sat_id}")
        assert resp.status_code == 200
        assert "deactivated" in resp.json()["message"].lower()

    @pytest.mark.asyncio
    async def test_deactivate_already_inactive_fails(self, sat_client, db_session):
        raw_token = await _create_token(sat_client, "double-deactivate", "eu")

        with (
            patch("bamf.api.routers.satellites.get_ca", return_value=_mock_ca()),
            patch("bamf.api.routers.satellites.settings") as mock_settings,
            _patch_audit_log_satellites(),
        ):
            mock_settings.tunnel_domain = ""
            join_resp = await sat_client.post(
                "/api/v1/satellites/join",
                json={"join_token": raw_token},
            )
        sat_id = join_resp.json()["satellite_id"]

        with _patch_admin_satellites(), _patch_audit_log_satellites():
            await sat_client.delete(f"/api/v1/satellites/{sat_id}")
            resp = await sat_client.delete(f"/api/v1/satellites/{sat_id}")
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_deactivate_nonexistent_fails(self, sat_client):
        with _patch_admin_satellites(), _patch_audit_log_satellites():
            resp = await sat_client.delete(
                "/api/v1/satellites/00000000-0000-0000-0000-000000000000"
            )
        assert resp.status_code == 404
