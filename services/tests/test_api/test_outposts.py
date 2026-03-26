"""Tests for outpost management and join flow.

Tests /api/v1/outposts endpoints including the unauthenticated join
flow and admin management endpoints.
"""

from __future__ import annotations

from datetime import UTC, datetime
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.api.dependencies import require_admin, require_admin_or_audit
from bamf.api.routers.outpost_tokens import router as token_router
from bamf.api.routers.outposts import router as outpost_router
from bamf.auth.sessions import Session
from bamf.db.session import get_db, get_db_read

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


@pytest.fixture
def outpost_app(db_session: AsyncSession):
    """Minimal app with both outpost and token routers."""
    app = FastAPI()
    app.include_router(token_router, prefix="/api/v1")
    app.include_router(outpost_router, prefix="/api/v1")

    async def override_get_db():
        yield db_session

    async def override_admin() -> Session:
        return ADMIN_SESSION

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_db_read] = override_get_db
    app.dependency_overrides[require_admin] = override_admin
    app.dependency_overrides[require_admin_or_audit] = override_admin
    return app


@pytest.fixture
async def outpost_client(outpost_app):
    async with AsyncClient(
        transport=ASGITransport(app=outpost_app),
        base_url="http://test",
    ) as client:
        yield client


def _patch_audit_log_tokens():
    return patch(
        "bamf.api.routers.outpost_tokens.log_audit_event",
        new_callable=AsyncMock,
    )


def _patch_audit_log_outposts():
    return patch(
        "bamf.api.routers.outposts.log_audit_event",
        new_callable=AsyncMock,
    )


def _mock_ca():
    """Mock the CA to return a fake cert PEM."""
    mock = MagicMock()
    mock.ca_cert_pem = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----"
    return mock


async def _create_token(client, name="test-token", outpost_name="eu"):
    """Helper: create an outpost token and return the raw token string."""
    with _patch_audit_log_tokens():
        resp = await client.post(
            "/api/v1/outpost-tokens",
            json={
                "name": name,
                "outpost_name": outpost_name,
                "expires_in_hours": 24,
            },
        )
    assert resp.status_code == 201
    return resp.json()["token"]


# ── Tests ─────────────────────────────────────────────────────────────────


class TestOutpostJoin:
    @pytest.mark.asyncio
    async def test_join_creates_outpost(self, outpost_client, db_session):
        raw_token = await _create_token(outpost_client, "join-test", "us-east")

        with (
            patch("bamf.api.routers.outposts.get_ca", return_value=_mock_ca()),
            patch("bamf.api.routers.outposts.settings") as mock_settings,
            _patch_audit_log_outposts(),
        ):
            mock_settings.tunnel_domain = "tunnel.bamf.example.com"
            resp = await outpost_client.post(
                "/api/v1/outposts/join",
                json={"join_token": raw_token},
            )

        assert resp.status_code == 201
        data = resp.json()
        assert data["outpost_name"] == "us-east"
        assert data["internal_token"].startswith("out_int_")
        assert data["bridge_bootstrap_token"].startswith("out_brg_")
        assert "BEGIN CERTIFICATE" in data["ca_certificate"]
        assert data["tunnel_domain"] == "tunnel.bamf.example.com"

    @pytest.mark.asyncio
    async def test_join_invalid_token_fails(self, outpost_client):
        with (
            patch("bamf.api.routers.outposts.get_ca", return_value=_mock_ca()),
            patch("bamf.api.routers.outposts.settings") as mock_settings,
            _patch_audit_log_outposts(),
        ):
            mock_settings.tunnel_domain = ""
            resp = await outpost_client.post(
                "/api/v1/outposts/join",
                json={"join_token": "bamf_out_invalid_token_value"},
            )
        assert resp.status_code == 401

    @pytest.mark.asyncio
    async def test_join_revoked_token_fails(self, outpost_client, db_session):
        raw_token = await _create_token(outpost_client, "revoke-join", "eu")

        # Revoke the token
        with _patch_audit_log_tokens():
            await outpost_client.post("/api/v1/outpost-tokens/revoke-join/revoke")

        with (
            patch("bamf.api.routers.outposts.get_ca", return_value=_mock_ca()),
            patch("bamf.api.routers.outposts.settings") as mock_settings,
            _patch_audit_log_outposts(),
        ):
            mock_settings.tunnel_domain = ""
            resp = await outpost_client.post(
                "/api/v1/outposts/join",
                json={"join_token": raw_token},
            )
        assert resp.status_code == 401
        assert "revoked" in resp.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_rejoin_regenerates_tokens(self, outpost_client, db_session):
        """Re-joining with the same outpost name regenerates tokens."""
        raw_token1 = await _create_token(outpost_client, "rejoin-1", "eu")
        raw_token2 = await _create_token(outpost_client, "rejoin-2", "eu")

        with (
            patch("bamf.api.routers.outposts.get_ca", return_value=_mock_ca()),
            patch("bamf.api.routers.outposts.settings") as mock_settings,
            _patch_audit_log_outposts(),
        ):
            mock_settings.tunnel_domain = ""
            resp1 = await outpost_client.post(
                "/api/v1/outposts/join",
                json={"join_token": raw_token1},
            )
            resp2 = await outpost_client.post(
                "/api/v1/outposts/join",
                json={"join_token": raw_token2},
            )

        data1 = resp1.json()
        data2 = resp2.json()
        assert data1["outpost_id"] == data2["outpost_id"]  # Same outpost
        assert data1["internal_token"] != data2["internal_token"]  # New tokens
        assert data1["bridge_bootstrap_token"] != data2["bridge_bootstrap_token"]

    @pytest.mark.asyncio
    async def test_join_increments_use_count(self, outpost_client, db_session):
        raw_token = await _create_token(outpost_client, "count-test", "apac")

        with (
            patch("bamf.api.routers.outposts.get_ca", return_value=_mock_ca()),
            patch("bamf.api.routers.outposts.settings") as mock_settings,
            _patch_audit_log_outposts(),
        ):
            mock_settings.tunnel_domain = ""
            await outpost_client.post(
                "/api/v1/outposts/join",
                json={"join_token": raw_token},
            )

        # Check token use_count was incremented
        resp = await outpost_client.get("/api/v1/outpost-tokens")
        tokens = resp.json()["items"]
        token = next(t for t in tokens if t["name"] == "count-test")
        assert token["use_count"] == 1

    @pytest.mark.asyncio
    async def test_join_max_uses_exceeded_fails(self, outpost_client, db_session):
        """Token with max_uses=1 should fail on second use."""
        with _patch_audit_log_tokens():
            resp = await outpost_client.post(
                "/api/v1/outpost-tokens",
                json={
                    "name": "max-use-test",
                    "outpost_name": "eu",
                    "expires_in_hours": 24,
                    "max_uses": 1,
                },
            )
        raw_token = resp.json()["token"]

        with (
            patch("bamf.api.routers.outposts.get_ca", return_value=_mock_ca()),
            patch("bamf.api.routers.outposts.settings") as mock_settings,
            _patch_audit_log_outposts(),
        ):
            mock_settings.tunnel_domain = ""
            # First join should succeed
            resp1 = await outpost_client.post(
                "/api/v1/outposts/join",
                json={"join_token": raw_token},
            )
            assert resp1.status_code == 201

            # Second join should fail
            resp2 = await outpost_client.post(
                "/api/v1/outposts/join",
                json={"join_token": raw_token},
            )
            assert resp2.status_code == 401
            assert "maximum uses" in resp2.json()["detail"].lower()


class TestListOutposts:
    @pytest.mark.asyncio
    async def test_list_empty(self, outpost_client):
        resp = await outpost_client.get("/api/v1/outposts")
        assert resp.status_code == 200
        assert resp.json()["items"] == []

    @pytest.mark.asyncio
    async def test_list_includes_joined_outpost(self, outpost_client, db_session):
        raw_token = await _create_token(outpost_client, "list-out", "eu-west")

        with (
            patch("bamf.api.routers.outposts.get_ca", return_value=_mock_ca()),
            patch("bamf.api.routers.outposts.settings") as mock_settings,
            _patch_audit_log_outposts(),
        ):
            mock_settings.tunnel_domain = ""
            await outpost_client.post(
                "/api/v1/outposts/join",
                json={"join_token": raw_token},
            )

        resp = await outpost_client.get("/api/v1/outposts")
        data = resp.json()
        assert len(data["items"]) >= 1
        names = [s["name"] for s in data["items"]]
        assert "eu-west" in names


class TestDeactivateOutpost:
    @pytest.mark.asyncio
    async def test_deactivate(self, outpost_client, db_session):
        raw_token = await _create_token(outpost_client, "deactivate-test", "apac")

        with (
            patch("bamf.api.routers.outposts.get_ca", return_value=_mock_ca()),
            patch("bamf.api.routers.outposts.settings") as mock_settings,
            _patch_audit_log_outposts(),
        ):
            mock_settings.tunnel_domain = ""
            join_resp = await outpost_client.post(
                "/api/v1/outposts/join",
                json={"join_token": raw_token},
            )
        outpost_id = join_resp.json()["outpost_id"]

        with _patch_audit_log_outposts():
            resp = await outpost_client.delete(f"/api/v1/outposts/{outpost_id}")
        assert resp.status_code == 200
        assert "deactivated" in resp.json()["message"].lower()

    @pytest.mark.asyncio
    async def test_deactivate_already_inactive_fails(self, outpost_client, db_session):
        raw_token = await _create_token(outpost_client, "double-deactivate", "eu")

        with (
            patch("bamf.api.routers.outposts.get_ca", return_value=_mock_ca()),
            patch("bamf.api.routers.outposts.settings") as mock_settings,
            _patch_audit_log_outposts(),
        ):
            mock_settings.tunnel_domain = ""
            join_resp = await outpost_client.post(
                "/api/v1/outposts/join",
                json={"join_token": raw_token},
            )
        outpost_id = join_resp.json()["outpost_id"]

        with _patch_audit_log_outposts():
            await outpost_client.delete(f"/api/v1/outposts/{outpost_id}")
            resp = await outpost_client.delete(f"/api/v1/outposts/{outpost_id}")
        assert resp.status_code == 400

    @pytest.mark.asyncio
    async def test_deactivate_nonexistent_fails(self, outpost_client):
        with _patch_audit_log_outposts():
            resp = await outpost_client.delete(
                "/api/v1/outposts/00000000-0000-0000-0000-000000000000"
            )
        assert resp.status_code == 404
