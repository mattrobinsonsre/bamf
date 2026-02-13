"""Tests for health endpoints."""

from unittest.mock import AsyncMock, patch

from fastapi.testclient import TestClient


def test_health_endpoint(client: TestClient):
    """Test /health endpoint returns healthy status."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"


def test_ready_endpoint(client: TestClient):
    """Test /ready endpoint returns ready status when all services are healthy."""
    with (
        patch("bamf.api.health.get_db_health", new_callable=AsyncMock, return_value=True),
        patch("bamf.api.health.get_redis_health", new_callable=AsyncMock, return_value=True),
    ):
        response = client.get("/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"
        assert data["checks"]["database"] == "healthy"
        assert data["checks"]["redis"] == "healthy"


def test_ready_endpoint_unhealthy(client: TestClient):
    """Test /ready endpoint returns 503 when a service is unhealthy."""
    with (
        patch("bamf.api.health.get_db_health", new_callable=AsyncMock, return_value=True),
        patch("bamf.api.health.get_redis_health", new_callable=AsyncMock, return_value=False),
    ):
        response = client.get("/ready")
        assert response.status_code == 503
        data = response.json()
        assert data["status"] == "not ready"
        assert data["checks"]["redis"] == "unhealthy"
