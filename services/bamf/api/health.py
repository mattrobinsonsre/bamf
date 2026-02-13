"""
Health check endpoints for BAMF API server.

Provides /health (liveness) and /ready (readiness) endpoints.
"""

from fastapi import APIRouter, Response, status

from bamf.config import settings
from bamf.db.session import get_db_health, get_db_read_health
from bamf.logging_config import get_logger
from bamf.redis.client import get_redis_health

router = APIRouter(tags=["health"])
logger = get_logger(__name__)


@router.get("/health", status_code=status.HTTP_200_OK)
async def health() -> dict[str, str]:
    """
    Liveness probe endpoint.

    Returns 200 if the API server is running.
    Used by Kubernetes liveness probe.
    """
    return {"status": "healthy"}


@router.get("/ready", status_code=status.HTTP_200_OK)
async def ready(response: Response) -> dict[str, str | dict[str, str]]:
    """
    Readiness probe endpoint.

    Checks database connectivity before returning 200.
    Used by Kubernetes readiness probe.
    """
    db_healthy = await get_db_health()
    redis_healthy = await get_redis_health()

    checks: dict[str, str] = {
        "database": "healthy" if db_healthy else "unhealthy",
        "redis": "healthy" if redis_healthy else "unhealthy",
    }

    all_healthy = db_healthy and redis_healthy

    if settings.database_read_url:
        db_read_healthy = await get_db_read_health()
        checks["database_read"] = "healthy" if db_read_healthy else "unhealthy"
        all_healthy = all_healthy and db_read_healthy

    if not all_healthy:
        logger.warning("Readiness check failed", checks=checks)
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE
        return {"status": "not ready", "checks": checks}

    return {"status": "ready", "checks": checks}
