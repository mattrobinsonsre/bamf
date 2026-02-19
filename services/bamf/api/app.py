"""
FastAPI application factory for BAMF API server.

Uses lifespan handler for startup/shutdown with async resource management.
"""

import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

import structlog
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from bamf.auth.ca import init_ca
from bamf.auth.connectors import init_connectors
from bamf.config import settings
from bamf.db.session import close_db, init_db
from bamf.logging_config import configure_logging, get_logger
from bamf.redis.client import close_redis, init_redis

# Shutdown event — SSE generators check this to close promptly during shutdown.
shutdown_event = asyncio.Event()

from .health import router as health_router
from .routers.agents import router as agents_router
from .routers.audit import router as audit_router
from .routers.auth import router as auth_router
from .routers.certificates import router as certificates_router
from .routers.connect import router as connect_router
from .routers.internal_bridges import router as internal_bridges_router
from .routers.kube import router as kube_router
from .routers.resources import router as resources_router
from .routers.role_assignments import router as role_assignments_router
from .routers.roles import router as roles_router
from .routers.terminal import router as terminal_router
from .routers.tokens import router as tokens_router
from .routers.tunnels import router as tunnels_router
from .routers.users import router as users_router

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """Application lifespan handler for startup and shutdown."""
    # Startup
    configure_logging(json_logs=settings.json_logs, log_level=settings.log_level)
    logger.info("Starting BAMF API server", version="0.1.0")

    await init_db()
    logger.info("Database connection initialized")

    await init_redis()
    logger.info("Redis connection initialized")

    from bamf.db.session import async_session_factory

    async with async_session_factory() as db_session:
        await init_ca(db_session)
    logger.info("Certificate Authority initialized")

    init_connectors()
    logger.info("SSO connectors initialized")

    yield

    # Shutdown — signal SSE generators to close before tearing down connections
    logger.info("Shutting down BAMF API server")
    shutdown_event.set()
    # Brief pause so SSE generators see the event and close cleanly
    await asyncio.sleep(0.5)
    await close_redis()
    await close_db()


def create_application() -> FastAPI:
    """Create and configure the FastAPI application."""
    app = FastAPI(
        title="BAMF API",
        description="Bridge Access Management Fabric - API Server",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
    )

    # CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],  # Configure appropriately for production
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # HTTP proxy middleware — intercepts *.tunnel_domain requests before API routes
    from bamf.api.proxy.handler import proxy_middleware

    @app.middleware("http")
    async def http_proxy(request: Request, call_next: Any) -> Any:
        """Route *.tunnel_domain requests to the HTTP proxy handler."""
        return await proxy_middleware(request, call_next)

    # API self-audit middleware — captures API request/response exchanges.
    # Runs after request ID (so request_id is available) and before proxy
    # middleware (so it only captures API requests, not proxied web app traffic).
    from bamf.api.middleware import api_audit_middleware

    @app.middleware("http")
    async def api_audit(request: Request, call_next: Any) -> Any:
        """Record API request/response exchanges for audit."""
        return await api_audit_middleware(request, call_next)

    # Request ID middleware
    @app.middleware("http")
    async def add_request_id(request: Request, call_next: Any) -> Any:
        """Add request ID to context for logging correlation."""
        request_id = request.headers.get("X-Request-ID")
        if request_id:
            structlog.contextvars.bind_contextvars(request_id=request_id)

        response = await call_next(request)

        if request_id:
            response.headers["X-Request-ID"] = request_id
            structlog.contextvars.unbind_contextvars("request_id")

        return response

    # Exception handler
    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """Global exception handler for unhandled errors."""
        logger.error("Unhandled exception", exc_info=exc, path=str(request.url.path))
        return JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"},
        )

    # Health endpoints (no prefix)
    app.include_router(health_router)

    # API v1 routers
    app.include_router(agents_router, prefix=settings.api_prefix)
    app.include_router(auth_router, prefix=settings.api_prefix)
    app.include_router(users_router, prefix=settings.api_prefix)
    app.include_router(roles_router, prefix=settings.api_prefix)
    app.include_router(certificates_router, prefix=settings.api_prefix)
    app.include_router(connect_router, prefix=settings.api_prefix)
    app.include_router(kube_router, prefix=settings.api_prefix)
    app.include_router(resources_router, prefix=settings.api_prefix)
    app.include_router(role_assignments_router, prefix=settings.api_prefix)
    app.include_router(tokens_router, prefix=settings.api_prefix)
    app.include_router(terminal_router, prefix=settings.api_prefix)
    app.include_router(tunnels_router, prefix=settings.api_prefix)
    app.include_router(audit_router, prefix=settings.api_prefix)

    # Internal routes (called by Go bridge/agent, not end users)
    app.include_router(internal_bridges_router, prefix=settings.api_prefix)

    return app


# Application instance
app = create_application()
