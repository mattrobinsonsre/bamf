"""FastAPI application factory for the standalone BAMF proxy service.

The proxy service handles:
- Web app proxying (*.tunnel.domain)
- Kubernetes API proxying (/api/v1/kube/*)

It communicates with the API server exclusively via internal HTTP endpoints
for auth, RBAC, audit logging, and recording storage. No direct Redis/DB access.
"""

from __future__ import annotations

import uuid
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

import structlog
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.websockets import WebSocket

from . import api_client
from .config import settings
from .handler import handle_proxy_websocket, proxy_middleware
from .kube import kube_proxy_ws, router as kube_router

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """Application lifespan handler for startup and shutdown."""
    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.StackInfoRenderer(),
            structlog.processors.format_exc_info,
            structlog.processors.JSONRenderer()
            if settings.json_logs
            else structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.PrintLoggerFactory(),
    )
    logger.info(
        "Starting BAMF proxy service",
        api_url=settings.api_url,
        tunnel_domain=settings.tunnel_domain,
    )

    yield

    # Shutdown
    logger.info("Shutting down BAMF proxy service")
    await api_client.close_client()


def create_application() -> FastAPI:
    """Create and configure the FastAPI proxy application."""
    app = FastAPI(
        title="BAMF Proxy",
        description="Bridge Access Management Fabric - Proxy Service",
        version="0.1.0",
        lifespan=lifespan,
        docs_url="/proxy/docs",
        openapi_url="/proxy/openapi.json",
    )

    # HTTP proxy middleware — intercepts *.tunnel_domain requests
    @app.middleware("http")
    async def http_proxy(request: Request, call_next: Any) -> Any:
        """Route *.tunnel_domain requests to the HTTP proxy handler."""
        return await proxy_middleware(request, call_next)

    # Request ID middleware
    @app.middleware("http")
    async def add_request_id(request: Request, call_next: Any) -> Any:
        """Ensure every request has a request ID for logging correlation."""
        request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())
        structlog.contextvars.bind_contextvars(request_id=request_id)

        response = await call_next(request)
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

    # Health endpoint
    @app.get("/health")
    async def health() -> dict:
        return {"status": "ok", "service": "proxy"}

    @app.get("/ready")
    async def ready() -> dict:
        return {"status": "ok", "service": "proxy"}

    # Kube proxy router
    app.include_router(kube_router, prefix="/api/v1")

    # Kube WebSocket route — registered directly before catch-all
    app.add_api_websocket_route(
        "/api/v1/kube/{resource_name}/{path:path}",
        kube_proxy_ws,
    )

    # Catch-all WebSocket route for proxy requests (*.tunnel.domain)
    @app.websocket("/{path:path}")
    async def proxy_ws_catch_all(websocket: WebSocket, path: str) -> None:
        """Proxy WebSocket connections to *.tunnel.domain web apps."""
        await handle_proxy_websocket(websocket)

    return app


# Application instance
app = create_application()
