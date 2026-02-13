"""Pytest configuration and fixtures."""

import asyncio
import os
from collections.abc import AsyncGenerator, Generator
from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from bamf.api.app import create_application
from bamf.db.models import Base
from bamf.db.session import get_db

# Use PostgreSQL from docker-compose.test.yml (env var set in container)
# Falls back to local dev PG if no env var is set
TEST_DATABASE_URL = os.environ.get(
    "BAMF_DATABASE_URL",
    "postgresql+asyncpg://bamf:bamf@localhost:5432/bamf_test",
)


@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop]:
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
async def async_engine():
    """Create async engine for testing."""
    engine = create_async_engine(TEST_DATABASE_URL)

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

    yield engine

    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)

    await engine.dispose()


@pytest.fixture
async def db_session(async_engine) -> AsyncGenerator[AsyncSession]:
    """Create database session for testing."""
    async_session_factory = sessionmaker(
        async_engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )

    async with async_session_factory() as session:
        yield session
        await session.rollback()


@pytest.fixture
def app(db_session: AsyncSession) -> FastAPI:
    """Create FastAPI application for testing."""
    application = create_application()

    async def override_get_db() -> AsyncGenerator[AsyncSession]:
        yield db_session

    application.dependency_overrides[get_db] = override_get_db

    return application


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    """Create sync test client."""
    return TestClient(app)


@pytest.fixture
async def async_client(app: FastAPI) -> AsyncGenerator[AsyncClient]:
    """Create async test client."""
    async with AsyncClient(
        transport=ASGITransport(app=app),
        base_url="http://test",
    ) as client:
        yield client


@pytest.fixture
def mock_user() -> dict[str, Any]:
    """Create mock user data."""
    return {
        "email": "test@example.com",
        "is_active": True,
    }


@pytest.fixture
def mock_admin_user() -> dict[str, Any]:
    """Create mock admin user data."""
    return {
        "email": "admin@example.com",
        "is_active": True,
        "roles": ["admin"],
    }
