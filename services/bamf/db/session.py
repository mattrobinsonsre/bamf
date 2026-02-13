"""
Database session management for BAMF API server.

Provides async SQLAlchemy session factories for read-write (primary) and
read-only (replica) database access. The read replica falls back to the
primary if no separate read URL is configured.
"""

from collections.abc import AsyncGenerator

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

from bamf.config import settings
from bamf.logging_config import get_logger

logger = get_logger(__name__)

# Primary (read-write) engine
engine = create_async_engine(
    str(settings.database_url),
    echo=settings.debug,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

# Read replica engine — falls back to primary if not configured
_read_url = (
    str(settings.database_read_url) if settings.database_read_url else str(settings.database_url)
)
engine_read = create_async_engine(
    _read_url,
    echo=settings.debug,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
)

# Session factories
async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

async_session_factory_read = async_sessionmaker(
    engine_read,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def init_db() -> None:
    """Initialize database connection pools."""
    logger.info("Initializing database connection (primary)")
    async with engine.begin() as conn:
        await conn.execute(text("SELECT 1"))
    logger.info("Primary database connection established")

    if settings.database_read_url:
        logger.info("Initializing database connection (read replica)")
        async with engine_read.begin() as conn:
            await conn.execute(text("SELECT 1"))
        logger.info("Read replica database connection established")
    else:
        logger.info("No read replica configured, using primary for reads")


async def close_db() -> None:
    """Close database connection pools."""
    logger.info("Closing database connection pools")
    await engine.dispose()
    if settings.database_read_url:
        await engine_read.dispose()


async def get_db() -> AsyncGenerator[AsyncSession]:
    """
    Dependency that provides a read-write database session (primary).

    Use this for endpoints that create, update, or delete data.

    Usage:
        @router.post("/users")
        async def create_user(db: AsyncSession = Depends(get_db)):
            ...
    """
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


async def get_db_read() -> AsyncGenerator[AsyncSession]:
    """
    Dependency that provides a read-only database session (replica).

    Routes to the read replica when configured, otherwise falls back to primary.
    Use this for endpoints that only SELECT data (list, get, search).

    Usage:
        @router.get("/users")
        async def list_users(db: AsyncSession = Depends(get_db_read)):
            ...
    """
    async with async_session_factory_read() as session:
        try:
            yield session
        finally:
            # Read-only sessions should never need commit, but rollback
            # any implicit transaction to return the connection cleanly.
            await session.rollback()


async def get_db_health() -> bool:
    """Check database health for readiness probe."""
    try:
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.error("Database health check failed", error=str(e))
        return False


async def get_db_read_health() -> bool:
    """Check read replica health for readiness probe."""
    try:
        async with engine_read.begin() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception as e:
        logger.error("Read replica health check failed", error=str(e))
        return False
