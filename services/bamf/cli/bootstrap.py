"""
Bootstrap script for creating the initial admin user and join token.

Idempotent: skips if resources already exist.
Run via: python -m bamf.cli.bootstrap

Reads configuration from environment variables:
  BAMF_BOOTSTRAP_ADMIN_EMAIL    - Admin username/email (required)
  BAMF_BOOTSTRAP_ADMIN_PASSWORD - Admin password (optional; generated if omitted)
  BAMF_BOOTSTRAP_JOIN_TOKEN     - Join token value (optional; creates a token if set)
  DATABASE_URL                  - PostgreSQL connection URL (from Helm)
"""

import asyncio
import hashlib
import logging
import os
import secrets
import sys
from datetime import UTC, datetime, timedelta

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine

from bamf.auth.passwords import hash_password
from bamf.db.models import JoinToken, PlatformRoleAssignment, User

# Use stdlib logging — structlog isn't configured yet during bootstrap
logger = logging.getLogger("bamf.bootstrap")
logging.basicConfig(level=logging.INFO, format="%(message)s")


async def bootstrap() -> None:
    admin_email = os.environ.get("BAMF_BOOTSTRAP_ADMIN_EMAIL", "").strip()
    admin_password = os.environ.get("BAMF_BOOTSTRAP_ADMIN_PASSWORD", "").strip()
    database_url = os.environ.get("DATABASE_URL", "").strip()

    if not admin_email:
        logger.error("BAMF_BOOTSTRAP_ADMIN_EMAIL is required")
        sys.exit(1)

    if not database_url:
        logger.error("DATABASE_URL is required")
        sys.exit(1)

    generated = False
    if not admin_password:
        admin_password = secrets.token_urlsafe(24)
        generated = True

    # The DATABASE_URL from Helm contains $(DATABASE_PASSWORD) placeholder
    # that gets resolved by the shell. If it's still there, read the env var.
    db_password = os.environ.get("DATABASE_PASSWORD", "")
    if "$(DATABASE_PASSWORD)" in database_url and db_password:
        database_url = database_url.replace("$(DATABASE_PASSWORD)", db_password)

    engine = create_async_engine(database_url, echo=False)

    async with engine.begin() as conn:
        # Verify connection
        await conn.execute(text("SELECT 1"))
        logger.info("Connected to database")

    async with AsyncSession(engine, expire_on_commit=False) as session:
        async with session.begin():
            # Check if user already exists
            result = await session.execute(select(User).where(User.email == admin_email))
            existing_user = result.scalar_one_or_none()

            if existing_user:
                logger.info("User %s already exists, skipping user creation", admin_email)
            else:
                user = User(
                    email=admin_email,
                    display_name="Admin",
                    password_hash=hash_password(admin_password),
                    is_active=True,
                )
                session.add(user)
                logger.info("Created user: %s", admin_email)
                if generated:
                    logger.info("Generated password: %s", admin_password)
                    logger.warning("IMPORTANT: Save this password now. It will not be shown again.")

            # Check if admin role assignment exists
            result = await session.execute(
                select(PlatformRoleAssignment).where(
                    PlatformRoleAssignment.provider_name == "local",
                    PlatformRoleAssignment.email == admin_email,
                    PlatformRoleAssignment.role_name == "admin",
                )
            )
            existing_assignment = result.scalar_one_or_none()

            if existing_assignment:
                logger.info("Admin role already assigned to %s, skipping", admin_email)
            else:
                assignment = PlatformRoleAssignment(
                    provider_name="local",
                    email=admin_email,
                    role_name="admin",
                )
                session.add(assignment)
                logger.info("Assigned admin role to %s (provider: local)", admin_email)

            # Create join token if specified
            join_token = os.environ.get("BAMF_BOOTSTRAP_JOIN_TOKEN", "").strip()
            if join_token:
                token_hash = hashlib.sha256(join_token.encode()).hexdigest()
                result = await session.execute(
                    select(JoinToken).where(JoinToken.token_hash == token_hash)
                )
                existing_token = result.scalar_one_or_none()

                if existing_token:
                    logger.info("Join token already exists, skipping")
                else:
                    token = JoinToken(
                        name="bootstrap-token",
                        token_hash=token_hash,
                        expires_at=datetime.now(UTC) + timedelta(days=365),
                        max_uses=None,  # Unlimited uses for dev
                        agent_labels={"bootstrap": "true"},
                        created_by="system@bootstrap",
                    )
                    session.add(token)
                    logger.info("Created join token: bootstrap-token")

    await engine.dispose()
    logger.info("Bootstrap complete")


if __name__ == "__main__":
    asyncio.run(bootstrap())
