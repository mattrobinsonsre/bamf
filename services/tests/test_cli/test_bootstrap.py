"""Tests for the bootstrap CLI script.

Tests the bootstrap() async function which creates the initial admin user,
assigns the admin platform role, and optionally creates a join token.
"""

from __future__ import annotations

import hashlib
from unittest.mock import patch

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.auth.passwords import verify_password
from bamf.cli.bootstrap import bootstrap
from bamf.db.models import JoinToken, PlatformRoleAssignment, User

# ── Tests: Missing Environment Variables ─────────────────────────────────


class TestBootstrapMissingEnvVars:
    @pytest.mark.asyncio
    async def test_missing_admin_email_exits(self, monkeypatch):
        """Missing BAMF_BOOTSTRAP_ADMIN_EMAIL causes sys.exit(1)."""
        monkeypatch.delenv("BAMF_BOOTSTRAP_ADMIN_EMAIL", raising=False)
        monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://x:x@localhost/x")

        with pytest.raises(SystemExit) as exc_info:
            await bootstrap()

        assert exc_info.value.code == 1

    @pytest.mark.asyncio
    async def test_empty_admin_email_exits(self, monkeypatch):
        """Empty string BAMF_BOOTSTRAP_ADMIN_EMAIL causes sys.exit(1)."""
        monkeypatch.setenv("BAMF_BOOTSTRAP_ADMIN_EMAIL", "  ")
        monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://x:x@localhost/x")

        with pytest.raises(SystemExit) as exc_info:
            await bootstrap()

        assert exc_info.value.code == 1

    @pytest.mark.asyncio
    async def test_missing_database_url_exits(self, monkeypatch):
        """Missing DATABASE_URL causes sys.exit(1)."""
        monkeypatch.setenv("BAMF_BOOTSTRAP_ADMIN_EMAIL", "admin@test.com")
        monkeypatch.delenv("DATABASE_URL", raising=False)

        with pytest.raises(SystemExit) as exc_info:
            await bootstrap()

        assert exc_info.value.code == 1

    @pytest.mark.asyncio
    async def test_empty_database_url_exits(self, monkeypatch):
        """Empty string DATABASE_URL causes sys.exit(1)."""
        monkeypatch.setenv("BAMF_BOOTSTRAP_ADMIN_EMAIL", "admin@test.com")
        monkeypatch.setenv("DATABASE_URL", "")

        with pytest.raises(SystemExit) as exc_info:
            await bootstrap()

        assert exc_info.value.code == 1


# ── Tests: Successful Bootstrap ──────────────────────────────────────────


class TestBootstrapSuccess:
    @pytest.mark.asyncio
    async def test_creates_user_and_role(self, async_engine, monkeypatch):
        """Bootstrap creates admin user and platform role assignment."""
        monkeypatch.setenv("BAMF_BOOTSTRAP_ADMIN_EMAIL", "admin@bootstrap.test")
        monkeypatch.setenv("BAMF_BOOTSTRAP_ADMIN_PASSWORD", "test-password-xyz!")
        monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://fake/fake")
        monkeypatch.delenv("BAMF_BOOTSTRAP_JOIN_TOKEN", raising=False)

        with patch(
            "bamf.cli.bootstrap.create_async_engine", return_value=async_engine
        ):
            await bootstrap()

        # Verify user was created
        async with AsyncSession(async_engine, expire_on_commit=False) as session:
            result = await session.execute(
                select(User).where(User.email == "admin@bootstrap.test")
            )
            user = result.scalar_one_or_none()
            assert user is not None
            assert user.email == "admin@bootstrap.test"
            assert user.display_name == "Admin"
            assert user.is_active is True
            assert verify_password("test-password-xyz!", user.password_hash)

            # Verify platform role assignment
            result = await session.execute(
                select(PlatformRoleAssignment).where(
                    PlatformRoleAssignment.provider_name == "local",
                    PlatformRoleAssignment.email == "admin@bootstrap.test",
                    PlatformRoleAssignment.role_name == "admin",
                )
            )
            assignment = result.scalar_one_or_none()
            assert assignment is not None

    @pytest.mark.asyncio
    async def test_generated_password_when_omitted(self, async_engine, monkeypatch):
        """When BAMF_BOOTSTRAP_ADMIN_PASSWORD is missing, a password is generated."""
        monkeypatch.setenv("BAMF_BOOTSTRAP_ADMIN_EMAIL", "gen@bootstrap.test")
        monkeypatch.delenv("BAMF_BOOTSTRAP_ADMIN_PASSWORD", raising=False)
        monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://fake/fake")
        monkeypatch.delenv("BAMF_BOOTSTRAP_JOIN_TOKEN", raising=False)

        with patch(
            "bamf.cli.bootstrap.create_async_engine", return_value=async_engine
        ):
            await bootstrap()

        # Verify user was created with a password hash (generated)
        async with AsyncSession(async_engine, expire_on_commit=False) as session:
            result = await session.execute(
                select(User).where(User.email == "gen@bootstrap.test")
            )
            user = result.scalar_one_or_none()
            assert user is not None
            assert user.password_hash is not None
            assert user.password_hash.startswith("pbkdf2:sha256:100000$")


# ── Tests: Idempotency ──────────────────────────────────────────────────


class TestBootstrapIdempotency:
    @pytest.mark.asyncio
    async def test_skips_existing_user(self, async_engine, monkeypatch):
        """Running bootstrap twice does not create a duplicate user."""
        monkeypatch.setenv("BAMF_BOOTSTRAP_ADMIN_EMAIL", "idempotent@bootstrap.test")
        monkeypatch.setenv("BAMF_BOOTSTRAP_ADMIN_PASSWORD", "first-password-abc!")
        monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://fake/fake")
        monkeypatch.delenv("BAMF_BOOTSTRAP_JOIN_TOKEN", raising=False)

        with patch(
            "bamf.cli.bootstrap.create_async_engine", return_value=async_engine
        ):
            await bootstrap()
            # Run again -- should skip user creation
            await bootstrap()

        # Verify only one user exists
        async with AsyncSession(async_engine, expire_on_commit=False) as session:
            result = await session.execute(
                select(User).where(User.email == "idempotent@bootstrap.test")
            )
            users = result.scalars().all()
            assert len(users) == 1

            # Verify the original password is preserved (not overwritten)
            assert verify_password("first-password-abc!", users[0].password_hash)

    @pytest.mark.asyncio
    async def test_skips_existing_role_assignment(self, async_engine, monkeypatch):
        """Running bootstrap twice does not duplicate the admin role assignment."""
        monkeypatch.setenv("BAMF_BOOTSTRAP_ADMIN_EMAIL", "role-idem@bootstrap.test")
        monkeypatch.setenv("BAMF_BOOTSTRAP_ADMIN_PASSWORD", "role-pass-xyz!")
        monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://fake/fake")
        monkeypatch.delenv("BAMF_BOOTSTRAP_JOIN_TOKEN", raising=False)

        with patch(
            "bamf.cli.bootstrap.create_async_engine", return_value=async_engine
        ):
            await bootstrap()
            await bootstrap()

        async with AsyncSession(async_engine, expire_on_commit=False) as session:
            result = await session.execute(
                select(PlatformRoleAssignment).where(
                    PlatformRoleAssignment.email == "role-idem@bootstrap.test",
                )
            )
            assignments = result.scalars().all()
            assert len(assignments) == 1


# ── Tests: Join Token ────────────────────────────────────────────────────


class TestBootstrapJoinToken:
    @pytest.mark.asyncio
    async def test_creates_join_token(self, async_engine, monkeypatch):
        """Setting BAMF_BOOTSTRAP_JOIN_TOKEN creates a join token."""
        monkeypatch.setenv("BAMF_BOOTSTRAP_ADMIN_EMAIL", "token@bootstrap.test")
        monkeypatch.setenv("BAMF_BOOTSTRAP_ADMIN_PASSWORD", "token-pass-abc!")
        monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://fake/fake")
        monkeypatch.setenv("BAMF_BOOTSTRAP_JOIN_TOKEN", "my-secret-join-token")

        with patch(
            "bamf.cli.bootstrap.create_async_engine", return_value=async_engine
        ):
            await bootstrap()

        expected_hash = hashlib.sha256(b"my-secret-join-token").hexdigest()

        async with AsyncSession(async_engine, expire_on_commit=False) as session:
            result = await session.execute(
                select(JoinToken).where(JoinToken.token_hash == expected_hash)
            )
            token = result.scalar_one_or_none()
            assert token is not None
            assert token.name == "bootstrap-token"
            assert token.max_uses is None
            assert token.agent_labels == {"bootstrap": "true"}
            assert token.created_by == "system@bootstrap"
            assert token.expires_at is not None

    @pytest.mark.asyncio
    async def test_no_join_token_when_env_not_set(self, async_engine, monkeypatch):
        """Without BAMF_BOOTSTRAP_JOIN_TOKEN, no join token is created."""
        monkeypatch.setenv("BAMF_BOOTSTRAP_ADMIN_EMAIL", "notoken@bootstrap.test")
        monkeypatch.setenv("BAMF_BOOTSTRAP_ADMIN_PASSWORD", "notoken-pass-abc!")
        monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://fake/fake")
        monkeypatch.delenv("BAMF_BOOTSTRAP_JOIN_TOKEN", raising=False)

        with patch(
            "bamf.cli.bootstrap.create_async_engine", return_value=async_engine
        ):
            await bootstrap()

        async with AsyncSession(async_engine, expire_on_commit=False) as session:
            result = await session.execute(select(JoinToken))
            tokens = result.scalars().all()
            assert len(tokens) == 0

    @pytest.mark.asyncio
    async def test_join_token_idempotent(self, async_engine, monkeypatch):
        """Running bootstrap twice with the same token does not duplicate it."""
        monkeypatch.setenv("BAMF_BOOTSTRAP_ADMIN_EMAIL", "tokenidem@bootstrap.test")
        monkeypatch.setenv("BAMF_BOOTSTRAP_ADMIN_PASSWORD", "tokenidem-pass-abc!")
        monkeypatch.setenv("DATABASE_URL", "postgresql+asyncpg://fake/fake")
        monkeypatch.setenv("BAMF_BOOTSTRAP_JOIN_TOKEN", "idempotent-token")

        with patch(
            "bamf.cli.bootstrap.create_async_engine", return_value=async_engine
        ):
            await bootstrap()
            await bootstrap()

        expected_hash = hashlib.sha256(b"idempotent-token").hexdigest()

        async with AsyncSession(async_engine, expire_on_commit=False) as session:
            result = await session.execute(
                select(JoinToken).where(JoinToken.token_hash == expected_hash)
            )
            tokens = result.scalars().all()
            assert len(tokens) == 1


# ── Tests: DATABASE_URL Placeholder Resolution ──────────────────────────


class TestDatabaseUrlPlaceholder:
    @pytest.mark.asyncio
    async def test_resolves_database_password_placeholder(
        self, async_engine, monkeypatch
    ):
        """$(DATABASE_PASSWORD) in DATABASE_URL is replaced with DATABASE_PASSWORD env var."""
        monkeypatch.setenv("BAMF_BOOTSTRAP_ADMIN_EMAIL", "placeholder@bootstrap.test")
        monkeypatch.setenv("BAMF_BOOTSTRAP_ADMIN_PASSWORD", "placeholder-pass!")
        monkeypatch.setenv(
            "DATABASE_URL",
            "postgresql+asyncpg://bamf:$(DATABASE_PASSWORD)@db:5432/bamf",
        )
        monkeypatch.setenv("DATABASE_PASSWORD", "real-db-password")
        monkeypatch.delenv("BAMF_BOOTSTRAP_JOIN_TOKEN", raising=False)

        captured_url = None

        def capture_engine(url, **kwargs):
            nonlocal captured_url
            captured_url = url
            return async_engine

        with patch(
            "bamf.cli.bootstrap.create_async_engine", side_effect=capture_engine
        ):
            await bootstrap()

        assert captured_url == "postgresql+asyncpg://bamf:real-db-password@db:5432/bamf"
        assert "$(DATABASE_PASSWORD)" not in captured_url

    @pytest.mark.asyncio
    async def test_placeholder_not_resolved_without_env(
        self, async_engine, monkeypatch
    ):
        """$(DATABASE_PASSWORD) is left in place if DATABASE_PASSWORD env var is empty."""
        monkeypatch.setenv("BAMF_BOOTSTRAP_ADMIN_EMAIL", "noenv@bootstrap.test")
        monkeypatch.setenv("BAMF_BOOTSTRAP_ADMIN_PASSWORD", "noenv-pass!")
        monkeypatch.setenv(
            "DATABASE_URL",
            "postgresql+asyncpg://bamf:$(DATABASE_PASSWORD)@db:5432/bamf",
        )
        monkeypatch.delenv("DATABASE_PASSWORD", raising=False)
        monkeypatch.delenv("BAMF_BOOTSTRAP_JOIN_TOKEN", raising=False)

        captured_url = None

        def capture_engine(url, **kwargs):
            nonlocal captured_url
            captured_url = url
            return async_engine

        with patch(
            "bamf.cli.bootstrap.create_async_engine", side_effect=capture_engine
        ):
            await bootstrap()

        # Placeholder remains because DATABASE_PASSWORD is not set
        assert "$(DATABASE_PASSWORD)" in captured_url

    @pytest.mark.asyncio
    async def test_no_placeholder_passes_url_unchanged(
        self, async_engine, monkeypatch
    ):
        """DATABASE_URL without placeholder is passed through unchanged."""
        monkeypatch.setenv("BAMF_BOOTSTRAP_ADMIN_EMAIL", "plain@bootstrap.test")
        monkeypatch.setenv("BAMF_BOOTSTRAP_ADMIN_PASSWORD", "plain-pass!")
        monkeypatch.setenv(
            "DATABASE_URL",
            "postgresql+asyncpg://bamf:literal-password@db:5432/bamf",
        )
        monkeypatch.delenv("BAMF_BOOTSTRAP_JOIN_TOKEN", raising=False)

        captured_url = None

        def capture_engine(url, **kwargs):
            nonlocal captured_url
            captured_url = url
            return async_engine

        with patch(
            "bamf.cli.bootstrap.create_async_engine", side_effect=capture_engine
        ):
            await bootstrap()

        assert captured_url == "postgresql+asyncpg://bamf:literal-password@db:5432/bamf"
