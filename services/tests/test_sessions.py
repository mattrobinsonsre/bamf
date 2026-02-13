"""Tests for Redis session management."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from bamf.auth.sessions import (
    create_session,
    get_session,
    list_user_sessions,
    revoke_all_user_sessions,
    revoke_session,
)


class TestCreateSession:
    """Test session creation."""

    @pytest.fixture
    def mock_redis(self):
        """Create a mock Redis client with pipeline support."""
        redis = AsyncMock()
        pipeline = AsyncMock()
        pipeline.__aenter__ = AsyncMock(return_value=pipeline)
        pipeline.__aexit__ = AsyncMock(return_value=None)
        redis.pipeline = lambda **kwargs: pipeline
        return redis, pipeline

    @pytest.mark.asyncio
    async def test_create_session(self, mock_redis):
        """Test creating a session stores in Redis and returns token."""
        redis, pipeline = mock_redis

        with patch("bamf.auth.sessions.get_redis_client", return_value=redis):
            session = await create_session(
                email="user@example.com",
                display_name="Test User",
                roles=["admin", "ssh-access"],
                provider_name="local",
            )

        assert session.token != ""
        assert session.email == "user@example.com"
        assert session.roles == ["admin", "ssh-access"]
        assert session.provider_name == "local"
        assert session.display_name == "Test User"

        # Pipeline should have been used for atomic set + sadd + expire
        pipeline.set.assert_called_once()
        pipeline.sadd.assert_called_once()
        pipeline.execute.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_session_unique_tokens(self, mock_redis):
        """Test that each session gets a unique token."""
        redis, _ = mock_redis
        tokens = set()

        with patch("bamf.auth.sessions.get_redis_client", return_value=redis):
            for _ in range(10):
                session = await create_session(
                    email="user@example.com",
                    display_name=None,
                    roles=[],
                    provider_name="local",
                )
                tokens.add(session.token)

        assert len(tokens) == 10


class TestGetSession:
    """Test session lookup."""

    @pytest.mark.asyncio
    async def test_get_session_found(self):
        """Test retrieving an existing session."""
        redis = AsyncMock()
        session_data = {
            "email": "user@example.com",
            "display_name": "Test User",
            "roles": ["admin"],
            "provider_name": "auth0",
            "created_at": "2024-01-01T00:00:00+00:00",
            "expires_at": "2024-01-01T12:00:00+00:00",
            "last_active_at": "2024-01-01T00:00:00+00:00",
        }
        redis.get = AsyncMock(return_value=json.dumps(session_data))

        with patch("bamf.auth.sessions.get_redis_client", return_value=redis):
            session = await get_session("test-token")

        assert session is not None
        assert session.token == "test-token"
        assert session.email == "user@example.com"
        assert session.roles == ["admin"]
        assert session.provider_name == "auth0"

    @pytest.mark.asyncio
    async def test_get_session_not_found(self):
        """Test retrieving a non-existent session."""
        redis = AsyncMock()
        redis.get = AsyncMock(return_value=None)

        with patch("bamf.auth.sessions.get_redis_client", return_value=redis):
            session = await get_session("nonexistent-token")

        assert session is None


class TestRevokeSession:
    """Test session revocation."""

    @pytest.fixture
    def mock_redis(self):
        """Create a mock Redis client with pipeline support."""
        redis = AsyncMock()
        pipeline = AsyncMock()
        pipeline.__aenter__ = AsyncMock(return_value=pipeline)
        pipeline.__aexit__ = AsyncMock(return_value=None)
        redis.pipeline = lambda **kwargs: pipeline
        return redis, pipeline

    @pytest.mark.asyncio
    async def test_revoke_existing_session(self, mock_redis):
        """Test revoking an existing session."""
        redis, pipeline = mock_redis
        session_data = json.dumps({"email": "user@example.com"})
        redis.get = AsyncMock(return_value=session_data)
        pipeline.execute.return_value = [1]  # delete returned 1

        with patch("bamf.auth.sessions.get_redis_client", return_value=redis):
            result = await revoke_session("test-token")

        assert result is True
        pipeline.delete.assert_called_once()
        pipeline.srem.assert_called_once()

    @pytest.mark.asyncio
    async def test_revoke_nonexistent_session(self, mock_redis):
        """Test revoking a session that doesn't exist."""
        redis, pipeline = mock_redis
        redis.get = AsyncMock(return_value=None)
        pipeline.execute.return_value = [0]  # delete returned 0

        with patch("bamf.auth.sessions.get_redis_client", return_value=redis):
            result = await revoke_session("nonexistent-token")

        assert result is False


class TestListUserSessions:
    """Test listing user sessions."""

    @pytest.mark.asyncio
    async def test_list_sessions(self):
        """Test listing sessions for a user."""
        redis = AsyncMock()
        redis.smembers = AsyncMock(return_value={"token-1", "token-2"})

        session_data = json.dumps(
            {
                "email": "user@example.com",
                "display_name": None,
                "roles": ["admin"],
                "provider_name": "local",
                "created_at": "2024-01-01T00:00:00+00:00",
                "expires_at": "2024-01-01T12:00:00+00:00",
                "last_active_at": "2024-01-01T00:00:00+00:00",
            }
        )
        redis.get = AsyncMock(return_value=session_data)
        redis.srem = AsyncMock()

        with patch("bamf.auth.sessions.get_redis_client", return_value=redis):
            sessions = await list_user_sessions("user@example.com")

        assert len(sessions) == 2

    @pytest.mark.asyncio
    async def test_list_sessions_empty(self):
        """Test listing sessions when none exist."""
        redis = AsyncMock()
        redis.smembers = AsyncMock(return_value=set())

        with patch("bamf.auth.sessions.get_redis_client", return_value=redis):
            sessions = await list_user_sessions("user@example.com")

        assert sessions == []

    @pytest.mark.asyncio
    async def test_list_sessions_cleans_stale(self):
        """Test that stale tokens are cleaned from the user's set."""
        redis = AsyncMock()
        redis.smembers = AsyncMock(return_value={"active-token", "stale-token"})

        async def mock_get(key):
            if "active-token" in key:
                return json.dumps(
                    {
                        "email": "user@example.com",
                        "display_name": None,
                        "roles": [],
                        "provider_name": "local",
                        "created_at": "2024-01-01T00:00:00+00:00",
                        "expires_at": "2024-01-01T12:00:00+00:00",
                        "last_active_at": "2024-01-01T00:00:00+00:00",
                    }
                )
            return None  # stale-token expired

        redis.get = AsyncMock(side_effect=mock_get)
        redis.srem = AsyncMock()

        with patch("bamf.auth.sessions.get_redis_client", return_value=redis):
            sessions = await list_user_sessions("user@example.com")

        assert len(sessions) == 1
        assert sessions[0].token == "active-token"
        # Should have cleaned up the stale token
        redis.srem.assert_called_once()


class TestRevokeAllUserSessions:
    """Test revoking all sessions for a user."""

    @pytest.fixture
    def mock_redis(self):
        """Create a mock Redis client with pipeline support."""
        redis = AsyncMock()
        pipeline = AsyncMock()
        pipeline.__aenter__ = AsyncMock(return_value=pipeline)
        pipeline.__aexit__ = AsyncMock(return_value=None)
        redis.pipeline = lambda **kwargs: pipeline
        return redis, pipeline

    @pytest.mark.asyncio
    async def test_revoke_all(self, mock_redis):
        """Test revoking all sessions for a user."""
        redis, pipeline = mock_redis
        redis.smembers = AsyncMock(return_value={"token-1", "token-2"})
        pipeline.execute.return_value = [1, 1, 1]  # 2 session deletes + 1 set delete

        with patch("bamf.auth.sessions.get_redis_client", return_value=redis):
            count = await revoke_all_user_sessions("user@example.com")

        assert count == 2

    @pytest.mark.asyncio
    async def test_revoke_all_empty(self, mock_redis):
        """Test revoking when no sessions exist."""
        redis, _ = mock_redis
        redis.smembers = AsyncMock(return_value=set())

        with patch("bamf.auth.sessions.get_redis_client", return_value=redis):
            count = await revoke_all_user_sessions("user@example.com")

        assert count == 0
