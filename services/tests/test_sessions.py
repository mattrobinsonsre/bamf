"""Tests for Redis session management."""

import json
from datetime import timedelta
from unittest.mock import AsyncMock, patch

import pytest

from bamf.auth.sessions import (
    SESSION_REFRESH_INTERVAL,
    _should_refresh_session,
    create_session,
    get_session,
    list_user_sessions,
    refresh_session,
    revoke_all_user_sessions,
    revoke_session,
)
from bamf.db.models import utc_now


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


class TestCreateSessionMaxTTL:
    """Test session creation with max_ttl (id_token cap)."""

    @pytest.fixture
    def mock_redis(self):
        redis = AsyncMock()
        pipeline = AsyncMock()
        pipeline.__aenter__ = AsyncMock(return_value=pipeline)
        pipeline.__aexit__ = AsyncMock(return_value=None)
        redis.pipeline = lambda **kwargs: pipeline
        return redis, pipeline

    @pytest.mark.asyncio
    async def test_max_ttl_caps_session(self, mock_redis):
        """When max_ttl < configured TTL, session expires sooner."""
        redis, pipeline = mock_redis

        with patch("bamf.auth.sessions.get_redis_client", return_value=redis):
            session = await create_session(
                email="user@example.com",
                display_name=None,
                roles=["admin"],
                provider_name="auth0",
                max_ttl=1800,  # 30 minutes
            )

        # Verify the pipeline.set was called with ex=1800 (capped TTL)
        call_args = pipeline.set.call_args
        assert call_args.kwargs.get("ex") == 1800 or call_args[1].get("ex") == 1800

        # Verify expires_at is ~30 min from now, not 12 hours
        from datetime import datetime

        expires = datetime.fromisoformat(session.expires_at)
        created = datetime.fromisoformat(session.created_at)
        delta = (expires - created).total_seconds()
        assert 1790 <= delta <= 1810  # ~30 minutes, with tolerance

    @pytest.mark.asyncio
    async def test_max_ttl_none_uses_default(self, mock_redis):
        """When max_ttl is None, session uses configured TTL."""
        redis, pipeline = mock_redis

        with (
            patch("bamf.auth.sessions.get_redis_client", return_value=redis),
            patch("bamf.auth.sessions._session_ttl", return_value=43200),
        ):
            await create_session(
                email="user@example.com",
                display_name=None,
                roles=[],
                provider_name="local",
                max_ttl=None,
            )

        call_args = pipeline.set.call_args
        assert call_args.kwargs.get("ex") == 43200 or call_args[1].get("ex") == 43200

    @pytest.mark.asyncio
    async def test_max_ttl_larger_than_config_ignored(self, mock_redis):
        """When max_ttl > configured TTL, configured TTL wins."""
        redis, pipeline = mock_redis

        with (
            patch("bamf.auth.sessions.get_redis_client", return_value=redis),
            patch("bamf.auth.sessions._session_ttl", return_value=3600),
        ):
            await create_session(
                email="user@example.com",
                display_name=None,
                roles=[],
                provider_name="auth0",
                max_ttl=86400,  # 24 hours > configured 1 hour
            )

        call_args = pipeline.set.call_args
        assert call_args.kwargs.get("ex") == 3600 or call_args[1].get("ex") == 3600

    @pytest.mark.asyncio
    async def test_max_ttl_zero_ignored(self, mock_redis):
        """When max_ttl is 0, configured TTL is used (0 is not positive)."""
        redis, pipeline = mock_redis

        with (
            patch("bamf.auth.sessions.get_redis_client", return_value=redis),
            patch("bamf.auth.sessions._session_ttl", return_value=3600),
        ):
            await create_session(
                email="user@example.com",
                display_name=None,
                roles=[],
                provider_name="auth0",
                max_ttl=0,
            )

        call_args = pipeline.set.call_args
        assert call_args.kwargs.get("ex") == 3600 or call_args[1].get("ex") == 3600


class TestShouldRefreshSession:
    """Test the rate-limiting logic for session refresh."""

    def test_recent_activity_no_refresh(self):
        """Session active 1 minute ago — no refresh needed."""
        from bamf.auth.sessions import Session

        now = utc_now()
        session = Session(
            email="user@example.com",
            display_name=None,
            roles=[],
            provider_name="local",
            created_at=now.isoformat(),
            expires_at=(now + timedelta(hours=12)).isoformat(),
            last_active_at=(now - timedelta(minutes=1)).isoformat(),
        )
        assert _should_refresh_session(session) is False

    def test_stale_activity_needs_refresh(self):
        """Session active 10 minutes ago — refresh needed."""
        from bamf.auth.sessions import Session

        now = utc_now()
        session = Session(
            email="user@example.com",
            display_name=None,
            roles=[],
            provider_name="local",
            created_at=now.isoformat(),
            expires_at=(now + timedelta(hours=12)).isoformat(),
            last_active_at=(now - timedelta(minutes=10)).isoformat(),
        )
        assert _should_refresh_session(session) is True

    def test_exactly_at_threshold(self):
        """Session active exactly at threshold — no refresh (> not >=)."""
        from bamf.auth.sessions import Session

        fixed_now = utc_now()
        session = Session(
            email="user@example.com",
            display_name=None,
            roles=[],
            provider_name="local",
            created_at=fixed_now.isoformat(),
            expires_at=(fixed_now + timedelta(hours=12)).isoformat(),
            last_active_at=(fixed_now - timedelta(seconds=SESSION_REFRESH_INTERVAL)).isoformat(),
        )
        # Pin utc_now so no time elapses between setting last_active_at and the check
        with patch("bamf.auth.sessions.utc_now", return_value=fixed_now):
            # At exactly the threshold, (now - last_active).total_seconds() == 300
            # The check is > 300, so this should be False
            assert _should_refresh_session(session) is False

    def test_invalid_timestamp_refreshes(self):
        """Invalid last_active_at — refresh to be safe."""
        from bamf.auth.sessions import Session

        now = utc_now()
        session = Session(
            email="user@example.com",
            display_name=None,
            roles=[],
            provider_name="local",
            created_at=now.isoformat(),
            expires_at=(now + timedelta(hours=12)).isoformat(),
            last_active_at="not-a-timestamp",
        )
        assert _should_refresh_session(session) is True


class TestRefreshSession:
    """Test session TTL refresh (sliding window)."""

    @pytest.fixture
    def mock_redis(self):
        redis = AsyncMock()
        pipeline = AsyncMock()
        pipeline.__aenter__ = AsyncMock(return_value=pipeline)
        pipeline.__aexit__ = AsyncMock(return_value=None)
        redis.pipeline = lambda **kwargs: pipeline
        return redis, pipeline

    @pytest.mark.asyncio
    async def test_refresh_updates_ttl(self, mock_redis):
        """Refreshing a session resets its Redis TTL and updates timestamps."""
        redis, pipeline = mock_redis
        from bamf.auth.sessions import Session

        now = utc_now()
        old_active = (now - timedelta(minutes=10)).isoformat()
        session_data = {
            "email": "user@example.com",
            "display_name": None,
            "roles": ["admin"],
            "provider_name": "local",
            "created_at": now.isoformat(),
            "expires_at": (now + timedelta(hours=2)).isoformat(),
            "last_active_at": old_active,
            "kubernetes_groups": [],
        }
        redis.get = AsyncMock(return_value=json.dumps(session_data))

        session = Session(token="test-token", **session_data)

        with patch("bamf.auth.sessions.get_redis_client", return_value=redis):
            await refresh_session("test-token", session)

        # Pipeline should have set the session with new TTL and expire user key
        pipeline.set.assert_called_once()
        pipeline.expire.assert_called_once()
        pipeline.execute.assert_called_once()

        # Verify the stored data has updated timestamps
        stored_data = json.loads(pipeline.set.call_args[0][1])
        assert stored_data["last_active_at"] != old_active
        assert stored_data["email"] == "user@example.com"

    @pytest.mark.asyncio
    async def test_refresh_vanished_session(self, mock_redis):
        """Refreshing a session that vanished between check and refresh is harmless."""
        redis, pipeline = mock_redis
        from bamf.auth.sessions import Session

        now = utc_now()
        redis.get = AsyncMock(return_value=None)  # Session gone

        session = Session(
            email="user@example.com",
            display_name=None,
            roles=[],
            provider_name="local",
            created_at=now.isoformat(),
            expires_at=(now + timedelta(hours=12)).isoformat(),
            last_active_at=now.isoformat(),
            token="test-token",
        )

        with patch("bamf.auth.sessions.get_redis_client", return_value=redis):
            await refresh_session("test-token", session)

        # Pipeline should NOT have been used since session was gone
        pipeline.set.assert_not_called()
