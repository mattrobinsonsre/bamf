"""Tests for Redis recent user tracking."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from bamf.auth.recent_users import (
    RECENT_USER_PREFIX,
    RECENT_USER_TTL,
    list_recent_users,
    record_recent_user,
)


class TestRecordRecentUser:
    """Test recording recent users in Redis."""

    @pytest.fixture
    def mock_redis(self):
        """Create a mock Redis client."""
        redis = AsyncMock()
        return redis

    @pytest.mark.asyncio
    async def test_record_sets_key_with_ttl(self, mock_redis):
        """Recording a user should SET the key with 7-day TTL."""
        with patch("bamf.auth.recent_users.get_redis_client", return_value=mock_redis):
            await record_recent_user("auth0", "alice@corp.com", "Alice")

        expected_key = f"{RECENT_USER_PREFIX}auth0:alice@corp.com"
        mock_redis.set.assert_called_once()
        args, kwargs = mock_redis.set.call_args
        assert args[0] == expected_key
        assert kwargs["ex"] == RECENT_USER_TTL

        # Verify the stored value
        stored = json.loads(args[1])
        assert stored["provider_name"] == "auth0"
        assert stored["email"] == "alice@corp.com"
        assert stored["display_name"] == "Alice"
        assert "last_seen" in stored

    @pytest.mark.asyncio
    async def test_record_with_none_display_name(self, mock_redis):
        """Recording a user with no display name should work."""
        with patch("bamf.auth.recent_users.get_redis_client", return_value=mock_redis):
            await record_recent_user("local", "bob@corp.com", None)

        args, _ = mock_redis.set.call_args
        stored = json.loads(args[1])
        assert stored["display_name"] is None

    @pytest.mark.asyncio
    async def test_record_local_provider(self, mock_redis):
        """Recording a local auth user should use 'local' as provider."""
        with patch("bamf.auth.recent_users.get_redis_client", return_value=mock_redis):
            await record_recent_user("local", "admin@corp.com", "Admin")

        expected_key = f"{RECENT_USER_PREFIX}local:admin@corp.com"
        args, _ = mock_redis.set.call_args
        assert args[0] == expected_key

    @pytest.mark.asyncio
    async def test_ttl_is_seven_days(self):
        """TTL constant should be 7 days in seconds."""
        assert RECENT_USER_TTL == 604800  # 7 * 24 * 60 * 60


class TestListRecentUsers:
    """Test listing recent users from Redis."""

    @pytest.fixture
    def mock_redis(self):
        """Create a mock Redis client with scan_iter support."""
        redis = AsyncMock()
        return redis

    @pytest.mark.asyncio
    async def test_list_returns_all_recent_users(self, mock_redis):
        """Listing should return all matching keys."""
        user1 = json.dumps(
            {
                "provider_name": "auth0",
                "email": "alice@corp.com",
                "display_name": "Alice",
                "last_seen": "2025-02-03T10:00:00+00:00",
            }
        )
        user2 = json.dumps(
            {
                "provider_name": "local",
                "email": "bob@corp.com",
                "display_name": None,
                "last_seen": "2025-02-03T12:00:00+00:00",
            }
        )

        # Mock scan_iter as an async generator
        async def mock_scan_iter(**kwargs):
            yield f"{RECENT_USER_PREFIX}auth0:alice@corp.com"
            yield f"{RECENT_USER_PREFIX}local:bob@corp.com"

        mock_redis.scan_iter = mock_scan_iter
        mock_redis.get = AsyncMock(side_effect=[user1, user2])

        with patch("bamf.auth.recent_users.get_redis_client", return_value=mock_redis):
            users = await list_recent_users()

        assert len(users) == 2
        # Sorted by last_seen descending — bob (12:00) before alice (10:00)
        assert users[0].email == "bob@corp.com"
        assert users[1].email == "alice@corp.com"

    @pytest.mark.asyncio
    async def test_list_empty_when_no_recent_users(self, mock_redis):
        """Listing with no matching keys returns empty list."""

        async def mock_scan_iter(**kwargs):
            return
            yield  # noqa: RET504  — make this an async generator

        mock_redis.scan_iter = mock_scan_iter

        with patch("bamf.auth.recent_users.get_redis_client", return_value=mock_redis):
            users = await list_recent_users()

        assert users == []

    @pytest.mark.asyncio
    async def test_list_skips_expired_keys(self, mock_redis):
        """Keys that expired between SCAN and GET should be skipped."""
        user1 = json.dumps(
            {
                "provider_name": "auth0",
                "email": "alice@corp.com",
                "display_name": "Alice",
                "last_seen": "2025-02-03T10:00:00+00:00",
            }
        )

        async def mock_scan_iter(**kwargs):
            yield f"{RECENT_USER_PREFIX}auth0:alice@corp.com"
            yield f"{RECENT_USER_PREFIX}expired:user@corp.com"

        mock_redis.scan_iter = mock_scan_iter
        # Second GET returns None (key expired between SCAN and GET)
        mock_redis.get = AsyncMock(side_effect=[user1, None])

        with patch("bamf.auth.recent_users.get_redis_client", return_value=mock_redis):
            users = await list_recent_users()

        assert len(users) == 1
        assert users[0].email == "alice@corp.com"
