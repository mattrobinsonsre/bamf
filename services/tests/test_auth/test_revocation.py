"""Tests for certificate revocation."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from bamf.auth.revocation import is_certificate_revoked, revoke_certificate


@pytest.mark.asyncio
async def test_is_certificate_revoked_true():
    redis = MagicMock()
    redis.sismember = AsyncMock(return_value=1)
    with patch("bamf.auth.revocation.get_redis_client", return_value=redis):
        assert await is_certificate_revoked("abc") is True


@pytest.mark.asyncio
async def test_is_certificate_revoked_false():
    redis = MagicMock()
    redis.sismember = AsyncMock(return_value=0)
    with patch("bamf.auth.revocation.get_redis_client", return_value=redis):
        assert await is_certificate_revoked("abc") is False


@pytest.mark.asyncio
async def test_is_certificate_revoked_fails_open_on_redis_error():
    with patch("bamf.auth.revocation.get_redis_client", side_effect=RuntimeError("down")):
        assert await is_certificate_revoked("abc") is False


@pytest.mark.asyncio
async def test_revoke_adds_to_db_and_redis():
    redis = MagicMock()
    redis.sadd = AsyncMock()
    db = AsyncMock()
    db.get = AsyncMock(return_value=None)  # not already revoked
    db.add = MagicMock()
    db.flush = AsyncMock()
    with patch("bamf.auth.revocation.get_redis_client", return_value=redis):
        await revoke_certificate(db, "abc123", reason="leaked", revoked_by="admin@example.com")
    db.add.assert_called_once()
    redis.sadd.assert_awaited_once()


@pytest.mark.asyncio
async def test_revoke_idempotent_when_already_revoked():
    redis = MagicMock()
    redis.sadd = AsyncMock()
    db = AsyncMock()
    db.get = AsyncMock(return_value=object())  # already in the table
    db.add = MagicMock()
    with patch("bamf.auth.revocation.get_redis_client", return_value=redis):
        await revoke_certificate(db, "abc123")
    db.add.assert_not_called()  # no duplicate row
    redis.sadd.assert_awaited_once()  # but still ensures the Redis set has it
