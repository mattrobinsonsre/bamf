"""Tests for Redis auth state management."""

import json
from unittest.mock import AsyncMock, patch

import pytest

from bamf.auth.auth_state import (
    AUTH_CODE_TTL,
    AUTH_STATE_TTL,
    AuthCode,
    AuthState,
    consume_auth_code,
    consume_auth_state,
    generate_code,
    generate_state,
    store_auth_code,
    store_auth_state,
)


class TestGenerateHelpers:
    """Test state/code generation."""

    def test_generate_state_is_unique(self):
        """Each generated state should be unique."""
        states = {generate_state() for _ in range(100)}
        assert len(states) == 100

    def test_generate_code_is_unique(self):
        """Each generated code should be unique."""
        codes = {generate_code() for _ in range(100)}
        assert len(codes) == 100

    def test_generate_state_is_url_safe(self):
        """Generated state should be URL-safe base64."""
        state = generate_state()
        # URL-safe base64 only contains these characters
        allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        assert all(c in allowed for c in state)


class TestAuthState:
    """Test auth state store/consume."""

    @pytest.fixture
    def mock_redis(self):
        """Create a mock Redis client."""
        redis = AsyncMock()
        # Pipeline must be a sync call returning an async context manager
        pipeline = AsyncMock()
        pipeline.__aenter__ = AsyncMock(return_value=pipeline)
        pipeline.__aexit__ = AsyncMock(return_value=None)
        redis.pipeline = lambda **kwargs: pipeline
        return redis, pipeline

    @pytest.mark.asyncio
    async def test_store_auth_state(self, mock_redis):
        """Test storing auth state in Redis."""
        redis, _ = mock_redis
        state = AuthState(
            provider_name="auth0",
            client_redirect_uri="http://localhost:8080/callback",
            client_state="client-state-123",
            code_challenge="challenge-abc",
            code_challenge_method="S256",
            idp_state="idp-state-xyz",
            nonce="nonce-123",
        )

        with patch("bamf.auth.auth_state.get_redis_client", return_value=redis):
            result = await store_auth_state(state)

        assert result == "idp-state-xyz"
        redis.set.assert_called_once()
        call_args = redis.set.call_args
        assert "bamf:auth_state:idp-state-xyz" == call_args[0][0]
        assert call_args[1]["ex"] == AUTH_STATE_TTL

    @pytest.mark.asyncio
    async def test_consume_auth_state_found(self, mock_redis):
        """Test consuming existing auth state."""
        redis, pipeline = mock_redis
        state_data = {
            "provider_name": "auth0",
            "client_redirect_uri": "http://localhost:8080/callback",
            "client_state": "client-state-123",
            "code_challenge": "challenge-abc",
            "code_challenge_method": "S256",
            "idp_state": "idp-state-xyz",
            "nonce": "nonce-123",
        }
        pipeline.execute.return_value = [json.dumps(state_data), 1]

        with patch("bamf.auth.auth_state.get_redis_client", return_value=redis):
            result = await consume_auth_state("idp-state-xyz")

        assert result is not None
        assert result.provider_name == "auth0"
        assert result.client_state == "client-state-123"
        assert result.code_challenge == "challenge-abc"

    @pytest.mark.asyncio
    async def test_consume_auth_state_not_found(self, mock_redis):
        """Test consuming non-existent auth state."""
        redis, pipeline = mock_redis
        pipeline.execute.return_value = [None, 0]

        with patch("bamf.auth.auth_state.get_redis_client", return_value=redis):
            result = await consume_auth_state("nonexistent-state")

        assert result is None


class TestAuthCode:
    """Test auth code store/consume."""

    @pytest.fixture
    def mock_redis(self):
        """Create a mock Redis client."""
        redis = AsyncMock()
        pipeline = AsyncMock()
        pipeline.__aenter__ = AsyncMock(return_value=pipeline)
        pipeline.__aexit__ = AsyncMock(return_value=None)
        redis.pipeline = lambda **kwargs: pipeline
        return redis, pipeline

    @pytest.mark.asyncio
    async def test_store_auth_code(self, mock_redis):
        """Test storing an auth code in Redis."""
        redis, _ = mock_redis
        auth_code = AuthCode(
            email="user@example.com",
            roles=["admin", "ssh-access"],
            provider_name="auth0",
            code_challenge="challenge-abc",
            code_challenge_method="S256",
        )

        with patch("bamf.auth.auth_state.get_redis_client", return_value=redis):
            await store_auth_code("test-code-123", auth_code)

        redis.set.assert_called_once()
        call_args = redis.set.call_args
        assert "bamf:auth_code:test-code-123" == call_args[0][0]
        assert call_args[1]["ex"] == AUTH_CODE_TTL

    @pytest.mark.asyncio
    async def test_consume_auth_code_found(self, mock_redis):
        """Test consuming existing auth code."""
        redis, pipeline = mock_redis
        code_data = {
            "email": "user@example.com",
            "roles": ["admin"],
            "provider_name": "auth0",
            "code_challenge": "challenge-abc",
            "code_challenge_method": "S256",
        }
        pipeline.execute.return_value = [json.dumps(code_data), 1]

        with patch("bamf.auth.auth_state.get_redis_client", return_value=redis):
            result = await consume_auth_code("test-code-123")

        assert result is not None
        assert result.email == "user@example.com"
        assert result.roles == ["admin"]
        assert result.provider_name == "auth0"

    @pytest.mark.asyncio
    async def test_consume_auth_code_not_found(self, mock_redis):
        """Test consuming non-existent auth code (expired or already used)."""
        redis, pipeline = mock_redis
        pipeline.execute.return_value = [None, 0]

        with patch("bamf.auth.auth_state.get_redis_client", return_value=redis):
            result = await consume_auth_code("expired-code")

        assert result is None
