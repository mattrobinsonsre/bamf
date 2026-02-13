"""Tests for authentication functionality."""

from datetime import UTC, datetime, timedelta

import pytest

from bamf.auth.passwords import hash_password, verify_password
from bamf.auth.tokens import create_access_token, decode_access_token


class TestPasswords:
    """Test password hashing and verification."""

    def test_hash_password(self):
        """Test password hashing produces valid hash."""
        password = "test-password-123"
        hashed = hash_password(password)

        assert hashed != password
        assert hashed.startswith("pbkdf2:sha256:")

    def test_verify_password_correct(self):
        """Test correct password verification."""
        password = "test-password-123"
        hashed = hash_password(password)

        assert verify_password(password, hashed) is True

    def test_verify_password_incorrect(self):
        """Test incorrect password verification."""
        password = "test-password-123"
        wrong_password = "wrong-password"
        hashed = hash_password(password)

        assert verify_password(wrong_password, hashed) is False

    def test_hash_uniqueness(self):
        """Test same password produces different hashes (salt)."""
        password = "test-password-123"
        hash1 = hash_password(password)
        hash2 = hash_password(password)

        assert hash1 != hash2
        # But both should verify
        assert verify_password(password, hash1)
        assert verify_password(password, hash2)


class TestTokens:
    """Test JWT token creation and validation."""

    def test_create_access_token(self):
        """Test access token creation."""
        email = "test@example.com"
        expires_at = datetime.now(UTC) + timedelta(hours=1)

        token = create_access_token(email=email, expires_at=expires_at)

        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0

    def test_decode_access_token(self):
        """Test access token decoding."""
        email = "test@example.com"
        expires_at = datetime.now(UTC) + timedelta(hours=1)

        token = create_access_token(email=email, expires_at=expires_at)
        payload = decode_access_token(token)

        assert payload is not None
        assert payload["sub"] == email

    def test_decode_invalid_token(self):
        """Test invalid token raises exception."""
        with pytest.raises(ValueError):
            decode_access_token("invalid-token")

    def test_token_with_roles(self):
        """Test token creation with additional claims."""
        email = "test@example.com"
        expires_at = datetime.now(UTC) + timedelta(hours=1)
        roles = ["admin", "user"]

        token = create_access_token(
            email=email,
            expires_at=expires_at,
            additional_claims={"roles": roles},
        )
        payload = decode_access_token(token)

        assert payload["roles"] == roles

    def test_token_with_roles_and_provider(self):
        """Test token creation with roles and provider claims."""
        email = "test@example.com"
        expires_at = datetime.now(UTC) + timedelta(hours=1)

        token = create_access_token(
            email=email,
            expires_at=expires_at,
            roles=["admin", "ssh-access"],
            provider="auth0",
        )
        payload = decode_access_token(token)

        assert payload["sub"] == email
        assert payload["roles"] == ["admin", "ssh-access"]
        assert payload["provider"] == "auth0"

    def test_token_without_optional_claims(self):
        """Test that optional claims are omitted when not provided."""
        email = "test@example.com"
        expires_at = datetime.now(UTC) + timedelta(hours=1)

        token = create_access_token(email=email, expires_at=expires_at)
        payload = decode_access_token(token)

        assert payload["sub"] == email
        assert "roles" not in payload
        assert "provider" not in payload
