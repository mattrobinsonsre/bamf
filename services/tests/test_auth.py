"""Tests for authentication functionality."""

from bamf.auth.passwords import hash_password, verify_password


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
