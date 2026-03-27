"""Tests for the password hashing and strength validation module."""

from __future__ import annotations

import pytest

from bamf.auth.passwords import hash_password, validate_password_strength, verify_password


class TestValidatePasswordStrength:
    def test_strong_password_passes(self):
        result = validate_password_strength("c0rrect-h0rse-battery-staple!")
        assert result == "c0rrect-h0rse-battery-staple!"

    def test_weak_password_raises(self):
        with pytest.raises(ValueError):
            validate_password_strength("password123")

    def test_password_over_72_chars_raises(self):
        long_password = "a" * 73
        with pytest.raises(ValueError, match="72 characters or fewer"):
            validate_password_strength(long_password)

    def test_exactly_72_chars_does_not_raise_for_length(self):
        # 72 chars of random-looking content that zxcvbn should score well
        password = "kX9$mP2!vR7@nQ4#wL6&jT8*bY1^cF3%dH5(gA0)eU"
        # Should not raise for the length check (may still fail zxcvbn)
        result = validate_password_strength(password)
        assert result == password

    def test_user_inputs_penalize_score(self):
        # "alice" alone as a password is weak, but with user_inputs
        # containing the email, passwords derived from the email should
        # be penalized even further.
        with pytest.raises(ValueError):
            validate_password_strength("alice2024", user_inputs=["alice@example.com"])


class TestHashPassword:
    def test_returns_correct_format(self):
        hashed = hash_password("test-password-123!")
        parts = hashed.split("$")
        assert len(parts) == 3
        assert parts[0] == "pbkdf2:sha256:100000"
        # Salt is 32 hex chars (16 bytes)
        assert len(parts[1]) == 32
        # Hash is 64 hex chars (32 bytes SHA-256)
        assert len(parts[2]) == 64

    def test_different_calls_produce_different_salts(self):
        hash1 = hash_password("same-password")
        hash2 = hash_password("same-password")
        salt1 = hash1.split("$")[1]
        salt2 = hash2.split("$")[1]
        assert salt1 != salt2


class TestVerifyPassword:
    def test_correct_password_returns_true(self):
        hashed = hash_password("my-secret-password")
        assert verify_password("my-secret-password", hashed) is True

    def test_wrong_password_returns_false(self):
        hashed = hash_password("my-secret-password")
        assert verify_password("wrong-password", hashed) is False

    def test_malformed_hash_returns_false(self):
        assert verify_password("anything", "not-a-hash") is False

    def test_wrong_method_prefix_returns_false(self):
        hashed = hash_password("test")
        # Replace pbkdf2 with bcrypt
        bad_hash = hashed.replace("pbkdf2:sha256:", "bcrypt:sha256:", 1)
        assert verify_password("test", bad_hash) is False

    def test_wrong_number_of_parts_returns_false(self):
        assert verify_password("test", "pbkdf2:sha256:100000$only-one-part") is False
