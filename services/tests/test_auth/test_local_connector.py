"""Tests for the local identity provider connector.

Tests build_authorization_request() and handle_callback() with various
user states: valid credentials, missing user, wrong password, inactive user,
and user with no password_hash.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest

from bamf.auth.connectors.local import LocalConnector
from bamf.auth.passwords import hash_password
from bamf.auth.sso import AuthorizationRequest
from bamf.db.models import User


@pytest.fixture
def connector():
    return LocalConnector()


# ── Tests: Properties ────────────────────────────────────────────────────


class TestLocalConnectorProperties:
    def test_name(self, connector):
        assert connector.name == "local"

    def test_provider_type(self, connector):
        assert connector.provider_type == "local"

    def test_display_name_falls_back_to_name(self, connector):
        assert connector.display_name == "local"


# ── Tests: Build Authorization Request ───────────────────────────────────


class TestBuildAuthorizationRequest:
    @pytest.mark.asyncio
    async def test_returns_authorization_request(self, connector):
        with patch("bamf.auth.connectors.local.settings") as mock_settings:
            mock_settings.auth.callback_base_url = "https://bamf.example.com"

            req = await connector.build_authorization_request(
                callback_url="http://127.0.0.1:9999/callback",
                state="test-state-abc",
            )

        assert isinstance(req, AuthorizationRequest)
        assert req.state == "test-state-abc"
        assert req.authorize_url == "https://bamf.example.com/login?cli_state=test-state-abc"

    @pytest.mark.asyncio
    async def test_state_is_preserved(self, connector):
        with patch("bamf.auth.connectors.local.settings") as mock_settings:
            mock_settings.auth.callback_base_url = "https://bamf.test"

            req = await connector.build_authorization_request(
                callback_url="http://127.0.0.1:8080/callback",
                state="my-unique-state-42",
            )

        assert "cli_state=my-unique-state-42" in req.authorize_url

    @pytest.mark.asyncio
    async def test_login_url_uses_callback_base_url(self, connector):
        with patch("bamf.auth.connectors.local.settings") as mock_settings:
            mock_settings.auth.callback_base_url = "https://custom.domain.io"

            req = await connector.build_authorization_request(
                callback_url="http://127.0.0.1:8080/callback",
                state="s1",
            )

        assert req.authorize_url.startswith("https://custom.domain.io/login")


# ── Tests: Handle Callback ──────────────────────────────────────────────


class TestHandleCallback:
    @pytest.mark.asyncio
    async def test_valid_credentials(self, db_session, connector):
        """Correct email + password for an active user returns AuthenticatedIdentity."""
        password = "super-secret-password-123!"
        user = User(
            email="alice@example.com",
            display_name="Alice",
            password_hash=hash_password(password),
            is_active=True,
        )
        db_session.add(user)
        await db_session.flush()

        identity = await connector.handle_callback(
            callback_url="",
            db=db_session,
            email="alice@example.com",
            password=password,
        )

        assert identity.provider_name == "local"
        assert identity.email == "alice@example.com"
        assert identity.subject == "alice@example.com"
        assert identity.display_name == "Alice"
        assert identity.groups == []
        assert identity.raw_claims["sub"] == "alice@example.com"
        assert identity.raw_claims["auth_method"] == "password"

    @pytest.mark.asyncio
    async def test_user_not_found_raises(self, db_session, connector):
        """Non-existent email raises ValueError."""
        with pytest.raises(ValueError, match="Invalid credentials"):
            await connector.handle_callback(
                callback_url="",
                db=db_session,
                email="nobody@example.com",
                password="anything",
            )

    @pytest.mark.asyncio
    async def test_wrong_password_raises(self, db_session, connector):
        """Correct email but wrong password raises ValueError."""
        user = User(
            email="bob@example.com",
            display_name="Bob",
            password_hash=hash_password("correct-password-xyz!"),
            is_active=True,
        )
        db_session.add(user)
        await db_session.flush()

        with pytest.raises(ValueError, match="Invalid credentials"):
            await connector.handle_callback(
                callback_url="",
                db=db_session,
                email="bob@example.com",
                password="wrong-password",
            )

    @pytest.mark.asyncio
    async def test_inactive_user_raises(self, db_session, connector):
        """Active user with correct password but is_active=False raises."""
        password = "valid-password-456!"
        user = User(
            email="disabled@example.com",
            display_name="Disabled User",
            password_hash=hash_password(password),
            is_active=False,
        )
        db_session.add(user)
        await db_session.flush()

        with pytest.raises(ValueError, match="User account is disabled"):
            await connector.handle_callback(
                callback_url="",
                db=db_session,
                email="disabled@example.com",
                password=password,
            )

    @pytest.mark.asyncio
    async def test_user_without_password_hash_raises(self, db_session, connector):
        """User with no password_hash (SSO-only user in local table) raises."""
        user = User(
            email="sso-only@example.com",
            display_name="SSO User",
            password_hash=None,
            is_active=True,
        )
        db_session.add(user)
        await db_session.flush()

        with pytest.raises(ValueError, match="Invalid credentials"):
            await connector.handle_callback(
                callback_url="",
                db=db_session,
                email="sso-only@example.com",
                password="any-password",
            )

    @pytest.mark.asyncio
    async def test_empty_password_hash_raises(self, db_session, connector):
        """User with empty string password_hash raises (treated as falsy)."""
        user = User(
            email="empty-hash@example.com",
            display_name="Empty Hash",
            password_hash="",
            is_active=True,
        )
        db_session.add(user)
        await db_session.flush()

        with pytest.raises(ValueError, match="Invalid credentials"):
            await connector.handle_callback(
                callback_url="",
                db=db_session,
                email="empty-hash@example.com",
                password="any-password",
            )

    @pytest.mark.asyncio
    async def test_returns_empty_groups(self, db_session, connector):
        """Local connector always returns empty groups list."""
        password = "another-valid-pass-789!"
        user = User(
            email="carol@example.com",
            display_name="Carol",
            password_hash=hash_password(password),
            is_active=True,
        )
        db_session.add(user)
        await db_session.flush()

        identity = await connector.handle_callback(
            callback_url="",
            db=db_session,
            email="carol@example.com",
            password=password,
        )

        assert identity.groups == []

    @pytest.mark.asyncio
    async def test_display_name_propagated(self, db_session, connector):
        """Display name from User record is carried into the identity."""
        password = "display-name-test-pass!"
        user = User(
            email="display@example.com",
            display_name="Dr. Display Name",
            password_hash=hash_password(password),
            is_active=True,
        )
        db_session.add(user)
        await db_session.flush()

        identity = await connector.handle_callback(
            callback_url="",
            db=db_session,
            email="display@example.com",
            password=password,
        )

        assert identity.display_name == "Dr. Display Name"

    @pytest.mark.asyncio
    async def test_none_display_name(self, db_session, connector):
        """User with no display_name returns None in identity."""
        password = "no-display-name-pass!"
        user = User(
            email="noname@example.com",
            display_name=None,
            password_hash=hash_password(password),
            is_active=True,
        )
        db_session.add(user)
        await db_session.flush()

        identity = await connector.handle_callback(
            callback_url="",
            db=db_session,
            email="noname@example.com",
            password=password,
        )

        assert identity.display_name is None
