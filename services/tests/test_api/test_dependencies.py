"""Tests for API authentication and authorization dependencies.

Tests _validate_client_cert (certificate validation against BAMF CA),
get_current_session (session token lookup), require_admin, and
require_admin_or_audit role-checking dependencies.
"""

from __future__ import annotations

import base64
import datetime
from unittest.mock import AsyncMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.x509.oid import NameOID
from fastapi import HTTPException

from bamf.api.dependencies import (
    _validate_client_cert,
    get_current_session,
    require_admin,
    require_admin_or_audit,
)
from bamf.auth.ca import CertificateAuthority, serialize_certificate
from bamf.auth.sessions import Session

# ── Helpers ──────────────────────────────────────────────────────────────

_NOW = datetime.datetime.now(datetime.UTC).isoformat()


def _encode_cert(cert: x509.Certificate) -> str:
    """Base64-encode a certificate's PEM bytes (as the header value)."""
    return base64.b64encode(serialize_certificate(cert)).decode()


def _make_session(**overrides) -> Session:
    """Create a Session with sensible defaults, overridable per field."""
    defaults = {
        "email": "user@example.com",
        "display_name": "Test User",
        "roles": [],
        "provider_name": "local",
        "created_at": _NOW,
        "expires_at": _NOW,
        "last_active_at": _NOW,
    }
    defaults.update(overrides)
    return Session(**defaults)


def _issue_expired_cert(ca: CertificateAuthority) -> x509.Certificate:
    """Issue a service cert that is already expired."""
    private_key = Ed25519PrivateKey.generate()
    now = datetime.datetime.now(datetime.UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "expired-agent")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca.ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(hours=2))
        .not_valid_after(now - datetime.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca.ca_key, None)
    )
    return cert


def _issue_not_yet_valid_cert(ca: CertificateAuthority) -> x509.Certificate:
    """Issue a service cert whose not_valid_before is in the future."""
    private_key = Ed25519PrivateKey.generate()
    now = datetime.datetime.now(datetime.UTC)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "future-agent")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca.ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now + datetime.timedelta(hours=1))
        .not_valid_after(now + datetime.timedelta(hours=2))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca.ca_key, None)
    )
    return cert


def _issue_cert_no_cn(ca: CertificateAuthority) -> x509.Certificate:
    """Issue a cert signed by the CA that has no CN in its subject."""
    private_key = Ed25519PrivateKey.generate()
    now = datetime.datetime.now(datetime.UTC)
    # Subject with only Organization, no CN
    subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BAMF")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca.ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(ca.ca_key, None)
    )
    return cert


# ── _validate_client_cert tests ──────────────────────────────────────────


class TestValidateClientCert:
    """Tests for _validate_client_cert(header_value, entity_type)."""

    def setup_method(self):
        self.ca = CertificateAuthority.generate()

    def test_missing_header_returns_401(self):
        with patch("bamf.api.dependencies.get_ca", return_value=self.ca):
            with pytest.raises(HTTPException) as exc_info:
                _validate_client_cert(None, "agent")
            assert exc_info.value.status_code == 401
            assert "Missing X-Bamf-Client-Cert header" in exc_info.value.detail

    def test_empty_header_returns_401(self):
        with patch("bamf.api.dependencies.get_ca", return_value=self.ca):
            with pytest.raises(HTTPException) as exc_info:
                _validate_client_cert("", "agent")
            assert exc_info.value.status_code == 401
            assert "Missing X-Bamf-Client-Cert header" in exc_info.value.detail

    def test_invalid_base64_returns_401(self):
        with patch("bamf.api.dependencies.get_ca", return_value=self.ca):
            with pytest.raises(HTTPException) as exc_info:
                _validate_client_cert("not-valid-base64!!!", "agent")
            assert exc_info.value.status_code == 401
            assert "Invalid certificate format" in exc_info.value.detail

    def test_valid_base64_but_not_pem_returns_401(self):
        garbage = base64.b64encode(b"this is not a certificate").decode()
        with patch("bamf.api.dependencies.get_ca", return_value=self.ca):
            with pytest.raises(HTTPException) as exc_info:
                _validate_client_cert(garbage, "bridge")
            assert exc_info.value.status_code == 401
            assert "Invalid certificate format" in exc_info.value.detail

    def test_cert_not_signed_by_ca_returns_401(self):
        # Issue cert from a different CA
        other_ca = CertificateAuthority.generate()
        cert, _ = other_ca.issue_service_certificate("rogue-agent", "agent")
        header = _encode_cert(cert)

        with patch("bamf.api.dependencies.get_ca", return_value=self.ca):
            with pytest.raises(HTTPException) as exc_info:
                _validate_client_cert(header, "agent")
            assert exc_info.value.status_code == 401
            assert "Certificate not signed by BAMF CA" in exc_info.value.detail

    def test_expired_cert_returns_401(self):
        cert = _issue_expired_cert(self.ca)
        header = _encode_cert(cert)

        with patch("bamf.api.dependencies.get_ca", return_value=self.ca):
            with pytest.raises(HTTPException) as exc_info:
                _validate_client_cert(header, "agent")
            assert exc_info.value.status_code == 401
            assert "Certificate has expired" in exc_info.value.detail

    def test_not_yet_valid_cert_returns_401(self):
        cert = _issue_not_yet_valid_cert(self.ca)
        header = _encode_cert(cert)

        with patch("bamf.api.dependencies.get_ca", return_value=self.ca):
            with pytest.raises(HTTPException) as exc_info:
                _validate_client_cert(header, "agent")
            assert exc_info.value.status_code == 401
            assert "Certificate not yet valid" in exc_info.value.detail

    def test_cert_with_no_cn_returns_401(self):
        cert = _issue_cert_no_cn(self.ca)
        header = _encode_cert(cert)

        with patch("bamf.api.dependencies.get_ca", return_value=self.ca):
            with pytest.raises(HTTPException) as exc_info:
                _validate_client_cert(header, "agent")
            assert exc_info.value.status_code == 401
            assert "Certificate has no CN" in exc_info.value.detail

    def test_valid_cert_returns_certificate(self):
        cert, _ = self.ca.issue_service_certificate("valid-agent", "agent")
        header = _encode_cert(cert)

        with patch("bamf.api.dependencies.get_ca", return_value=self.ca):
            result = _validate_client_cert(header, "agent")
        assert isinstance(result, x509.Certificate)
        cn = result.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        assert cn[0].value == "valid-agent"


# ── get_current_session tests ────────────────────────────────────────────


class TestGetCurrentSession:
    """Tests for get_current_session(credentials)."""

    @pytest.mark.asyncio
    async def test_invalid_session_returns_401(self):
        creds = type("Creds", (), {"credentials": "bad-token"})()

        with patch("bamf.api.dependencies.get_session", new_callable=AsyncMock, return_value=None):
            with pytest.raises(HTTPException) as exc_info:
                await get_current_session(creds)
            assert exc_info.value.status_code == 401
            assert "Invalid or expired session" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_valid_session_returns_session(self):
        session = _make_session(email="alice@example.com", roles=["developer"])
        creds = type("Creds", (), {"credentials": "good-token"})()

        with (
            patch("bamf.api.dependencies.get_session", new_callable=AsyncMock, return_value=session),
            patch("bamf.api.dependencies._should_refresh_session", return_value=False),
        ):
            result = await get_current_session(creds)
        assert result.email == "alice@example.com"
        assert result.roles == ["developer"]


# ── require_admin tests ──────────────────────────────────────────────────


class TestRequireAdmin:
    """Tests for require_admin(session)."""

    @pytest.mark.asyncio
    async def test_non_admin_returns_403(self):
        session = _make_session(roles=["developer"])
        with pytest.raises(HTTPException) as exc_info:
            await require_admin(session)
        assert exc_info.value.status_code == 403
        assert "Admin access required" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_admin_returns_session(self):
        session = _make_session(roles=["admin"])
        result = await require_admin(session)
        assert result is session


# ── require_admin_or_audit tests ─────────────────────────────────────────


class TestRequireAdminOrAudit:
    """Tests for require_admin_or_audit(session)."""

    @pytest.mark.asyncio
    async def test_neither_role_returns_403(self):
        session = _make_session(roles=["developer"])
        with pytest.raises(HTTPException) as exc_info:
            await require_admin_or_audit(session)
        assert exc_info.value.status_code == 403
        assert "Admin or audit access required" in exc_info.value.detail

    @pytest.mark.asyncio
    async def test_admin_returns_session(self):
        session = _make_session(roles=["admin"])
        result = await require_admin_or_audit(session)
        assert result is session

    @pytest.mark.asyncio
    async def test_audit_returns_session(self):
        session = _make_session(roles=["audit"])
        result = await require_admin_or_audit(session)
        assert result is session
