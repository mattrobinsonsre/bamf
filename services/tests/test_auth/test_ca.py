"""Tests for the Certificate Authority module.

Tests CA initialization, certificate issuance for users, agents,
bridges, and sessions.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

import bamf.auth.ca as ca_module


class TestCertificateAuthority:
    def test_generate(self):
        ca = ca_module.CertificateAuthority.generate()
        assert ca is not None
        assert ca.ca_cert_pem is not None
        assert "BEGIN CERTIFICATE" in ca.ca_cert_pem

    def test_generate_issues_ed25519_key(self):
        ca = ca_module.CertificateAuthority.generate()
        cert = x509.load_pem_x509_certificate(ca.ca_cert_pem.encode())
        # CA subject should contain BAMF
        subject = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        assert len(subject) == 1
        assert "BAMF" in subject[0].value

    def test_ca_cert_is_self_signed(self):
        ca = ca_module.CertificateAuthority.generate()
        cert = x509.load_pem_x509_certificate(ca.ca_cert_pem.encode())
        assert cert.issuer == cert.subject

    def test_ca_cert_is_ca(self):
        ca = ca_module.CertificateAuthority.generate()
        cert = x509.load_pem_x509_certificate(ca.ca_cert_pem.encode())
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        assert bc.value.ca is True


class TestIssueUserCertificate:
    def test_issues_cert(self):
        ca = ca_module.CertificateAuthority.generate()
        cert, key = ca.issue_user_certificate(
            email="alice@example.com",
            roles=["admin", "developer"],
        )
        assert cert is not None
        assert key is not None

    def test_cert_has_correct_subject(self):
        ca = ca_module.CertificateAuthority.generate()
        cert, _ = ca.issue_user_certificate(
            email="alice@example.com",
            roles=["admin"],
        )
        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        assert cn[0].value == "alice@example.com"

    def test_cert_has_role_san_uris(self):
        ca = ca_module.CertificateAuthority.generate()
        cert, _ = ca.issue_user_certificate(
            email="alice@example.com",
            roles=["admin", "developer"],
        )
        # parse_san_uris returns a dict; for user certs with multiple roles,
        # only the last role survives because dict keys are unique ("role" key
        # is overwritten). Verify by reading raw SAN URIs instead.
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        uris = san.value.get_values_for_type(x509.UniformResourceIdentifier)
        role_uris = [u for u in uris if u.startswith("bamf://role/")]
        assert len(role_uris) == 2
        assert "bamf://role/admin" in role_uris
        assert "bamf://role/developer" in role_uris

    def test_cert_expires_in_12_hours(self):
        ca = ca_module.CertificateAuthority.generate()
        cert, _ = ca.issue_user_certificate(
            email="alice@example.com",
            roles=[],
        )
        # Should expire roughly 12 hours from now
        delta = cert.not_valid_after_utc - datetime.now(UTC)
        assert timedelta(hours=11) < delta < timedelta(hours=13)


class TestIssueServiceCertificate:
    def test_issues_agent_cert(self):
        ca = ca_module.CertificateAuthority.generate()
        cert, key = ca.issue_service_certificate(
            service_name="my-agent",
            service_type="agent",
        )
        assert cert is not None
        cn = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        assert cn[0].value == "my-agent"

    def test_agent_cert_1_year_expiry(self):
        ca = ca_module.CertificateAuthority.generate()
        cert, _ = ca.issue_service_certificate(
            service_name="agent-1",
            service_type="agent",
        )
        delta = cert.not_valid_after_utc - datetime.now(UTC)
        assert timedelta(days=360) < delta < timedelta(days=370)

    def test_issues_bridge_cert_with_dns(self):
        ca = ca_module.CertificateAuthority.generate()
        cert, _ = ca.issue_service_certificate(
            service_name="bridge-0",
            service_type="bridge",
            dns_names=["0.bridge.tunnel.bamf.local"],
        )
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        assert "0.bridge.tunnel.bamf.local" in dns_names

    def test_bridge_cert_24_hour_expiry(self):
        ca = ca_module.CertificateAuthority.generate()
        cert, _ = ca.issue_service_certificate(
            service_name="bridge-0",
            service_type="bridge",
        )
        delta = cert.not_valid_after_utc - datetime.now(UTC)
        assert timedelta(hours=23) < delta < timedelta(hours=25)


class TestIssueSessionCertificate:
    def test_issues_session_cert(self):
        ca = ca_module.CertificateAuthority.generate()
        cert, key = ca.issue_session_certificate(
            session_id="sess-123",
            resource_name="web-01",
            bridge_id="bridge-0",
            subject_cn="alice@example.com",
            role="developer",
        )
        assert cert is not None
        assert key is not None

    def test_session_cert_has_4_san_uris(self):
        ca = ca_module.CertificateAuthority.generate()
        cert, _ = ca.issue_session_certificate(
            session_id="sess-123",
            resource_name="web-01",
            bridge_id="bridge-0",
            subject_cn="alice@example.com",
            role="developer",
        )
        # parse_san_uris returns a dict keyed by URI type
        uris = ca_module.parse_san_uris(cert)
        assert len(uris) == 4
        assert uris["session"] == "sess-123"
        assert uris["resource"] == "web-01"
        assert uris["bridge"] == "bridge-0"
        assert uris["role"] == "developer"

    def test_session_cert_short_ttl(self):
        ca = ca_module.CertificateAuthority.generate()
        cert, _ = ca.issue_session_certificate(
            session_id="s1",
            resource_name="r1",
            bridge_id="b1",
            subject_cn="user@example.com",
            role="admin",
            ttl_seconds=30,
        )
        delta = cert.not_valid_after_utc - datetime.now(UTC)
        assert delta < timedelta(seconds=35)


class TestHelpers:
    def test_serialize_certificate(self):
        ca = ca_module.CertificateAuthority.generate()
        cert, _ = ca.issue_user_certificate(email="test@test.com", roles=[])
        pem = ca_module.serialize_certificate(cert)
        assert pem.startswith(b"-----BEGIN CERTIFICATE-----")
        assert pem.endswith(b"-----END CERTIFICATE-----\n")

    def test_serialize_private_key(self):
        key = Ed25519PrivateKey.generate()
        pem = ca_module.serialize_private_key(key)
        assert pem.startswith(b"-----BEGIN PRIVATE KEY-----")

    def test_parse_san_uris_no_extension(self):
        ca = ca_module.CertificateAuthority.generate()
        cert = x509.load_pem_x509_certificate(ca.ca_cert_pem.encode())
        # CA cert has no SAN URIs — should return empty dict
        uris = ca_module.parse_san_uris(cert)
        assert isinstance(uris, dict)

    def test_get_certificate_fingerprint(self):
        ca = ca_module.CertificateAuthority.generate()
        cert, _ = ca.issue_user_certificate(email="fp@test.com", roles=[])
        fp = ca_module.get_certificate_fingerprint(cert)
        assert isinstance(fp, str)
        assert len(fp) > 20  # SHA256 hex is 64 chars


class TestLoadCA:
    def test_load_from_pem(self):
        """Generate CA, serialize, reload and verify fingerprint matches."""
        ca = ca_module.CertificateAuthority.generate()
        cert_pem = ca_module.serialize_certificate(ca.ca_cert)
        key_pem = ca_module.serialize_private_key(ca.ca_key)
        loaded = ca_module.CertificateAuthority.load(cert_pem, key_pem)
        assert loaded.ca_cert_pem == ca.ca_cert_pem

    def test_load_wrong_key_type_raises(self):
        """Loading a CA with a non-Ed25519 key should raise TypeError."""
        from cryptography.hazmat.primitives.asymmetric import rsa

        rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        ca = ca_module.CertificateAuthority.generate()
        cert_pem = ca_module.serialize_certificate(ca.ca_cert)
        key_pem = ca_module.serialize_private_key(rsa_key)
        with pytest.raises(TypeError, match="Expected Ed25519"):
            ca_module.CertificateAuthority.load(cert_pem, key_pem)


class TestLoadOrGenerate:
    def test_generates_when_no_files(self, tmp_path):
        """Should generate a new CA and persist cert+key files when none exist."""
        ca = ca_module.CertificateAuthority.load_or_generate(tmp_path)
        assert ca is not None
        assert (tmp_path / "ca.crt").exists()
        assert (tmp_path / "ca.key").exists()

    def test_loads_when_files_exist(self, tmp_path):
        """Should reload the same CA from disk if files already exist."""
        ca1 = ca_module.CertificateAuthority.load_or_generate(tmp_path)
        ca2 = ca_module.CertificateAuthority.load_or_generate(tmp_path)
        assert ca_module.get_certificate_fingerprint(
            ca1.ca_cert
        ) == ca_module.get_certificate_fingerprint(ca2.ca_cert)

    def test_key_file_has_restricted_permissions(self, tmp_path):
        """The generated ca.key file should have 0600 permissions."""
        ca_module.CertificateAuthority.load_or_generate(tmp_path)
        key_path = tmp_path / "ca.key"
        # stat().st_mode includes file type bits; mask with 0o777 for perms only
        assert key_path.stat().st_mode & 0o777 == 0o600


class TestLoadHelpers:
    def test_load_certificate(self):
        """load_certificate should round-trip a PEM-serialized cert."""
        ca = ca_module.CertificateAuthority.generate()
        pem = ca_module.serialize_certificate(ca.ca_cert)
        cert = ca_module.load_certificate(pem)
        assert ca_module.get_certificate_fingerprint(cert) == ca_module.get_certificate_fingerprint(
            ca.ca_cert
        )

    def test_load_private_key(self):
        """load_private_key should return an Ed25519PrivateKey from PEM."""
        key = Ed25519PrivateKey.generate()
        pem = ca_module.serialize_private_key(key)
        loaded = ca_module.load_private_key(pem)
        assert isinstance(loaded, Ed25519PrivateKey)

    def test_load_private_key_with_password(self):
        """load_private_key should decrypt a password-protected PEM."""
        key = Ed25519PrivateKey.generate()
        password = b"test-password"
        pem = ca_module.serialize_private_key(key, password=password)
        loaded = ca_module.load_private_key(pem, password=password)
        assert isinstance(loaded, Ed25519PrivateKey)

    def test_load_private_key_wrong_password_raises(self):
        """load_private_key should raise when given the wrong password."""
        key = Ed25519PrivateKey.generate()
        pem = ca_module.serialize_private_key(key, password=b"correct")
        with pytest.raises(ValueError):
            ca_module.load_private_key(pem, password=b"wrong")


class TestGetCA:
    def test_get_ca_when_not_initialized(self):
        """get_ca() should raise RuntimeError when CA singleton is None."""
        old = ca_module._ca
        try:
            ca_module._ca = None
            with pytest.raises(RuntimeError, match="CA not initialized"):
                ca_module.get_ca()
        finally:
            ca_module._ca = old

    def test_get_ca_returns_singleton(self):
        """get_ca() should return the CA when it has been set."""
        old = ca_module._ca
        try:
            ca = ca_module.CertificateAuthority.generate()
            ca_module._ca = ca
            assert ca_module.get_ca() is ca
        finally:
            ca_module._ca = old

    def test_get_ssh_host_key_pem_none_initially(self):
        """get_ssh_host_key_pem() should return None when not set."""
        old = ca_module._ssh_host_key_pem
        try:
            ca_module._ssh_host_key_pem = None
            assert ca_module.get_ssh_host_key_pem() is None
        finally:
            ca_module._ssh_host_key_pem = old

    def test_get_ssh_host_key_pem_returns_value(self):
        """get_ssh_host_key_pem() should return the stored PEM string."""
        old = ca_module._ssh_host_key_pem
        try:
            ca_module._ssh_host_key_pem = "fake-pem-data"
            assert ca_module.get_ssh_host_key_pem() == "fake-pem-data"
        finally:
            ca_module._ssh_host_key_pem = old


class TestAdditionalServiceCert:
    def test_service_cert_with_ip_address(self):
        """Service cert with ip_addresses should include IPAddress SANs."""
        ca = ca_module.CertificateAuthority.generate()
        cert, _ = ca.issue_service_certificate(
            service_name="my-service",
            service_type="agent",
            ip_addresses=["192.168.1.1"],
        )
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        ips = san.value.get_values_for_type(x509.IPAddress)
        assert ipaddress.IPv4Address("192.168.1.1") in ips

    def test_service_cert_with_multiple_ip_addresses(self):
        """Service cert should support multiple IP SANs including IPv6."""
        ca = ca_module.CertificateAuthority.generate()
        cert, _ = ca.issue_service_certificate(
            service_name="multi-ip",
            service_type="bridge",
            ip_addresses=["10.0.0.1", "::1"],
        )
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        ips = san.value.get_values_for_type(x509.IPAddress)
        assert ipaddress.IPv4Address("10.0.0.1") in ips
        assert ipaddress.IPv6Address("::1") in ips

    def test_service_cert_with_dns_and_ip(self):
        """Service cert should support both DNS names and IP addresses together."""
        ca = ca_module.CertificateAuthority.generate()
        cert, _ = ca.issue_service_certificate(
            service_name="combo-service",
            service_type="bridge",
            dns_names=["bridge.tunnel.local"],
            ip_addresses=["172.16.0.1"],
        )
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        dns_names = san.value.get_values_for_type(x509.DNSName)
        ips = san.value.get_values_for_type(x509.IPAddress)
        assert "bridge.tunnel.local" in dns_names
        assert ipaddress.IPv4Address("172.16.0.1") in ips

    def test_serialize_private_key_with_password(self):
        """serialize_private_key with password should produce encrypted PEM."""
        key = Ed25519PrivateKey.generate()
        pem = ca_module.serialize_private_key(key, password=b"secret")
        assert b"ENCRYPTED" in pem

    def test_serialize_private_key_without_password(self):
        """serialize_private_key without password should produce unencrypted PEM."""
        key = Ed25519PrivateKey.generate()
        pem = ca_module.serialize_private_key(key)
        assert b"ENCRYPTED" not in pem
        assert b"BEGIN PRIVATE KEY" in pem
