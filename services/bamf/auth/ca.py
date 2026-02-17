"""Certificate Authority module for BAMF.

Handles generation of:
- CA certificate and key (Ed25519)
- Short-lived user identity certificates (12h default)
- Agent certificates (1 year default) — long-lived for VMs that may sleep for months
- Bridge certificates (24h default) — ephemeral pods renew on restart
- Per-tunnel session certificates with custom SAN URIs (30s default)
"""
# Certificate model: docs/admin/certificates.md

import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.x509.oid import NameOID
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from bamf.config import settings
from bamf.logging_config import get_logger

logger = get_logger(__name__)

# Module-level CA singleton, initialized in lifespan
_ca: "CertificateAuthority | None" = None

# Module-level SSH host key singleton (PEM string), for ssh-audit proxy
_ssh_host_key_pem: str | None = None

# Default CA data directory
CA_DATA_DIR = Path("/var/lib/bamf/ca")


class CertificateAuthority:
    """Certificate Authority for issuing short-lived certificates."""

    def __init__(
        self,
        ca_cert: x509.Certificate,
        ca_key: ed25519.Ed25519PrivateKey,
    ):
        self._ca_cert = ca_cert
        self._ca_key = ca_key

    @property
    def ca_cert(self) -> x509.Certificate:
        return self._ca_cert

    @property
    def ca_key(self) -> ed25519.Ed25519PrivateKey:
        return self._ca_key

    @property
    def ca_cert_pem(self) -> str:
        """Return the CA certificate as a PEM string."""
        return self._ca_cert.public_bytes(serialization.Encoding.PEM).decode()

    # ── CA Generation ────────────────────────────────────────────────────

    @classmethod
    def generate(
        cls,
        common_name: str = "BAMF Certificate Authority",
        validity_days: int = 3650,
    ) -> "CertificateAuthority":
        """Generate a new CA certificate and Ed25519 key pair."""
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, common_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BAMF"),
            ]
        )

        now = datetime.datetime.now(datetime.UTC)

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=validity_days))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_cert_sign=True,
                    crl_sign=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False,
            )
            .sign(private_key, None)  # Ed25519 doesn't use a hash algorithm
        )

        logger.info(
            "Generated new CA certificate",
            common_name=common_name,
            expires=cert.not_valid_after_utc.isoformat(),
        )

        return cls(ca_cert=cert, ca_key=private_key)

    @classmethod
    def load(cls, cert_pem: bytes, key_pem: bytes) -> "CertificateAuthority":
        """Load CA from PEM-encoded certificate and key."""
        cert = x509.load_pem_x509_certificate(cert_pem)
        key = serialization.load_pem_private_key(key_pem, password=None)
        if not isinstance(key, ed25519.Ed25519PrivateKey):
            raise TypeError(f"Expected Ed25519 private key, got {type(key).__name__}")
        return cls(ca_cert=cert, ca_key=key)

    @classmethod
    def load_or_generate(cls, data_dir: Path | None = None) -> "CertificateAuthority":
        """Load CA from disk if available, otherwise generate and persist."""
        data_dir = data_dir or CA_DATA_DIR
        cert_path = data_dir / "ca.crt"
        key_path = data_dir / "ca.key"

        if cert_path.exists() and key_path.exists():
            logger.info("Loading CA from disk", path=str(data_dir))
            return cls.load(cert_path.read_bytes(), key_path.read_bytes())

        logger.info("No existing CA found, generating new CA", path=str(data_dir))
        ca = cls.generate()

        # Persist to disk
        data_dir.mkdir(parents=True, exist_ok=True)
        cert_path.write_bytes(serialize_certificate(ca.ca_cert))
        key_path.write_bytes(serialize_private_key(ca.ca_key))
        # Restrict key file permissions
        key_path.chmod(0o600)

        return ca

    # ── Certificate Issuance ─────────────────────────────────────────────

    def issue_user_certificate(
        self,
        email: str,
        roles: list[str] | None = None,
        ttl_hours: int | None = None,
    ) -> tuple[x509.Certificate, ed25519.Ed25519PrivateKey]:
        """Issue a short-lived identity certificate for a user.

        Used for CLI → API authentication and as the basis for session certs.
        """
        if ttl_hours is None:
            ttl_hours = settings.certificates.user_ttl_hours

        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, email),
                x509.NameAttribute(NameOID.EMAIL_ADDRESS, email),
            ]
        )

        now = datetime.datetime.now(datetime.UTC)

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(hours=ttl_hours))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
        )

        # Embed roles in SAN as URIs: bamf://role/{role_name}
        san_entries: list[x509.GeneralName] = []
        if roles:
            for role in roles:
                san_entries.append(x509.UniformResourceIdentifier(f"bamf://role/{role}"))
        if san_entries:
            builder = builder.add_extension(
                x509.SubjectAlternativeName(san_entries),
                critical=False,
            )

        cert = builder.sign(self._ca_key, None)

        logger.info(
            "Issued user certificate",
            email=email,
            roles=roles,
            expires=cert.not_valid_after_utc.isoformat(),
        )

        return cert, private_key

    def issue_service_certificate(
        self,
        service_name: str,
        service_type: str = "agent",
        dns_names: list[str] | None = None,
        ip_addresses: list[str] | None = None,
        ttl_hours: int | None = None,
    ) -> tuple[x509.Certificate, ed25519.Ed25519PrivateKey]:
        """Issue a certificate for a service (agent or bridge).

        Args:
            service_name: Service identifier (agent name or bridge ID).
            service_type: "agent" or "bridge".
            dns_names: DNS names for TLS server validation.
            ip_addresses: IP addresses for TLS server validation.
            ttl_hours: Certificate lifetime (default: 1 year for agents, 24h for bridges).
        """
        if ttl_hours is None:
            if service_type == "agent":
                ttl_hours = settings.certificates.agent_ttl_hours
            else:
                ttl_hours = settings.certificates.bridge_ttl_hours

        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, service_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BAMF"),
            ]
        )

        now = datetime.datetime.now(datetime.UTC)

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(hours=ttl_hours))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=True,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
                        x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                    ]
                ),
                critical=False,
            )
        )

        # Build SAN entries
        san_entries: list[x509.GeneralName] = [
            x509.UniformResourceIdentifier(f"bamf://{service_type}/{service_name}"),
        ]
        if dns_names:
            for name in dns_names:
                san_entries.append(x509.DNSName(name))
        if ip_addresses:
            for ip in ip_addresses:
                san_entries.append(x509.IPAddress(ipaddress.ip_address(ip)))

        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        )

        cert = builder.sign(self._ca_key, None)

        logger.info(
            "Issued service certificate",
            service_name=service_name,
            service_type=service_type,
            dns_names=dns_names,
            expires=cert.not_valid_after_utc.isoformat(),
        )

        return cert, private_key

    def issue_session_certificate(
        self,
        session_id: str,
        resource_name: str,
        bridge_id: str,
        subject_cn: str,
        role: str = "client",
        ttl_seconds: int = 30,
    ) -> tuple[x509.Certificate, ed25519.Ed25519PrivateKey]:
        """Issue a per-tunnel session certificate.

        The cert IS the authorization. Bridge validates the chain against
        BAMF CA and reads SAN URIs to route the connection.

        SAN URIs encode:
            bamf://session/{session_id}     — pairs client + agent connections
            bamf://resource/{resource_name} — target resource
            bamf://bridge/{bridge_id}       — which bridge this is for
            bamf://role/{role}              — "client" or "agent" (for bridge matching)

        Args:
            session_id: Unique session identifier for pairing.
            resource_name: Target resource name.
            bridge_id: Assigned bridge identifier (cert only works on this bridge).
            subject_cn: CN for the cert (user email or agent name).
            role: "client" or "agent" — tells the bridge which side this is.
            ttl_seconds: Certificate lifetime in seconds (default 30s for setup).
        """
        private_key = ed25519.Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COMMON_NAME, subject_cn),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BAMF"),
            ]
        )

        now = datetime.datetime.now(datetime.UTC)

        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self._ca_cert.subject)
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(seconds=ttl_seconds))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    key_encipherment=False,
                    content_commitment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=False,
                    crl_sign=False,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .add_extension(
                x509.SubjectAlternativeName(
                    [
                        x509.UniformResourceIdentifier(f"bamf://session/{session_id}"),
                        x509.UniformResourceIdentifier(f"bamf://resource/{resource_name}"),
                        x509.UniformResourceIdentifier(f"bamf://bridge/{bridge_id}"),
                        x509.UniformResourceIdentifier(f"bamf://role/{role}"),
                    ]
                ),
                critical=False,
            )
        )

        cert = builder.sign(self._ca_key, None)

        logger.info(
            "Issued session certificate",
            session_id=session_id,
            resource=resource_name,
            bridge=bridge_id,
            subject=subject_cn,
            expires=cert.not_valid_after_utc.isoformat(),
        )

        return cert, private_key


# ── Serialization Helpers ────────────────────────────────────────────────


def serialize_certificate(cert: x509.Certificate) -> bytes:
    """Serialize certificate to PEM format."""
    return cert.public_bytes(serialization.Encoding.PEM)


def serialize_private_key(
    key: ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey,
    password: bytes | None = None,
) -> bytes:
    """Serialize private key to PEM format."""
    encryption: serialization.KeySerializationEncryption
    if password:
        encryption = serialization.BestAvailableEncryption(password)
    else:
        encryption = serialization.NoEncryption()

    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption,
    )


def load_certificate(pem_data: bytes) -> x509.Certificate:
    """Load certificate from PEM data."""
    return x509.load_pem_x509_certificate(pem_data)


def load_private_key(
    pem_data: bytes,
    password: bytes | None = None,
) -> ed25519.Ed25519PrivateKey | rsa.RSAPrivateKey:
    """Load private key from PEM data."""
    return serialization.load_pem_private_key(pem_data, password=password)


def get_certificate_fingerprint(cert: x509.Certificate) -> str:
    """Get SHA256 fingerprint of certificate."""
    return cert.fingerprint(hashes.SHA256()).hex()


def parse_san_uris(cert: x509.Certificate) -> dict[str, str]:
    """Extract bamf:// SAN URIs from a certificate.

    Returns a dict like:
        {"session": "abc-123", "resource": "my-server", "bridge": "bridge-1"}
    """
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return {}

    result: dict[str, str] = {}
    for uri in san.value.get_values_for_type(x509.UniformResourceIdentifier):
        if uri.startswith("bamf://"):
            # bamf://session/abc-123 → ("session", "abc-123")
            parts = uri[len("bamf://") :].split("/", 1)
            if len(parts) == 2:
                result[parts[0]] = parts[1]
    return result


# ── Lifecycle ────────────────────────────────────────────────────────────


async def init_ca(db: AsyncSession) -> CertificateAuthority:
    """Initialize the CA singleton from database, falling back to generate + persist.

    Startup sequence:
    1. Query certificate_authority table for existing CA
    2. If found: load cert + key from PEM columns, set singleton
    3. If not found: generate new CA, persist to DB, set singleton
    4. Also write to filesystem as cache (for components that read from disk)
    5. Ensure SSH host key exists in DB record (for ssh-audit bridge proxy)
    """
    from bamf.db.models import CertificateAuthority as CertificateAuthorityModel

    global _ca  # noqa: PLW0603
    global _ssh_host_key_pem  # noqa: PLW0603

    # Try loading from database first
    result = await db.execute(
        select(CertificateAuthorityModel)
        .order_by(CertificateAuthorityModel.created_at.desc())
        .limit(1)
    )
    ca_record = result.scalar_one_or_none()

    if ca_record:
        # Load existing CA from database
        ca = CertificateAuthority.load(
            ca_record.ca_cert.encode(),
            ca_record.ca_key_encrypted.encode(),
        )
        logger.info(
            "Loaded CA from database",
            fingerprint=get_certificate_fingerprint(ca.ca_cert)[:16],
        )
    else:
        # Generate new CA
        ca = CertificateAuthority.generate()

        # Persist to database
        cert_pem = serialize_certificate(ca.ca_cert).decode()
        key_pem = serialize_private_key(ca.ca_key).decode()

        ca_record = CertificateAuthorityModel(
            ca_cert=cert_pem,
            ca_key_encrypted=key_pem,
        )
        db.add(ca_record)
        await db.commit()

        logger.info(
            "Generated and stored new CA in database",
            fingerprint=get_certificate_fingerprint(ca.ca_cert)[:16],
        )

    # Ensure SSH host key exists (for ssh-audit bridge proxy).
    # Generated once per deployment, shared by all bridge pods.
    if ca_record.ssh_host_key:
        _ssh_host_key_pem = ca_record.ssh_host_key
        logger.info("Loaded SSH host key from database")
    else:
        ssh_key = ed25519.Ed25519PrivateKey.generate()
        _ssh_host_key_pem = ssh_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.OpenSSH,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()
        ca_record.ssh_host_key = _ssh_host_key_pem
        await db.commit()
        logger.info("Generated and stored SSH host key in database")

    # Write to filesystem as cache
    data_dir = settings.ca_data_dir or CA_DATA_DIR
    try:
        data_dir.mkdir(parents=True, exist_ok=True)
        cert_path = data_dir / "ca.crt"
        key_path = data_dir / "ca.key"
        cert_path.write_bytes(serialize_certificate(ca.ca_cert))
        key_path.write_bytes(serialize_private_key(ca.ca_key))
        key_path.chmod(0o600)
    except OSError as e:
        logger.warning("Failed to write CA cache to filesystem", error=str(e))

    _ca = ca
    return _ca


def get_ca() -> CertificateAuthority:
    """Return the CA singleton. Raises if not initialized."""
    if _ca is None:
        raise RuntimeError("CA not initialized — call init_ca() first")
    return _ca


def get_ssh_host_key_pem() -> str | None:
    """Return the SSH host key PEM string, or None if not initialized."""
    return _ssh_host_key_pem
