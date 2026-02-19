"""mTLS helper to dial bridge from the API server (Python).

Used by the terminal WebSocket relay to establish a framed connection to
the bridge for web-ssh and web-db sessions.
"""

from __future__ import annotations

import asyncio
import ssl
import tempfile
from pathlib import Path

from bamf.logging_config import get_logger

logger = get_logger(__name__)


async def dial_bridge(
    bridge_host: str,
    bridge_port: int,
    session_cert_pem: str,
    session_key_pem: str,
    ca_cert_pem: str,
    session_id: str,
    resource_type: str,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """Open an mTLS connection to the bridge and send the session header.

    The bridge expects a text-line header identifying the session before
    entering the frame protocol:

        {session_id}\\ntype={resource_type}\\n

    Returns (reader, writer) for the framed connection.
    """
    # Write cert/key/CA to temp files for ssl.SSLContext.
    # Use a secure tmpdir with restrictive permissions.
    tmpdir = tempfile.mkdtemp(prefix="bamf-tls-")
    cert_path = Path(tmpdir) / "cert.pem"
    key_path = Path(tmpdir) / "key.pem"
    ca_path = Path(tmpdir) / "ca.pem"

    try:
        cert_path.write_text(session_cert_pem)
        cert_path.chmod(0o600)
        key_path.write_text(session_key_pem)
        key_path.chmod(0o600)
        ca_path.write_text(ca_cert_pem)
        ca_path.chmod(0o600)

        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.load_cert_chain(str(cert_path), str(key_path))
        ctx.load_verify_locations(str(ca_path))
        # Bridge uses BAMF CA-issued certs — verify against our CA
        ctx.check_hostname = False  # bridge cert CN may not match hostname
        ctx.verify_mode = ssl.CERT_REQUIRED

        reader, writer = await asyncio.open_connection(bridge_host, bridge_port, ssl=ctx)

        # Send session header
        header = f"{session_id}\ntype={resource_type}\n"
        writer.write(header.encode())
        await writer.drain()

        logger.info(
            "Connected to bridge",
            bridge_host=bridge_host,
            bridge_port=bridge_port,
            session_id=session_id,
            resource_type=resource_type,
        )

        return reader, writer

    finally:
        # Clean up temp files
        for p in (cert_path, key_path, ca_path):
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass
        try:
            Path(tmpdir).rmdir()
        except OSError:
            pass
