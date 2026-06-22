# SPDX-License-Identifier: Apache-2.0
"""Self-signed TLS certificate generation for first-run HTTPS.

When the operator hasn't supplied their own cert (`MCP_TLS_CERT` /
`MCP_TLS_KEY`) and hasn't disabled TLS (`MCP_TLS_DISABLE=1`), the
server generates a self-signed certificate on first start so HTTPS is
on by default. The cert and key live in the persistent data directory
(`/data/cert.pem` and `/data/key.pem` by default), so subsequent
restarts reuse them.

The auto-generated cert is valid for ~2 years and includes
`localhost`, `127.0.0.1`, and `::1` in the Subject Alternative Name.
Operators who reach the server by hostname or external IP should
either set `MCP_TLS_HOSTNAME` (comma-separated list of additional
hostnames or IPs to add to the SAN — regenerates the cert if it
doesn't already cover them) or replace `cert.pem` / `key.pem` with a
CA-signed cert.

The cryptography library used here is already a runtime dependency
(it powers Fernet config encryption), so no extra packages are added.
"""

from __future__ import annotations

import ipaddress
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

CERT_FILENAME = "cert.pem"
KEY_FILENAME = "key.pem"


def _build_san(extra_names: list[str]) -> x509.SubjectAlternativeName:
    """Build a SubjectAlternativeName covering localhost + extras.

    Extras may be hostnames (added as DNS names) or IP addresses
    (added as IP entries). Anything that fails IP parsing is treated
    as a DNS name.
    """
    sans: list[x509.GeneralName] = [
        x509.DNSName("localhost"),
        x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
        x509.IPAddress(ipaddress.ip_address("::1")),
    ]
    seen = {"localhost", "127.0.0.1", "::1"}
    for raw in extra_names:
        name = (raw or "").strip()
        if not name or name in seen:
            continue
        seen.add(name)
        try:
            sans.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            sans.append(x509.DNSName(name))
    return x509.SubjectAlternativeName(sans)


def _cert_covers(cert_path: Path, required_names: list[str]) -> bool:
    """Return True if the existing cert's SAN already covers every
    required name. Used to decide whether to regenerate when
    MCP_TLS_HOSTNAME changes."""
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except Exception:
        return False
    have: set[str] = set()
    for name in san_ext.value:
        if isinstance(name, x509.DNSName):
            have.add(name.value)
        elif isinstance(name, x509.IPAddress):
            have.add(str(name.value))
    for required in required_names:
        n = (required or "").strip()
        if n and n not in have:
            return False
    return True


def _generate(cert_path: Path, key_path: Path, sans: x509.SubjectAlternativeName) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "tenable-ot-mcp")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(minutes=5))
        .not_valid_after(datetime.now(UTC) + timedelta(days=825))
        .add_extension(sans, critical=False)
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
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    os.chmod(cert_path, 0o644)
    key_path.write_bytes(
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )
    os.chmod(key_path, 0o600)


def ensure_self_signed_cert(
    data_dir: Path,
    extra_hostnames: list[str] | None = None,
) -> tuple[Path, Path]:
    """Return (cert_path, key_path) for HTTPS, generating a self-signed
    cert at first start.

    Behavior:
      - If both files exist AND their SAN already covers every entry
        in `extra_hostnames`, reuse them.
      - Otherwise generate a fresh keypair + cert and overwrite.

    The cert lives in `data_dir`, which the container's `mcp` user
    (UID 1000) owns — so generation succeeds without root.
    """
    cert_path = data_dir / CERT_FILENAME
    key_path = data_dir / KEY_FILENAME
    extras = list(extra_hostnames or [])

    if cert_path.is_file() and key_path.is_file() and _cert_covers(cert_path, extras):
        return cert_path, key_path

    sans = _build_san(extras)
    _generate(cert_path, key_path, sans)
    return cert_path, key_path
