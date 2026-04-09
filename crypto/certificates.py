"""
Certificate management for FATCA Crypto Utility.

Handles loading of X.509 certificates from .p12 (PKCS#12) and .pem files,
GIIN extraction from certificate subject fields, and validation.
"""

import re
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives.asymmetric.types import PrivateKeyTypes
from cryptography.x509 import Certificate

from utils.errors import (
    CertificateError,
    CertificateNotFoundError,
    InvalidGIINError,
)
from utils.validators import (
    validate_certificate_expiry,
    validate_file_exists,
    validate_giin,
)

# ---------------------------------------------------------------------------
# GIIN extraction patterns
# ---------------------------------------------------------------------------
# GIIN might appear in OU, O, or serialNumber fields of the certificate Subject
GIIN_EXTRACT_PATTERN = re.compile(
    r"[A-Z0-9]{6}\.[A-Z0-9]{5}\.[A-Z]{2}\.\d{3}"
)


@dataclass(frozen=True)
class CertificateBundle:
    """
    Holds all materials extracted from a certificate file.

    Attributes:
        private_key: The RSA/EC private key (None if loading public cert only).
        certificate: The X.509 certificate.
        chain: Additional certificates in the chain.
        giin: Extracted or manually provided GIIN.
        not_before: Certificate validity start.
        not_after: Certificate validity end.
        subject: Certificate subject as string.
    """
    private_key: PrivateKeyTypes | None
    certificate: Certificate
    chain: list[Certificate]
    giin: str | None
    not_before: datetime
    not_after: datetime
    subject: str


def load_certificate(
    path: str | Path,
    giin_override: str | None = None,
    key_path: str | Path | None = None,
    password: str | bytes | None = None,
) -> CertificateBundle:
    """
    Load an X.509 certificate from a .p12 or .pem file.

    Automatically detects the file format by extension.

    Args:
        path: Path to the certificate file (.p12, .pfx, .pem, .crt).
        giin_override: If provided, skip GIIN extraction and use this value.
        key_path: Optional path to a separate private key file (.key or .pem).
                  Use this when the certificate and key are in separate files.
        password: Optional password for encrypted .p12 or PEM files.

    Returns:
        CertificateBundle with all extracted materials.

    Raises:
        CertificateNotFoundError: If the file doesn't exist.
        CertificateError: If parsing fails.
    """
    cert_path = validate_file_exists(path, label="Certificate file")
    ext = cert_path.suffix.lower()

    key_file = None
    if key_path:
        key_file = validate_file_exists(key_path, label="Private key file")

    if ext in (".p12", ".pfx"):
        return _load_pkcs12(cert_path, giin_override, password)
    elif ext in (".pem", ".crt", ".cer", ".key"):
        return _load_pem(cert_path, giin_override, key_file, password)
    else:
        raise CertificateError(
            f"Unsupported certificate format: '{ext}'. "
            f"Supported: .p12, .pfx, .pem, .crt, .cer"
        )


def load_public_certificate(path: str | Path) -> CertificateBundle:
    """
    Load a public-only certificate (no private key required).

    Used for loading the IRS public certificate for encryption.

    Args:
        path: Path to the public certificate file (.pem, .crt, .cer).

    Returns:
        CertificateBundle with private_key=None.
    """
    cert_path = validate_file_exists(path, label="Public certificate file")
    cert_data = cert_path.read_bytes()

    try:
        cert = x509.load_pem_x509_certificate(cert_data)
    except Exception:
        try:
            cert = x509.load_der_x509_certificate(cert_data)
        except Exception as e:
            raise CertificateError(
                f"Cannot parse public certificate: {e}"
            ) from e

    return CertificateBundle(
        private_key=None,
        certificate=cert,
        chain=[],
        giin=None,
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        subject=cert.subject.rfc4514_string(),
    )


# ---------------------------------------------------------------------------
# Private loaders
# ---------------------------------------------------------------------------

def _to_password_bytes(password: str | bytes | None) -> bytes | None:
    """Convert a password to bytes, or return None if no password."""
    if password is None:
        return None
    if isinstance(password, str):
        return password.encode("utf-8")
    return password


def _load_pkcs12(
    path: Path,
    giin_override: str | None,
    password: str | bytes | None = None,
) -> CertificateBundle:
    """Load from PKCS#12 (.p12 / .pfx) format."""
    from cryptography.hazmat.primitives.serialization import pkcs12

    raw = path.read_bytes()
    pwd_bytes = _to_password_bytes(password)
    try:
        private_key, certificate, chain = pkcs12.load_key_and_certificates(
            raw, pwd_bytes
        )
    except Exception as e:
        raise CertificateError(
            f"Failed to load PKCS#12 file '{path.name}': {e}. "
            f"If the file is password-protected, use --password."
        ) from e

    if certificate is None:
        raise CertificateError(
            f"PKCS#12 file '{path.name}' contains no certificate."
        )

    giin = giin_override or _extract_giin(certificate)
    if giin:
        giin = validate_giin(giin)

    return CertificateBundle(
        private_key=private_key,
        certificate=certificate,
        chain=list(chain) if chain else [],
        giin=giin,
        not_before=certificate.not_valid_before_utc,
        not_after=certificate.not_valid_after_utc,
        subject=certificate.subject.rfc4514_string(),
    )


def _load_pem(
    path: Path,
    giin_override: str | None,
    key_file: Path | None = None,
    password: str | bytes | None = None,
) -> CertificateBundle:
    """
    Load from PEM format.

    A .pem file can contain both cert and private key, or just one.
    If key_file is provided, the private key is loaded from that file.
    """
    raw = path.read_bytes()
    private_key = None
    certificate = None
    chain: list[Certificate] = []

    pwd_bytes = _to_password_bytes(password)

    # --- Try loading private key ---
    # If a separate key file is provided, load from there
    key_data = key_file.read_bytes() if key_file else raw
    try:
        private_key = serialization.load_pem_private_key(key_data, password=pwd_bytes)
    except (ValueError, TypeError, UnsupportedAlgorithm):
        pass  # No private key found
    except Exception:
        pass

    # --- Try loading certificate(s) ---
    # PEM files can contain multiple certs; the first is the main cert
    pem_certs = _extract_pem_certs(raw)
    for i, cert_bytes in enumerate(pem_certs):
        try:
            cert = x509.load_pem_x509_certificate(cert_bytes)
            if i == 0:
                certificate = cert
            else:
                chain.append(cert)
        except Exception:
            continue

    if certificate is None:
        raise CertificateError(
            f"No X.509 certificate found in PEM file '{path.name}'."
        )

    giin = giin_override or _extract_giin(certificate)
    if giin:
        giin = validate_giin(giin)

    return CertificateBundle(
        private_key=private_key,
        certificate=certificate,
        chain=chain,
        giin=giin,
        not_before=certificate.not_valid_before_utc,
        not_after=certificate.not_valid_after_utc,
        subject=certificate.subject.rfc4514_string(),
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_pem_certs(raw: bytes) -> list[bytes]:
    """Split a PEM file into individual certificate blocks."""
    certs = []
    begin = b"-----BEGIN CERTIFICATE-----"
    end = b"-----END CERTIFICATE-----"
    start = 0
    while True:
        idx = raw.find(begin, start)
        if idx == -1:
            break
        end_idx = raw.find(end, idx)
        if end_idx == -1:
            break
        certs.append(raw[idx: end_idx + len(end)])
        start = end_idx + len(end)
    return certs


def _extract_giin(cert: Certificate) -> str | None:
    """
    Attempt to extract GIIN from certificate Subject fields.

    The GIIN may appear in:
    - OU (Organizational Unit)
    - O  (Organization)
    - serialNumber
    - CN (Common Name)
    """
    subject = cert.subject
    # Check each attribute that might contain the GIIN
    for attr in subject:
        value = attr.value
        if isinstance(value, str):
            match = GIIN_EXTRACT_PATTERN.search(value.upper())
            if match:
                return match.group(0)

    # Also check Subject Alternative Names (if present)
    try:
        san = cert.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        )
        for name in san.value:
            if hasattr(name, "value"):
                val = str(name.value).upper()
                match = GIIN_EXTRACT_PATTERN.search(val)
                if match:
                    return match.group(0)
    except x509.ExtensionNotFound:
        pass

    return None
