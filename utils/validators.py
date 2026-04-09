"""
Validators for GIIN format, certificate expiry, and file checks.
"""

import re
from datetime import datetime, timezone
from pathlib import Path

from utils.errors import (
    CertificateExpiredError,
    CertificateNotFoundError,
    InvalidGIINError,
)

# ---------------------------------------------------------------------------
# GIIN validation
# Format: XXXXXX.XXXXX.XX.XXX  (6 alnum . 5 alnum . 2 alpha . 3 digits)
# Example: 98Q96B.00000.LE.250
# ---------------------------------------------------------------------------
GIIN_PATTERN = re.compile(
    r"^[A-Z0-9]{6}\.[A-Z0-9]{5}\.[A-Z]{2}\.\d{3}$"
)


def validate_giin(giin: str) -> str:
    """
    Validate a GIIN string against IRS format.

    Args:
        giin: The GIIN string to validate.

    Returns:
        The validated (stripped, uppercased) GIIN.

    Raises:
        InvalidGIINError: If format is invalid.
    """
    if not giin:
        raise InvalidGIINError("GIIN is empty or None.")

    giin = giin.strip().upper()

    if not GIIN_PATTERN.match(giin):
        raise InvalidGIINError(
            f"Invalid GIIN format: '{giin}'. "
            f"Expected format: XXXXXX.XXXXX.XX.XXX  "
            f"(e.g. 98Q96B.00000.LE.250)"
        )
    return giin


# ---------------------------------------------------------------------------
# Certificate expiry validation
# ---------------------------------------------------------------------------

def validate_certificate_expiry(not_after: datetime) -> None:
    """
    Check that a certificate has not expired.

    Args:
        not_after: The certificate's notAfter timestamp.

    Raises:
        CertificateExpiredError: If the certificate has expired.
    """
    now = datetime.now(timezone.utc)
    # Ensure not_after is timezone-aware
    if not_after.tzinfo is None:
        not_after = not_after.replace(tzinfo=timezone.utc)

    if now > not_after:
        raise CertificateExpiredError(
            f"Certificate expired on {not_after.isoformat()}. "
            f"Current time: {now.isoformat()}."
        )


# ---------------------------------------------------------------------------
# File existence checks
# ---------------------------------------------------------------------------

def validate_file_exists(path: str | Path, label: str = "File") -> Path:
    """
    Verify a file exists and is readable.

    Args:
        path: Path to the file.
        label: Human-readable label for error messages.

    Returns:
        Resolved Path object.

    Raises:
        CertificateNotFoundError: If the file does not exist.
    """
    p = Path(path).resolve()
    if not p.is_file():
        raise CertificateNotFoundError(
            f"{label} not found: {p}"
        )
    return p
