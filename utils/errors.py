"""
Custom exceptions for the FATCA Crypto Utility.

All exceptions inherit from FatcaCryptoError so callers can catch
the entire family with a single except clause.
"""


class FatcaCryptoError(Exception):
    """Base exception for all FATCA Crypto Utility errors."""

    def __init__(self, message: str, detail: str | None = None):
        self.detail = detail
        super().__init__(message)


class CertificateError(FatcaCryptoError):
    """Raised when certificate loading, parsing, or validation fails."""
    pass


class CertificateExpiredError(CertificateError):
    """Raised when a certificate has expired."""
    pass


class CertificateNotFoundError(CertificateError):
    """Raised when a certificate file is missing or unreadable."""
    pass


class InvalidGIINError(FatcaCryptoError):
    """Raised when GIIN format is invalid or cannot be extracted."""
    pass


class EncryptionError(FatcaCryptoError):
    """Raised when encryption operations fail."""
    pass


class DecryptionError(FatcaCryptoError):
    """Raised when decryption operations fail."""
    pass


class SigningError(FatcaCryptoError):
    """Raised when XML signing fails."""
    pass


class XMLError(FatcaCryptoError):
    """Raised when XML parsing or validation fails."""
    pass


class PackagingError(FatcaCryptoError):
    """Raised when ZIP packaging fails."""
    pass
