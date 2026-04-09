"""
FATCA Feedback File Decryption.

Decrypts IRS feedback files received after IDES submission.

Per IRS IDES spec:
1. Decrypt the key file (RSA PKCS#1 v1.5) → 48 bytes (AES key 32 + IV 16)
2. Split into AES key and IV
3. Decrypt the payload with AES-256-CBC + PKCS#7 unpadding
4. Parse and return the feedback XML
"""

import zipfile
from dataclasses import dataclass
from pathlib import Path

from lxml import etree

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from crypto.certificates import CertificateBundle
from utils.errors import DecryptionError
from utils.security import SecureBytes

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
AES_BLOCK_SIZE = 128  # bits
IV_SIZE = 16  # bytes


@dataclass
class FeedbackResult:
    """
    Parsed IRS feedback result.

    Attributes:
        raw_xml: The decrypted XML as bytes.
        status: Overall status (ACCEPTED, REJECTED, PARTIAL, UNKNOWN).
        message_ref_id: Reference ID linking back to original submission.
        errors: List of error messages (if any).
        notifications: List of notification/info messages (if any).
    """
    raw_xml: bytes
    status: str
    message_ref_id: str | None
    errors: list[str]
    notifications: list[str]


def decrypt_feedback(
    encrypted_path: str | Path,
    key_path: str | Path,
    cert_bundle: CertificateBundle,
    output_path: str | Path | None = None,
) -> FeedbackResult:
    """
    Decrypt an IRS feedback file.

    Args:
        encrypted_path: Path to the encrypted feedback payload file.
        key_path: Path to the wrapped (encrypted) AES key file.
        cert_bundle: Bank's CertificateBundle with private key for
                     RSA key unwrapping.
        output_path: Optional path to write decrypted XML to disk.

    Returns:
        FeedbackResult with decrypted content and parsed status.

    Raises:
        DecryptionError: If decryption fails.
    """
    encrypted_path = Path(encrypted_path).resolve()
    key_path = Path(key_path).resolve()

    if cert_bundle.private_key is None:
        raise DecryptionError(
            "Cannot decrypt: certificate bundle has no private key. "
            "Provide a .p12 or .pem file with a private key."
        )

    if not encrypted_path.is_file():
        raise DecryptionError(
            f"Encrypted feedback file not found: {encrypted_path}"
        )
    if not key_path.is_file():
        raise DecryptionError(
            f"Wrapped key file not found: {key_path}"
        )

    try:
        # Read encrypted payload and wrapped key
        encrypted_data = encrypted_path.read_bytes()
        wrapped_key_data = key_path.read_bytes()

        # Unwrap: RSA decrypt → 48 bytes (AES key 32 + IV 16)
        key_plus_iv = SecureBytes(_rsa_unwrap_key(wrapped_key_data, cert_bundle))

        if len(key_plus_iv.data) != 48:
            raise DecryptionError(
                f"Unexpected decrypted key size: {len(key_plus_iv.data)} bytes. "
                f"Expected 48 bytes (32-byte AES key + 16-byte IV)."
            )

        aes_key_bytes = key_plus_iv.data[:32]
        iv = key_plus_iv.data[32:48]

        # Decrypt with AES-256-CBC (ciphertext has no IV prefix per IRS spec)
        plaintext = _aes_decrypt(encrypted_data, aes_key_bytes, iv)

        # Clear key from memory
        key_plus_iv.clear()

        # Write decrypted output if requested
        if output_path is not None:
            out = Path(output_path).resolve()
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(plaintext)

        # Parse feedback
        return _parse_feedback_xml(plaintext)

    except DecryptionError:
        raise
    except Exception as e:
        raise DecryptionError(f"Decryption failed: {e}") from e


def decrypt_feedback_single_file(
    encrypted_path: str | Path,
    cert_bundle: CertificateBundle,
    output_path: str | Path | None = None,
) -> FeedbackResult:
    """
    Decrypt a single IRS feedback ZIP file.

    The IRS delivers feedback as a ZIP archive containing a payload file
    (ending with _Payload) and a wrapped key file (ending with _Key).
    This function opens the ZIP, locates both files, and performs the
    standard RSA + AES decryption flow.

    Args:
        encrypted_path: Path to the IRS feedback ZIP file.
        cert_bundle: Bank's CertificateBundle with private key.
        output_path: Optional path to write decrypted XML.

    Returns:
        FeedbackResult.

    Raises:
        DecryptionError: If the ZIP structure is invalid or decryption fails.
    """
    zip_path = Path(encrypted_path).resolve()

    if cert_bundle.private_key is None:
        raise DecryptionError("No private key in certificate bundle.")

    try:
        with zipfile.ZipFile(zip_path, "r") as zf:
            names = zf.namelist()

            payload_name = next(
                (n for n in names if n.endswith("_Payload")), None
            )
            key_name = next(
                (n for n in names if n.endswith("_Key")), None
            )

            if payload_name is None:
                raise DecryptionError(
                    f"No _Payload file found in ZIP. Files present: {names}"
                )
            if key_name is None:
                raise DecryptionError(
                    f"No _Key file found in ZIP. Files present: {names}"
                )

            encrypted_data = zf.read(payload_name)
            wrapped_key_data = zf.read(key_name)

        # Unwrap: RSA decrypt → 48 bytes (AES key 32 + IV 16)
        key_plus_iv = SecureBytes(_rsa_unwrap_key(wrapped_key_data, cert_bundle))

        if len(key_plus_iv.data) != 48:
            raise DecryptionError(
                f"Unexpected decrypted key size: {len(key_plus_iv.data)} bytes. "
                f"Expected 48 bytes (32-byte AES key + 16-byte IV)."
            )

        aes_key_bytes = key_plus_iv.data[:32]
        iv = key_plus_iv.data[32:48]

        plaintext = _aes_decrypt(encrypted_data, aes_key_bytes, iv)

        key_plus_iv.clear()

        if output_path is not None:
            out = Path(output_path).resolve()
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_bytes(plaintext)

        return _parse_feedback_xml(plaintext)

    except DecryptionError:
        raise
    except Exception as e:
        raise DecryptionError(f"Decryption failed: {e}") from e


# ---------------------------------------------------------------------------
# Internal: RSA key unwrapping
# ---------------------------------------------------------------------------

def _rsa_unwrap_key(
    wrapped_key: bytes,
    cert_bundle: CertificateBundle,
) -> bytes:
    """
    Decrypt the key file using bank's RSA private key.

    Per IRS spec: PKCS#1 v1.5 padding.
    Returns 48 bytes (32-byte AES key + 16-byte IV).
    """
    try:
        return cert_bundle.private_key.decrypt(
            wrapped_key,
            asym_padding.PKCS1v15(),
        )
    except Exception as e:
        raise DecryptionError(
            f"RSA key unwrapping failed: {e}. "
            f"Ensure the correct private key is provided."
        ) from e


# ---------------------------------------------------------------------------
# Internal: AES-256-CBC decryption
# ---------------------------------------------------------------------------

def _aes_decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    """Decrypt AES-256-CBC with PKCS7 unpadding."""
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding
    unpadder = PKCS7(AES_BLOCK_SIZE).unpadder()
    plaintext = unpadder.update(padded) + unpadder.finalize()

    return plaintext


# ---------------------------------------------------------------------------
# Internal: Parse IRS feedback XML
# ---------------------------------------------------------------------------

def _parse_feedback_xml(xml_bytes: bytes) -> FeedbackResult:
    """
    Parse the decrypted IRS feedback XML and extract status information.

    The IRS feedback XML typically contains:
    - FATCANotification elements with status codes
    - Error details for rejected records
    """
    errors = []
    notifications = []
    status = "UNKNOWN"
    message_ref_id = None

    try:
        root = etree.fromstring(xml_bytes)

        # Try to find message reference ID
        for tag in ("MessageRefId", "SenderFileId", "OriginalIDESTransmissionId"):
            elem = root.find(f".//{tag}")
            if elem is None:
                # Try with any namespace
                for e in root.iter():
                    local = etree.QName(e.tag).localname if isinstance(e.tag, str) else ""
                    if local == tag and e.text:
                        message_ref_id = e.text.strip()
                        break
            elif elem.text:
                message_ref_id = elem.text.strip()
            if message_ref_id:
                break

        # Extract status from notification elements
        for elem in root.iter():
            local = etree.QName(elem.tag).localname if isinstance(elem.tag, str) else ""

            if local in (
                "FileAcceptanceStatus", "RecordAcceptanceStatus", "Status",
                "FATCANotificationTp", "AcceptanceStatus",
            ):
                if elem.text:
                    val = elem.text.strip().upper()
                    if val in ("ACCEPTED", "REJECTED", "PARTIAL"):
                        status = val
                    elif "ACCEPT" in val:
                        status = "ACCEPTED"
                    elif "REJECT" in val:
                        status = "REJECTED"
                    elif "PARTIAL" in val:
                        status = "PARTIAL"

            elif local in ("ErrorDetail", "Error", "ErrorMessage", "ErrMsg", "ValidationError"):
                if elem.text and elem.text.strip():
                    errors.append(elem.text.strip())

            elif local in ("Notification", "Warning", "Info", "NotifcTp"):
                if elem.text and elem.text.strip():
                    notifications.append(elem.text.strip())

    except etree.XMLSyntaxError:
        # If XML parsing fails, still return raw content
        notifications.append(
            "Warning: Decrypted content is not valid XML. "
            "Raw content is available in raw_xml."
        )

    return FeedbackResult(
        raw_xml=xml_bytes,
        status=status,
        message_ref_id=message_ref_id,
        errors=errors,
        notifications=notifications,
    )
