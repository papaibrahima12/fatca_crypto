"""
FATCA XML Encryption for IRS IDES compliance.

Implements the IRS-required encryption flow (per IDES Data Preparation spec):
1. Generate AES-256 key (32 bytes) + IV (16 bytes)
2. Encrypt XML payload with AES-256-CBC + PKCS#7 padding
3. Concatenate AES key + IV = 48 bytes, encrypt with RSA PKCS#1 v1.5
4. Package encrypted payload and wrapped key + metadata

References:
- https://www.irs.gov/businesses/corporations/ides-data-transmission-and-file-preparation
- IRS IDES Technical FAQ E19-E21
"""

import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from lxml import etree

from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7

from ..crypto.certificates import CertificateBundle
from ..utils.errors import EncryptionError
from ..utils.security import SecureBytes

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
AES_KEY_SIZE = 32  # 256 bits
AES_BLOCK_SIZE = 128  # bits (for PKCS7 padding)
IV_SIZE = 16  # AES block size in bytes
IRS_RECEIVER_GIIN = "000000.00000.TA.840"


@dataclass
class EncryptedPayload:
    """
    Result of the encryption operation.

    Attributes:
        encrypted_data: AES-256-CBC encrypted XML (no IV prefix).
        wrapped_key: 48-byte (AES key + IV) encrypted with RSA PKCS#1 v1.5.
        iv: Initialization vector used for AES-CBC.
        sender_giin: GIIN of the sending institution.
        receiver_giin: GIIN of the receiver (IRS).
        timestamp: When the encryption was performed.
        message_ref_id: Unique message reference ID.
        tax_year: Tax year extracted from the XML payload (None if unknown).
    """
    encrypted_data: bytes
    wrapped_key: bytes
    iv: bytes
    sender_giin: str
    receiver_giin: str
    timestamp: datetime
    message_ref_id: str
    tax_year: int | None = None


def _extract_tax_year(xml_data: bytes) -> int | None:
    """
    Extract the tax year from a FATCA XML payload.

    Looks for the ReportingPeriod element and returns the year portion.

    Args:
        xml_data: Raw XML bytes.

    Returns:
        Four-digit year as int, or None if not found.
    """
    try:
        root = etree.fromstring(xml_data)
        for e in root.iter():
            if not isinstance(e.tag, str):
                continue
            local = etree.QName(e.tag).localname
            if local == "ReportingPeriod" and e.text:
                return int(e.text.strip()[:4])
    except Exception:
        pass
    return None


def encrypt_fatca_xml(
    xml_path: str | Path,
    sender_cert: CertificateBundle,
    irs_cert: CertificateBundle,
    message_ref_id: str | None = None,
) -> EncryptedPayload:
    """
    Encrypt a FATCA XML file following IRS IDES specifications.

    Per IRS IDES spec:
    1. Read the XML payload
    2. Generate random AES-256 key (32 bytes) and IV (16 bytes)
    3. Encrypt payload with AES-256-CBC + PKCS#7 padding
    4. Concat AES key + IV (48 bytes), encrypt with RSA PKCS#1 v1.5
    5. Return EncryptedPayload with all components

    Args:
        xml_path: Path to the (optionally signed) FATCA XML file.
        sender_cert: Bank's certificate bundle (for GIIN extraction).
        irs_cert: IRS public certificate (for RSA key wrapping).
        message_ref_id: Optional unique message ref. Generated if None.

    Returns:
        EncryptedPayload containing encrypted data & metadata.

    Raises:
        EncryptionError: If any step fails.
    """
    xml_path = Path(xml_path).resolve()

    if not xml_path.is_file():
        raise EncryptionError(f"XML file not found: {xml_path}")

    if irs_cert.certificate is None:
        raise EncryptionError("IRS certificate is required for encryption.")

    sender_giin = sender_cert.giin
    if not sender_giin:
        raise EncryptionError(
            "Sender GIIN not found. Provide a certificate with GIIN in the "
            "subject fields, or use --giin to specify it manually."
        )

    if message_ref_id is None:
        ts = datetime.now(timezone.utc)
        utc_str = ts.strftime("%Y%m%dT%H%M%S") + f"{ts.microsecond // 1000:03d}Z"
        message_ref_id = f"{utc_str}_{sender_giin}"

    try:
        # Read the XML payload
        xml_data = xml_path.read_bytes()

        # Extract tax year from XML
        tax_year = _extract_tax_year(xml_data)

        # Generate AES-256 key and IV
        aes_key = SecureBytes(os.urandom(AES_KEY_SIZE))
        iv = os.urandom(IV_SIZE)

        # Encrypt the payload with AES-256-CBC + PKCS#7
        encrypted_data = _aes_encrypt(xml_data, aes_key.data, iv)

        # IRS spec: concat AES key (32) + IV (16) = 48 bytes
        # Then encrypt with RSA PKCS#1 v1.5
        key_plus_iv = aes_key.data + iv
        wrapped_key = _rsa_wrap_key(key_plus_iv, irs_cert)

        # Clear the AES key from memory
        aes_key.clear()

        return EncryptedPayload(
            encrypted_data=encrypted_data,
            wrapped_key=wrapped_key,
            iv=iv,
            sender_giin=sender_giin,
            receiver_giin=IRS_RECEIVER_GIIN,
            timestamp=datetime.now(timezone.utc),
            message_ref_id=message_ref_id,
            tax_year=tax_year,
        )

    except EncryptionError:
        raise
    except Exception as e:
        raise EncryptionError(f"Encryption failed: {e}") from e


def encrypt_xml_bytes(
    xml_bytes: bytes,
    sender_giin: str,
    irs_cert: CertificateBundle,
    message_ref_id: str | None = None,
) -> EncryptedPayload:
    """
    Encrypt XML content from memory (bytes) rather than file.

    Args:
        xml_bytes: Raw XML content.
        sender_giin: The bank's GIIN.
        irs_cert: IRS public certificate for key wrapping.
        message_ref_id: Optional message reference ID.

    Returns:
        EncryptedPayload.
    """
    if message_ref_id is None:
        ts = datetime.now(timezone.utc)
        utc_str = ts.strftime("%Y%m%dT%H%M%S") + f"{ts.microsecond // 1000:03d}Z"
        message_ref_id = f"{utc_str}_{sender_giin}"

    try:
        # Extract tax year from XML
        tax_year = _extract_tax_year(xml_bytes)

        aes_key = SecureBytes(os.urandom(AES_KEY_SIZE))
        iv = os.urandom(IV_SIZE)

        encrypted_data = _aes_encrypt(xml_bytes, aes_key.data, iv)

        key_plus_iv = aes_key.data + iv
        wrapped_key = _rsa_wrap_key(key_plus_iv, irs_cert)

        aes_key.clear()

        return EncryptedPayload(
            encrypted_data=encrypted_data,
            wrapped_key=wrapped_key,
            iv=iv,
            sender_giin=sender_giin,
            receiver_giin=IRS_RECEIVER_GIIN,
            timestamp=datetime.now(timezone.utc),
            message_ref_id=message_ref_id,
            tax_year=tax_year,
        )
    except Exception as e:
        raise EncryptionError(f"Encryption failed: {e}") from e


def write_encrypted_payload(
    payload: EncryptedPayload,
    output_dir: str | Path,
) -> dict[str, Path]:
    """
    Write the encrypted payload components to disk.

    Per IRS naming conventions:
    - <SenderGIIN>_Payload     — encrypted XML data
    - <ReceiverGIIN>_Key       — RSA-wrapped AES key + IV
    - <SenderGIIN>_Metadata.xml — IDES metadata

    Args:
        payload: The EncryptedPayload to write.
        output_dir: Directory to write files to.

    Returns:
        Dict of file type → Path.
    """
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    files = {}

    # Encrypted payload: SenderGIIN_Payload
    payload_path = output_dir / f"{payload.sender_giin}_Payload"
    payload_path.write_bytes(payload.encrypted_data)
    files["payload"] = payload_path

    # Wrapped key: ReceiverGIIN_Key
    key_path = output_dir / f"{payload.receiver_giin}_Key"
    key_path.write_bytes(payload.wrapped_key)
    files["key"] = key_path

    # Metadata XML: SenderGIIN_Metadata.xml
    metadata_path = output_dir / f"{payload.sender_giin}_Metadata.xml"
    metadata_xml = _build_metadata_xml(payload)
    metadata_path.write_bytes(metadata_xml)
    files["metadata"] = metadata_path

    return files


# ---------------------------------------------------------------------------
# Internal: AES-256-CBC encryption
# ---------------------------------------------------------------------------

def _aes_encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    """
    Encrypt data with AES-256-CBC and PKCS7 padding.

    Per IRS spec: CBC mode, no salt, PKCS#5/PKCS#7 padding.
    IV goes in the key file (not prepended to ciphertext).

    Args:
        plaintext: Data to encrypt.
        key: 32-byte AES key.
        iv: 16-byte initialization vector.

    Returns:
        Ciphertext only (IV is in the key file per IRS spec).
    """
    # Apply PKCS7 padding
    padder = PKCS7(AES_BLOCK_SIZE).padder()
    padded = padder.update(plaintext) + padder.finalize()

    # Encrypt
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded) + encryptor.finalize()

    # IRS spec: ciphertext only, no IV prefix
    return ciphertext


# ---------------------------------------------------------------------------
# Internal: RSA key wrapping
# ---------------------------------------------------------------------------

def _rsa_wrap_key(
    key_plus_iv: bytes,
    irs_cert: CertificateBundle,
) -> bytes:
    """
    Encrypt AES key + IV using the IRS RSA public key.

    Per IRS spec (FAQ E21):
    - Input: 48 bytes (32-byte AES key + 16-byte IV)
    - Padding: PKCS#1 v1.5

    Args:
        key_plus_iv: 48-byte value (AES key + IV).
        irs_cert: CertificateBundle containing the IRS public certificate.

    Returns:
        RSA-encrypted key+IV bytes.
    """
    public_key = irs_cert.certificate.public_key()

    wrapped = public_key.encrypt(
        key_plus_iv,
        asym_padding.PKCS1v15(),
    )
    return wrapped


# ---------------------------------------------------------------------------
# Internal: Metadata XML
# ---------------------------------------------------------------------------

def _build_metadata_xml(payload: EncryptedPayload) -> bytes:
    """
    Build encryption metadata XML per IRS FATCA-IDES-SenderFileMetadata v1.3 schema.

    Schema namespace: urn:fatca:idessenderfilemetadata
    Root element: FATCAIDESSenderFileMetadata
    """
    METADATA_NS = "urn:fatca:idessenderfilemetadata"
    XSI_NS = "http://www.w3.org/2001/XMLSchema-instance"

    nsmap = {
        None: METADATA_NS,
        "xsi": XSI_NS,
    }

    root = etree.Element(
        f"{{{METADATA_NS}}}FATCAIDESSenderFileMetadata",
        nsmap=nsmap,
    )
    root.set(
        f"{{{XSI_NS}}}schemaLocation",
        "urn:fatca:idessenderfilemetadata FatcaIdesSenderFileMetadata.xsd",
    )

    etree.SubElement(root, f"{{{METADATA_NS}}}FATCAEntitySenderId").text = \
        payload.sender_giin
    etree.SubElement(root, f"{{{METADATA_NS}}}FATCAEntityReceiverId").text = \
        payload.receiver_giin
    etree.SubElement(root, f"{{{METADATA_NS}}}FATCAEntCommunicationTypeCd").text = \
        "RPT"
    etree.SubElement(root, f"{{{METADATA_NS}}}SenderFileId").text = \
        payload.message_ref_id
    etree.SubElement(root, f"{{{METADATA_NS}}}FileFormatCd").text = "XML"
    etree.SubElement(root, f"{{{METADATA_NS}}}BinaryEncodingSchemeCd").text = "NONE"

    # Timestamp with milliseconds per schema TimestampWithMillisecondsType
    ts_str = payload.timestamp.strftime("%Y-%m-%dT%H:%M:%S") + \
             f".{payload.timestamp.microsecond // 1000:03d}Z"
    etree.SubElement(root, f"{{{METADATA_NS}}}FileCreateTs").text = ts_str

    tax_year = payload.tax_year if payload.tax_year is not None else payload.timestamp.year - 1
    etree.SubElement(root, f"{{{METADATA_NS}}}TaxYear").text = str(tax_year)
    etree.SubElement(root, f"{{{METADATA_NS}}}FileRevisionInd").text = "false"

    return etree.tostring(
        root,
        xml_declaration=True,
        encoding="UTF-8",
        pretty_print=True,
    )
