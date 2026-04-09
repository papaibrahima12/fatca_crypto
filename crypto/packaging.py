"""
ZIP packaging for IRS IDES submission.

Per IRS spec, the ZIP contains:
    <SenderGIIN>_Payload        (AES-256-CBC encrypted XML)
    <ReceiverGIIN>_Key          (48-byte AES key+IV, RSA PKCS#1 v1.5)
    <SenderGIIN>_Metadata.xml   (unencrypted IDES metadata)

ZIP naming: UTC_FATCAEntitySenderId.zip
"""

import zipfile
from datetime import datetime, timezone
from pathlib import Path

from crypto.encryptor import EncryptedPayload, _build_metadata_xml
from utils.errors import PackagingError


def package_for_ides(
    payload: EncryptedPayload,
    output_dir: str | Path,
    zip_filename: str | None = None,
) -> Path:
    """
    Create the IRS IDES ZIP package from an encrypted payload.

    The ZIP file contains:
    - Encrypted XML payload
    - RSA-wrapped AES key
    - Metadata XML

    Args:
        payload: The EncryptedPayload from the encryption step.
        output_dir: Directory where the ZIP will be created.
        zip_filename: Custom ZIP filename. Default: <GIIN>_RapportsIRS.zip

    Returns:
        Path to the created ZIP file.

    Raises:
        PackagingError: If packaging fails.
    """
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if zip_filename is None:
        # IRS convention: UTC_FATCAEntitySenderId.zip
        utc_ts = payload.timestamp.strftime("%Y%m%dT%H%M%S") + \
                 f"{payload.timestamp.microsecond // 1000:03d}Z"
        zip_filename = f"{utc_ts}_{payload.sender_giin}.zip"

    zip_path = output_dir / zip_filename

    try:
        # Build metadata XML
        metadata_xml = _build_metadata_xml(payload)

        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_STORED) as zf:
            # Encrypted payload: SenderGIIN_Payload
            zf.writestr(f"{payload.sender_giin}_Payload", payload.encrypted_data)

            # Wrapped key: ReceiverGIIN_Key
            zf.writestr(f"{payload.receiver_giin}_Key", payload.wrapped_key)

            # Metadata: SenderGIIN_Metadata.xml
            zf.writestr(f"{payload.sender_giin}_Metadata.xml", metadata_xml)

        return zip_path

    except Exception as e:
        raise PackagingError(f"ZIP packaging failed: {e}") from e


def package_files_for_ides(
    payload_path: str | Path,
    key_path: str | Path,
    metadata_path: str | Path,
    sender_giin: str,
    output_dir: str | Path,
    zip_filename: str | None = None,
) -> Path:
    """
    Create the IDES ZIP from pre-existing files on disk.

    Useful when the encrypted payload was already written to disk
    by write_encrypted_payload().

    Args:
        payload_path: Path to the encrypted payload file.
        key_path: Path to the wrapped key file.
        metadata_path: Path to the metadata XML file.
        sender_giin: The bank's GIIN (for ZIP naming).
        output_dir: Where to create the ZIP.
        zip_filename: Optional custom filename.

    Returns:
        Path to the ZIP file.
    """
    output_dir = Path(output_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)

    if zip_filename is None:
        utc_ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + \
                 f"{datetime.now(timezone.utc).microsecond // 1000:03d}Z"
        zip_filename = f"{utc_ts}_{sender_giin}.zip"

    zip_path = output_dir / zip_filename

    try:
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_STORED) as zf:
            for fpath in (payload_path, key_path, metadata_path):
                fpath = Path(fpath)
                if not fpath.is_file():
                    raise PackagingError(f"File not found: {fpath}")
                zf.write(fpath, fpath.name)

        return zip_path

    except PackagingError:
        raise
    except Exception as e:
        raise PackagingError(f"ZIP packaging failed: {e}") from e
