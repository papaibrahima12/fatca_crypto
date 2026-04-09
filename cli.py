"""
Command-Line Interface for FATCA Crypto Utility.

Commands:
    encrypt  — Encrypt a FATCA XML file and package as IDES ZIP
    decrypt  — Decrypt an IRS feedback file
    sign     — Sign an XML file only (without encryption)
    info     — Show XML file and certificate info
"""

import argparse
import getpass
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import traceback

__version__ = "1.0.0"
__app_name__ = "FATCA Crypto Utility"
from fatca_utils.errors import FatcaCryptoError


def main(argv: list[str] | None = None) -> int:
    """Entry point for the CLI."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    from fatca_utils.errors import FatcaCryptoError
    from fatca_utils.errors import FatcaCryptoError

    if not hasattr(args, "func"):
        parser.print_help()
        return 0

    try:
        return args.func(args)
    except FatcaCryptoError as e:
        _print_error(str(e))
        if e.detail:
            _print_error(f"  Detail: {e.detail}")
        return 1
    except KeyboardInterrupt:
        _print_error("\nOperation cancelled by user.")
        return 130
    except Exception as e:
        _print_error(f"Unexpected error: {e}")
        if "--debug" in (argv or sys.argv):
            traceback.print_exc()
        return 2


# ---------------------------------------------------------------------------
# Parser setup
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fatca-crypto",
        description=f"{__app_name__} v{__version__} — "
                    f"FATCA XML encryption/decryption for IRS IDES",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:

  # Encrypt & package a FATCA XML file
  fatca-crypto encrypt \\
    --xml report.xml \\
    --cert bank_cert.p12 \\
    --irs-cert irs_public.pem \\
    --output ./output/

  # Decrypt IRS feedback
  fatca-crypto decrypt \\
    --payload feedback_Payload \\
    --key feedback_Key \\
    --cert bank_cert.p12 \\
    --output ./decrypted/feedback.xml

  # Sign XML only
  fatca-crypto sign \\
    --xml report.xml \\
    --cert bank_cert.p12 \\
    --output signed_report.xml

  # Show file info
  fatca-crypto info --xml report.xml --cert bank_cert.p12
        """,
    )
    parser.add_argument(
        "--version", action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Show full stack traces on error.",
    )

    subparsers = parser.add_subparsers(
        title="commands", dest="command",
        description="Available operations",
    )

    # --- encrypt ---
    enc = subparsers.add_parser(
        "encrypt",
        help="Encrypt and package a FATCA XML file for IRS IDES.",
    )
    enc.add_argument(
        "--xml", required=True,
        help="Path to the FATCA XML file to encrypt.",
    )
    enc.add_argument(
        "--cert", required=True,
        help="Path to the bank's certificate (.crt, .pem, or .p12).",
    )
    enc.add_argument(
        "--irs-cert", required=True,
        help="Path to the IRS public certificate (.pem or .crt).",
    )
    enc.add_argument(
        "--giin", default=None,
        help="Bank's GIIN (extracted from cert if not provided).",
    )
    enc.add_argument(
        "--output", default="./output",
        help="Output directory for the ZIP package (default: ./output).",
    )
    enc.add_argument(
        "--password", default=None,
        help="Mot de passe du certificat .p12.",
    )
    enc.set_defaults(func=_cmd_encrypt)

    # --- decrypt ---
    dec = subparsers.add_parser(
        "decrypt",
        help="Decrypt an IRS feedback file.",
    )
    dec.add_argument(
        "--payload", required=True,
        help="Path to the encrypted feedback payload file.",
    )
    dec.add_argument(
        "--key", required=False, default=None,
        help="Path to the wrapped AES key file (if separate).",
    )
    dec.add_argument(
        "--cert", required=True,
        help="Path to the bank's certificate (.crt, .pem, or .p12).",
    )
    dec.add_argument(
        "--output", required=True,
        help="Path to write the decrypted XML file.",
    )
    dec.add_argument(
        "--password", default=None,
        help="Mot de passe du certificat .p12.",
    )
    dec.set_defaults(func=_cmd_decrypt)

    # --- sign ---
    sgn = subparsers.add_parser(
        "sign",
        help="Sign an XML file (without encryption).",
    )
    sgn.add_argument(
        "--xml", required=True,
        help="Path to the XML file to sign.",
    )
    sgn.add_argument(
        "--cert", required=True,
        help="Path to the bank's certificate (.p12, .pem, or .crt) with private key.",
    )
    sgn.add_argument(
        "--key", default=None,
        help="Path to the bank's private key file (.key), if separate from the certificate.",
    )
    sgn.add_argument(
        "--output", default=None,
        help="Output path for signed XML (default: overwrite input).",
    )
    sgn.add_argument(
        "--password", default=None,
        help="Mot de passe du certificat .p12.",
    )
    sgn.set_defaults(func=_cmd_sign)

    # --- info ---
    inf = subparsers.add_parser(
        "info",
        help="Show XML file and/or certificate information.",
    )
    inf.add_argument(
        "--xml", default=None,
        help="Path to an XML file to inspect.",
    )
    inf.add_argument(
        "--cert", default=None,
        help="Path to a certificate to inspect.",
    )
    inf.set_defaults(func=_cmd_info)

    return parser


# ---------------------------------------------------------------------------
# Helper: resolve certificate password
# ---------------------------------------------------------------------------

def _resolve_password(args, cert_path: str) -> str | None:
    """
    Determine the certificate password from CLI args or interactive prompt.

    If --password was supplied on the command line, use it.
    If the certificate is a .p12 or .pfx file, prompt interactively.
    Otherwise return None.

    Args:
        args: Parsed argparse namespace.
        cert_path: Path string to the certificate file.

    Returns:
        Password string, or None if no password is needed/provided.
    """
    if args.password:
        return args.password
    if cert_path.lower().endswith((".p12", ".pfx")):
        pw = getpass.getpass("Mot de passe du certificat (vide si aucun): ")
        return pw if pw else None
    return None


# ---------------------------------------------------------------------------
# Command: encrypt
# ---------------------------------------------------------------------------

def _cmd_encrypt(args: argparse.Namespace) -> int:
    from fatca_crypto_core.certificates import load_certificate, load_public_certificate
    from fatca_crypto_core.packaging import package_for_ides
    from fatca_crypto_core.signer import sign_xml_bytes
    from fatca_crypto_core.encryptor import encrypt_xml_bytes
    from fatca_utils.validators import validate_certificate_expiry

    _print_header("FATCA XML Encryption")

    password = _resolve_password(args, args.cert)

    # Load certificates
    _print_step("Loading bank certificate...")
    sender_cert = load_certificate(args.cert, giin_override=args.giin, password=password)
    validate_certificate_expiry(sender_cert.not_after)
    _print_ok(f"  Subject: {sender_cert.subject}")
    _print_ok(f"  GIIN:    {sender_cert.giin or 'NOT FOUND'}")
    _print_ok(f"  Valid:   {sender_cert.not_before} → {sender_cert.not_after}")

    _print_step("Loading IRS certificate...")
    irs_cert = load_public_certificate(args.irs_cert)
    validate_certificate_expiry(irs_cert.not_after)
    _print_ok(f"  Subject: {irs_cert.subject}")

    # Sign
    _print_step("Signature du XML...")
    xml_bytes = Path(args.xml).read_bytes()
    signed_xml = sign_xml_bytes(xml_bytes, sender_cert)
    _print_ok("  XML signé.")

    # Encrypt
    _print_step("Chiffrement du XML signé...")
    if not sender_cert.giin:
        _print_error("GIIN introuvable dans le certificat. Utilisez --giin.")
        return 1
    payload = encrypt_xml_bytes(signed_xml, sender_cert.giin, irs_cert)
    _print_ok(f"  Message Ref ID: {payload.message_ref_id}")

    # Package
    _print_step("Creating IDES ZIP package...")
    zip_path = package_for_ides(payload, args.output)
    _print_ok(f"  ZIP created: {zip_path}")

    _print_success(f"\n✅ Encryption complete! Output: {zip_path}")
    return 0


# ---------------------------------------------------------------------------
# Command: decrypt
# ---------------------------------------------------------------------------

def _cmd_decrypt(args: argparse.Namespace) -> int:
    from fatca_crypto_core.certificates import load_certificate
    from fatca_crypto_core.decryptor import (
        decrypt_feedback,
        decrypt_feedback_single_file,
    )

    _print_header("IRS Feedback Decryption")

    password = _resolve_password(args, args.cert)

    _print_step("Loading bank certificate...")
    cert_bundle = load_certificate(args.cert, password=password)
    _print_ok(f"  Subject: {cert_bundle.subject}")

    _print_step("Decrypting feedback file...")
    if args.key:
        result = decrypt_feedback(
            encrypted_path=args.payload,
            key_path=args.key,
            cert_bundle=cert_bundle,
            output_path=args.output,
        )
    else:
        result = decrypt_feedback_single_file(
            encrypted_path=args.payload,
            cert_bundle=cert_bundle,
            output_path=args.output,
        )

    _print_ok(f"  Decrypted to: {args.output}")
    _print_ok(f"  Status: {result.status}")
    if result.message_ref_id:
        _print_ok(f"  Message Ref: {result.message_ref_id}")

    if result.errors:
        _print_error("  Errors from IRS:")
        for err in result.errors:
            _print_error(f"    - {err}")

    if result.notifications:
        _print_step("  Notifications:")
        for note in result.notifications:
            print(f"    ℹ️  {note}")

    _print_success(f"\n✅ Decryption complete!")
    return 0


# ---------------------------------------------------------------------------
# Command: sign
# ---------------------------------------------------------------------------

def _cmd_sign(args: argparse.Namespace) -> int:
    from fatca_crypto_core.certificates import load_certificate
    from fatca_crypto_core.signer import sign_xml
    from fatca_utils.validators import validate_certificate_expiry

    _print_header("XML Signing")

    password = _resolve_password(args, args.cert)

    _print_step("Loading certificate...")
    cert_bundle = load_certificate(args.cert, key_path=getattr(args, 'key', None), password=password)
    validate_certificate_expiry(cert_bundle.not_after)
    _print_ok(f"  Subject: {cert_bundle.subject}")

    _print_step("Signing XML...")
    output = sign_xml(args.xml, cert_bundle, output_path=args.output)
    _print_ok(f"  Signed XML: {output}")

    _print_success("\n✅ Signing complete!")
    return 0


# ---------------------------------------------------------------------------
# Command: info
# ---------------------------------------------------------------------------

def _cmd_info(args: argparse.Namespace) -> int:
    _print_header("File Information")

    if args.cert:
        from fatca_crypto_core.certificates import load_certificate

        _print_step("Certificate details:")
        cert = load_certificate(args.cert)
        print(f"  Subject:     {cert.subject}")
        print(f"  GIIN:        {cert.giin or 'NOT FOUND'}")
        print(f"  Valid from:  {cert.not_before}")
        print(f"  Valid until: {cert.not_after}")
        print(f"  Has key:     {'Yes' if cert.private_key else 'No'}")
        print(f"  Chain certs: {len(cert.chain)}")

    if args.xml:
        from fatca_xml.parser import get_xml_info

        _print_step("XML file details:")
        info = get_xml_info(args.xml)
        print(f"  File:       {info['file']}")
        print(f"  Size:       {info['size_bytes']:,} bytes")
        print(f"  Root tag:   {info.get('root_tag', 'N/A')}")
        print(f"  Namespace:  {info.get('root_namespace', 'N/A')}")
        count = info.get('element_count', 0)
        note = info.get('element_count_note', '')
        print(f"  Elements:   {count:,} {f'({note})' if note else ''}")

    if not args.cert and not args.xml:
        _print_error("Provide --cert and/or --xml to inspect.")
        return 1

    return 0


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------

def _print_header(title: str) -> None:
    width = max(len(title) + 6, 50)
    print("=" * width)
    print(f"   {title}")
    print("=" * width)


def _print_step(msg: str) -> None:
    print(f"🔹 {msg}")


def _print_ok(msg: str) -> None:
    print(f"   ✓ {msg}" if not msg.startswith("  ") else f"  ✓{msg[1:]}")


def _print_success(msg: str) -> None:
    print(msg)


def _print_error(msg: str) -> None:
    print(f"❌ {msg}", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
