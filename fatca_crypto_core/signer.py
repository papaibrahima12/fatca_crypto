"""
XML Signing for FATCA Crypto Utility.

Implements enveloping XML digital signatures using SHA-256 with RSA,
compliant with IRS IDES requirements for FATCA XML submissions.

The signature follows the IRS FATCA sample format (enveloping signature):
- <Signature> is the document root (default namespace, no prefix)
- FATCA XML is wrapped inside <Object Id="FATCA">
- Reference URI="#FATCA" points to the Object element
- Only one Transform: Exclusive XML Canonicalization 1.0
- Digest algorithm: SHA-256
- Signature algorithm: RSA-SHA256
- KeyInfo contains X509SubjectName + X509Certificate
"""

import base64
import hashlib
from pathlib import Path

from lxml import etree

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from fatca_crypto_core.certificates import CertificateBundle
from fatca_utils.errors import SigningError

# ---------------------------------------------------------------------------
# XML Signature constants
# ---------------------------------------------------------------------------
XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#"
C14N_EXCLUSIVE = "http://www.w3.org/2001/10/xml-exc-c14n#"
SHA256_DIGEST = "http://www.w3.org/2001/04/xmlenc#sha256"
RSA_SHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

# Default namespace (no prefix) — matches IRS sample format
NSMAP_DS = {None: XMLDSIG_NS}


def sign_xml(
    xml_path: str | Path,
    cert_bundle: CertificateBundle,
    output_path: str | Path | None = None,
) -> Path:
    """
    Sign a FATCA XML file using enveloping XMLDSig (RSA-SHA256).

    The output file has <Signature> as root, with the FATCA XML
    wrapped inside <Object Id="FATCA">, matching the IRS IDES format.

    Args:
        xml_path: Path to the XML file to sign.
        cert_bundle: CertificateBundle containing the private key and cert.
        output_path: Where to write the signed XML. If None, overwrites input.

    Returns:
        Path to the signed XML file.

    Raises:
        SigningError: If signing fails.
    """
    xml_path = Path(xml_path).resolve()
    if output_path is None:
        output_path = xml_path
    else:
        output_path = Path(output_path).resolve()

    if cert_bundle.private_key is None:
        raise SigningError(
            "Cannot sign: certificate bundle has no private key. "
            "Provide a .p12 or .pem file with a private key."
        )

    try:
        parser = etree.XMLParser(remove_blank_text=False)
        tree = etree.parse(str(xml_path), parser)
        root = tree.getroot()

        signature_elem = _build_enveloping_signature(root, cert_bundle)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        etree.ElementTree(signature_elem).write(
            str(output_path),
            xml_declaration=True,
            encoding="UTF-8",
            pretty_print=True,
        )

        return output_path

    except SigningError:
        raise
    except Exception as e:
        raise SigningError(f"XML signing failed: {e}") from e


def sign_xml_bytes(
    xml_bytes: bytes,
    cert_bundle: CertificateBundle,
) -> bytes:
    """
    Sign XML content in memory and return signed XML bytes.

    Args:
        xml_bytes: Raw XML content.
        cert_bundle: CertificateBundle with private key.

    Returns:
        Signed XML as bytes, with <Signature> as root.
    """
    if cert_bundle.private_key is None:
        raise SigningError("Cannot sign: no private key in certificate bundle.")

    try:
        root = etree.fromstring(xml_bytes)
        signature_elem = _build_enveloping_signature(root, cert_bundle)
        return etree.tostring(
            signature_elem, xml_declaration=True, encoding="UTF-8"
        )
    except SigningError:
        raise
    except Exception as e:
        raise SigningError(f"XML signing failed: {e}") from e


# ---------------------------------------------------------------------------
# Internal: Build the enveloping <Signature> element
# ---------------------------------------------------------------------------

def _build_enveloping_signature(
    root: etree._Element,
    cert_bundle: CertificateBundle,
) -> etree._Element:
    """
    Construct a full enveloping <Signature> element per IRS IDES format.

    Output structure:
      <Signature xmlns="http://www.w3.org/2000/09/xmldsig#">
        <SignedInfo>
          <CanonicalizationMethod Algorithm="...exc-c14n#"/>
          <SignatureMethod Algorithm="...rsa-sha256"/>
          <Reference URI="#FATCA">
            <Transforms>
              <Transform Algorithm="...exc-c14n#"/>
            </Transforms>
            <DigestMethod Algorithm="...sha256"/>
            <DigestValue>...</DigestValue>
          </Reference>
        </SignedInfo>
        <SignatureValue>...</SignatureValue>
        <KeyInfo>
          <X509Data>
            <X509SubjectName>...</X509SubjectName>
            <X509Certificate>...</X509Certificate>
          </X509Data>
        </KeyInfo>
        <Object Id="FATCA">
          <!-- original FATCA XML here -->
        </Object>
      </Signature>

    Steps:
    1. Wrap FATCA XML in <Object Id="FATCA">
    2. Exclusive-C14N the Object → SHA-256 → DigestValue
    3. Build <SignedInfo> with URI="#FATCA" and the DigestValue
    4. Exclusive-C14N <SignedInfo> → RSA-SHA256 sign → SignatureValue
    5. Assemble the full <Signature> block
    """
    # --- Step 1: Wrap FATCA XML in <Object Id="FATCA"> ---
    object_elem = etree.Element(f"{{{XMLDSIG_NS}}}Object")
    object_elem.set("Id", "FATCA")
    object_elem.append(root)

    # --- Step 2: Compute digest of the Object element ---
    c14n_object = _c14n_exclusive(object_elem)
    digest_value = base64.b64encode(
        hashlib.sha256(c14n_object).digest()
    ).decode("ascii")

    # --- Step 3: Build <SignedInfo> ---
    signed_info = _build_signed_info(digest_value)

    # --- Step 4: Canonicalize <SignedInfo> and sign ---
    c14n_signed_info = _c14n_exclusive(signed_info)
    signature_value = cert_bundle.private_key.sign(
        c14n_signed_info,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    sig_value_b64 = base64.b64encode(signature_value).decode("ascii")

    # --- Step 5: Assemble <Signature> with default namespace (no prefix) ---
    sig_elem = etree.Element(f"{{{XMLDSIG_NS}}}Signature", nsmap=NSMAP_DS)

    sig_elem.append(signed_info)

    sig_value_elem = etree.SubElement(
        sig_elem, f"{{{XMLDSIG_NS}}}SignatureValue"
    )
    sig_value_elem.text = sig_value_b64

    sig_elem.append(_build_key_info(cert_bundle))
    sig_elem.append(object_elem)

    return sig_elem


def _c14n_exclusive(elem: etree._Element) -> bytes:
    """
    Perform Exclusive C14N 1.0 on an element and return bytes.

    Uses lxml tostring with method='c14n' and exclusive=True.
    """
    return etree.tostring(elem, method="c14n", exclusive=True)


def _build_signed_info(digest_value: str) -> etree._Element:
    """
    Build <SignedInfo> for enveloping signature.

    - Reference URI="#FATCA" (points to <Object Id="FATCA">)
    - One Transform: Exclusive C14N 1.0
    """
    signed_info = etree.Element(
        f"{{{XMLDSIG_NS}}}SignedInfo", nsmap=NSMAP_DS
    )

    c14n_method = etree.SubElement(
        signed_info, f"{{{XMLDSIG_NS}}}CanonicalizationMethod"
    )
    c14n_method.set("Algorithm", C14N_EXCLUSIVE)

    sig_method = etree.SubElement(
        signed_info, f"{{{XMLDSIG_NS}}}SignatureMethod"
    )
    sig_method.set("Algorithm", RSA_SHA256)

    reference = etree.SubElement(signed_info, f"{{{XMLDSIG_NS}}}Reference")
    reference.set("URI", "#FATCA")

    transforms = etree.SubElement(reference, f"{{{XMLDSIG_NS}}}Transforms")
    transform = etree.SubElement(transforms, f"{{{XMLDSIG_NS}}}Transform")
    transform.set("Algorithm", C14N_EXCLUSIVE)

    digest_method = etree.SubElement(
        reference, f"{{{XMLDSIG_NS}}}DigestMethod"
    )
    digest_method.set("Algorithm", SHA256_DIGEST)

    digest_val_elem = etree.SubElement(
        reference, f"{{{XMLDSIG_NS}}}DigestValue"
    )
    digest_val_elem.text = digest_value

    return signed_info


def _build_key_info(cert_bundle: CertificateBundle) -> etree._Element:
    """
    Build <KeyInfo> with X509SubjectName and X509Certificate.

    Matches IRS sample: SubjectName appears before Certificate.
    """
    key_info = etree.Element(f"{{{XMLDSIG_NS}}}KeyInfo", nsmap=NSMAP_DS)
    x509_data = etree.SubElement(key_info, f"{{{XMLDSIG_NS}}}X509Data")

    # X509SubjectName (present in IRS sample, before the certificate)
    subject_name = cert_bundle.certificate.subject.rfc4514_string()
    x509_subject = etree.SubElement(
        x509_data, f"{{{XMLDSIG_NS}}}X509SubjectName"
    )
    x509_subject.text = subject_name

    # X509Certificate (DER, base64-encoded)
    cert_der = cert_bundle.certificate.public_bytes(serialization.Encoding.DER)
    cert_b64 = base64.b64encode(cert_der).decode("ascii")
    x509_cert = etree.SubElement(
        x509_data, f"{{{XMLDSIG_NS}}}X509Certificate"
    )
    x509_cert.text = cert_b64

    return key_info
