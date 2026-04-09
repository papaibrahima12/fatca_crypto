"""
Test rapide : signe le XML sample et affiche le résultat
pour comparer avec le format IRS attendu.
"""

from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime

# --- 1. Générer un certificat de test auto-signé ---
print("=" * 60)
print("  1. Génération d'un certificat de test...")
print("=" * 60)

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
subject = issuer = x509.Name([
    x509.NameAttribute(NameOID.COUNTRY_NAME, "SN"),
    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Dakar"),
    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "BanqueTest"),
    x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "A1B2C3.00000.LE.686"),
    x509.NameAttribute(NameOID.COMMON_NAME, "Test FATCA"),
])
cert = (
    x509.CertificateBuilder()
    .subject_name(subject)
    .issuer_name(issuer)
    .public_key(key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
    .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365))
    .sign(key, hashes.SHA256())
)

print(f"  Subject: {cert.subject.rfc4514_string()}")
print(f"  GIIN (dans OU): A1B2C3.00000.LE.686")
print()

# --- 2. Construire un CertificateBundle ---
from fatca_crypto.crypto.certificates import CertificateBundle

bundle = CertificateBundle(
    private_key=key,
    certificate=cert,
    chain=[],
    giin="A1B2C3.00000.LE.686",
    not_before=cert.not_valid_before_utc,
    not_after=cert.not_valid_after_utc,
    subject=cert.subject.rfc4514_string(),
)

# --- 3. Signer le XML sample ---
print("=" * 60)
print("  2. Signature du XML sample...")
print("=" * 60)

sample_xml = Path(__file__).parent / "exepted_result_example" / "000000.00000.TA.152.xml"
xml_bytes = sample_xml.read_bytes()

from fatca_crypto.crypto.signer import sign_xml_bytes
signed_xml = sign_xml_bytes(xml_bytes, bundle)

# Écrire le résultat signé
output_dir = Path(__file__).parent / "test_output"
output_dir.mkdir(exist_ok=True)

signed_path = output_dir / "SIGNED_Payload.xml"
signed_path.write_bytes(signed_xml)

print(f"  XML signé écrit dans : {signed_path}")
print()

# --- 4. Afficher les 30 premières lignes du XML signé ---
print("=" * 60)
print("  3. Résultat signé (30 premières lignes) :")
print("=" * 60)

from lxml import etree
root = etree.fromstring(signed_xml)
pretty = etree.tostring(root, pretty_print=True, encoding="unicode")
lines = pretty.splitlines()
for i, line in enumerate(lines[:30], 1):
    print(f"  {i:3d} | {line}")
if len(lines) > 30:
    print(f"  ... ({len(lines) - 30} lignes supplémentaires)")
print()

# --- 5. Comparer avec le format IRS attendu ---
print("=" * 60)
print("  4. Vérifications de conformité IRS :")
print("=" * 60)

checks = {
    "Racine = <Signature>": root.tag == "{http://www.w3.org/2000/09/xmldsig#}Signature",
    "Pas de préfixe ds:": root.prefix is None,
    "<Object Id='FATCA'> présent": root.find("{http://www.w3.org/2000/09/xmldsig#}Object") is not None,
    "Object contient FATCA_OECD": root.find(".//{urn:oecd:ties:fatca:v2}FATCA_OECD") is not None,
    "Reference URI='#FATCA'": root.find(".//{http://www.w3.org/2000/09/xmldsig#}Reference").get("URI") == "#FATCA",
    "1 seul Transform (exc-c14n)": len(root.findall(".//{http://www.w3.org/2000/09/xmldsig#}Transform")) == 1,
    "SignatureMethod = RSA-SHA256": "rsa-sha256" in root.find(".//{http://www.w3.org/2000/09/xmldsig#}SignatureMethod").get("Algorithm"),
    "X509SubjectName présent": root.find(".//{http://www.w3.org/2000/09/xmldsig#}X509SubjectName") is not None,
    "X509Certificate présent": root.find(".//{http://www.w3.org/2000/09/xmldsig#}X509Certificate") is not None,
    "DigestValue non vide": bool(root.find(".//{http://www.w3.org/2000/09/xmldsig#}DigestValue").text),
    "SignatureValue non vide": bool(root.find(".//{http://www.w3.org/2000/09/xmldsig#}SignatureValue").text),
}

all_pass = True
for desc, passed in checks.items():
    icon = "✅" if passed else "❌"
    print(f"  {icon} {desc}")
    if not passed:
        all_pass = False

print()
if all_pass:
    print("  🎉 TOUTES LES VÉRIFICATIONS PASSENT — Format conforme IRS !")
else:
    print("  ⚠️  Certaines vérifications ont échoué.")
print()
print(f"  Fichier signé disponible ici pour inspection :")
print(f"  {signed_path}")
