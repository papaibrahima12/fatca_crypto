# FATCA Crypto Utility v1.0.0

Outil de chiffrement/dechiffrement de fichiers FATCA XML pour soumission IRS IDES.

Conforme aux specifications IRS :
- [IDES Data Transmission and File Preparation](https://www.irs.gov/businesses/corporations/ides-data-transmission-and-file-preparation)
- [FATCA IDES Technical FAQs](https://www.irs.gov/businesses/corporations/fatca-ides-technical-faqs) (E19, E20, E21)

---

## Fonctionnalites

| Fonction | Description |
|----------|-------------|
| **Encrypt** | Signe le XML FATCA (XMLDSig SHA-256/RSA) puis chiffre (AES-256-CBC + RSA PKCS#1 v1.5) et package en ZIP IDES |
| **Decrypt** | Dechiffre les fichiers feedback de l'IRS (ZIP ou payload + key separes) |
| **Sign** | Signature XML seule (sans chiffrement) |
| **Info** | Affiche les informations d'un certificat ou d'un fichier XML |

## Cryptographie utilisee

| Etape | Algorithme | Spec IRS |
|-------|-----------|----------|
| Signature XML | RSA-SHA256 + Exclusive C14N 1.0 | IDES User Guide Section 9.2 |
| Chiffrement payload | AES-256-CBC + PKCS#7 padding | FAQ E19 |
| Wrapping de cle | RSA PKCS#1 v1.5 (48 octets = AES key 32 + IV 16) | FAQ E21 |
| Format ZIP | `SenderGIIN_Payload` + `ReceiverGIIN_Key` + `SenderGIIN_Metadata.xml` | IDES Data Preparation |

---

## Installation

### Pre-requis

- Python 3.12+
- pip

### Installer les dependances

```bash
pip install -r requirements.txt
```

---

## Utilisation

### Option 1 : Executable Windows (.exe)

Telecharger `FATCACrypto.exe` (GUI) ou `fatca-crypto.exe` (CLI) depuis l'onglet **Actions > Artifacts** du repo GitHub.

Double-cliquer sur `FATCACrypto.exe` pour lancer l'interface graphique.

### Option 2 : Interface graphique (GUI) depuis Python

```bash
python launcher_gui.py
```

### Option 3 : Ligne de commande (CLI)

```bash
# Chiffrer un fichier FATCA XML
python launcher_cli.py encrypt \
    --xml report.xml \
    --cert banque.p12 \
    --irs-cert irs_public.pem \
    --output ./output/

# Dechiffrer un feedback IRS (ZIP)
python launcher_cli.py decrypt \
    --payload feedback.zip \
    --cert banque.p12 \
    --output ./decrypted/feedback.xml

# Dechiffrer un feedback IRS (fichiers separes)
python launcher_cli.py decrypt \
    --payload GIIN_Payload \
    --key GIIN_Key \
    --cert banque.p12 \
    --output ./decrypted/feedback.xml

# Signer uniquement
python launcher_cli.py sign \
    --xml report.xml \
    --cert banque.p12 \
    --output signed_report.xml

# Afficher les infos
python launcher_cli.py info --xml report.xml --cert banque.p12
```

---

## Guide de test de la GUI

### Fichiers necessaires

Pour tester, vous aurez besoin de :

1. **Fichier XML FATCA** : un fichier XML conforme au schema FATCA (exemple dans `exepted_result_example/`)
2. **Certificat de la banque** (`.p12` ou `.pem`) : contient la cle privee pour signer et dechiffrer
3. **Certificat public IRS** (`.pem` ou `.crt`) : cle publique de l'IRS pour le wrapping de cle

### Test du chiffrement (onglet Encrypt)

1. Lancer `FATCACrypto.exe` (ou `python launcher_gui.py`)
2. Dans l'onglet **Encrypt** :
   - **FATCA XML file** : selectionner votre fichier XML FATCA
   - **Bank certificate** : selectionner votre certificat `.p12`
   - **Certificate password** : saisir le mot de passe du `.p12`
   - **IRS public certificate** : selectionner le certificat public IRS (`encryption_service_services_irs_gov.crt`)
   - **GIIN** : se remplit automatiquement depuis le XML. Sinon, saisir manuellement (format : `XXXXXX.XXXXX.XX.XXX`)
   - **Output directory** : choisir le dossier de sortie
3. Cliquer **Encrypt & Package**
4. Resultat attendu : un fichier ZIP dans le dossier de sortie contenant :
   - `<SenderGIIN>_Payload` (donnees chiffrees)
   - `000000.00000.TA.840_Key` (cle AES wrappee)
   - `<SenderGIIN>_Metadata.xml` (metadonnees IDES)

### Test du dechiffrement (onglet Decrypt)

1. Aller dans l'onglet **Decrypt**
2. Remplir les champs :
   - **IRS feedback ZIP or payload file** : selectionner le ZIP de feedback IRS (ou le fichier `_Payload` seul)
   - **Wrapped key file** : laisser vide si ZIP, sinon selectionner le fichier `_Key`
   - **Bank certificate** : votre certificat `.p12` (meme que pour le chiffrement)
   - **Certificate password** : mot de passe du `.p12`
   - **Output XML file** : chemin pour le XML dechiffre (ex: `feedback.xml`)
3. Cliquer **Decrypt Feedback**
4. Resultat attendu : un popup avec le statut (`ACCEPTED`, `REJECTED`, `PARTIAL`) et le fichier XML dechiffre

### Test round-trip (chiffrer puis dechiffrer)

Pour valider que le chiffrement fonctionne correctement, vous pouvez :

1. Chiffrer un fichier XML avec l'onglet Encrypt
2. Dechiffrer le ZIP resultant avec l'onglet Decrypt (en utilisant le meme certificat `.p12`)
3. Comparer le XML dechiffre avec l'original : le contenu doit etre identique (avec la signature XML en plus)

> **Note** : Ce test valide uniquement la coherence interne. La validation finale se fait en soumettant le ZIP sur l'environnement de test IDES de l'IRS.

### Erreurs courantes

| Erreur | Cause | Solution |
|--------|-------|----------|
| `GIIN introuvable` | Le GIIN n'est ni dans le certificat ni dans le XML | Saisir le GIIN manuellement dans le champ |
| `RSA key unwrapping failed` | Mauvais certificat pour le dechiffrement | Utiliser le meme certificat que pour le chiffrement |
| `Certificate expired` | Le certificat a expire | Renouveler le certificat |
| `XML syntax error` | Le fichier XML est mal forme | Verifier le fichier XML avec un editeur |

---

## Structure du projet

```
fatca_crypto/
├── fatca_crypto_core/     # Modules cryptographiques
│   ├── certificates.py    # Chargement certificats X.509
│   ├── encryptor.py       # AES-256-CBC + RSA key wrapping
│   ├── decryptor.py       # Dechiffrement feedback IRS
│   ├── signer.py          # Signature XML (XMLDSig)
│   └── packaging.py       # ZIP packaging IDES
├── fatca_utils/           # Utilitaires
│   ├── errors.py          # Exceptions personnalisees
│   ├── security.py        # SecureBytes (nettoyage memoire)
│   └── validators.py      # Validation GIIN, certificats
├── fatca_xml/             # Parsing XML
│   └── parser.py          # Chargement et extraction XML
├── gui.py                 # Interface graphique Tkinter
├── cli.py                 # Interface ligne de commande
├── launcher_gui.py        # Point d'entree GUI (PyInstaller)
├── launcher_cli.py        # Point d'entree CLI (PyInstaller)
├── fatca_crypto_gui.spec  # Config PyInstaller (GUI)
├── fatca_crypto.spec      # Config PyInstaller (CLI)
└── requirements.txt       # Dependances Python
```

---

## Build de l'executable Windows

L'executable est genere automatiquement par GitHub Actions a chaque push sur `main`.

Pour le telecharger :
1. Aller dans l'onglet **Actions** du repo GitHub
2. Cliquer sur le dernier build reussi
3. Telecharger l'artifact **FATCACrypto-GUI-Windows** (ou CLI)

### Build manuel (sur Windows)

```bash
pip install -r requirements.txt
pyinstaller fatca_crypto_gui.spec    # GUI
pyinstaller fatca_crypto.spec        # CLI
```

Les executables sont dans `dist/`.
