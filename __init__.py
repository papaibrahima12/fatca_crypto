"""
FATCA Crypto Utility
====================
Standalone encryption/decryption tool for IRS IDES FATCA compliance.

Modules:
    crypto.certificates  - X.509 certificate loading (.p12, .pem)
    crypto.signer        - XML signing (SHA-256 enveloped XMLDSig)
    crypto.encryptor     - AES-256-CBC + RSA key wrapping
    crypto.decryptor     - IRS feedback decryption
    crypto.packaging     - ZIP output packaging
    cli                  - Command-line interface
    gui                  - Optional Tkinter GUI
"""

__version__ = "1.0.0"
__app_name__ = "FATCA Crypto Utility"
