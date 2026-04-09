# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for FATCA Crypto Utility.

Build:
    pyinstaller fatca_crypto.spec

Produces:
    dist/fatca-crypto  (single-file executable)
"""

a = Analysis(
    ['launcher_cli.py'],
    pathex=['.'],
    binaries=[],
    datas=[],
    hiddenimports=[
        'fatca_crypto',
        'fatca_crypto.cli',
        'fatca_crypto.crypto',
        'fatca_crypto.crypto.certificates',
        'fatca_crypto.crypto.encryptor',
        'fatca_crypto.crypto.decryptor',
        'fatca_crypto.crypto.signer',
        'fatca_crypto.crypto.packaging',
        'fatca_crypto.utils',
        'fatca_crypto.utils.errors',
        'fatca_crypto.utils.security',
        'fatca_crypto.utils.validators',
        'fatca_crypto.xml',
        'fatca_crypto.xml.parser',
        'lxml',
        'lxml.etree',
        'lxml._elementpath',
        'cryptography',
        'cryptography.hazmat.primitives',
        'cryptography.hazmat.primitives.ciphers',
        'cryptography.hazmat.primitives.asymmetric',
        'cryptography.hazmat.primitives.serialization',
        'cryptography.hazmat.primitives.serialization.pkcs12',
        'cryptography.x509',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'matplotlib',
        'numpy',
        'pandas',
        'scipy',
        'PIL',
        'tkinter',  # Remove this line if building GUI version
    ],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='fatca-crypto',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
