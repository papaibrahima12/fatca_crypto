# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for FATCA Crypto Utility — GUI mode.

Build:
    pyinstaller fatca_crypto_gui.spec

Produces:
    dist/FATCACrypto  (single-file executable, launches GUI by default)
"""

a = Analysis(
    ['launcher_gui.py'],
    pathex=['.'],
    binaries=[],
    datas=[],
    hiddenimports=[
        'gui',
        'cli',
        'fatca_crypto_core',
        'fatca_crypto_core.certificates',
        'fatca_crypto_core.encryptor',
        'fatca_crypto_core.decryptor',
        'fatca_crypto_core.signer',
        'fatca_crypto_core.packaging',
        'fatca_utils',
        'fatca_utils.errors',
        'fatca_utils.security',
        'fatca_utils.validators',
        'fatca_xml',
        'fatca_xml.parser',
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
        'tkinter',
        'tkinter.filedialog',
        'tkinter.messagebox',
        'tkinter.ttk',
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
    name='FATCACrypto',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,        # No terminal window — GUI only
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
