# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

from PyInstaller.utils.hooks import collect_all

try:
    _spec_dir = Path(SPECPATH).resolve()
except NameError:
    _spec_dir = Path(SPEC).resolve().parent

ROOT = _spec_dir.parent

block_cipher = None

datas = []
binaries = []
hiddenimports = [
    'gmp_bootstrap',
    'gmpy2',
    'phe',
    'phe.paillier',
    'phe.util',
    'pairing_context',
    'pairing_proxy_access',
    'preprocessing',
    'queryprocessing',
    'shared',
    'storage',
    'keys',
]

for pkg in ('numpy', 'phe'):
    ds, bs, hi = collect_all(pkg)
    datas += ds
    binaries += bs
    hiddenimports += hi

a = Analysis(
    [str(ROOT / 'main.py')],
    pathex=[str(ROOT)],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='spk-runner',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
)
