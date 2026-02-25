# -*- mode: python ; coding: utf-8 -*-
import os
from pathlib import Path

block_cipher = None

# Locate customtkinter assets so they get bundled
import customtkinter
ctk_path = Path(customtkinter.__file__).parent

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[
        # App assets
        ('sentry/gui/icon.png',    'sentry/gui'),
        ('sentry/gui/icon.ico',    'sentry/gui'),
        ('sentry/gui/rtp_on.png',  'sentry/gui'),
        ('sentry/gui/rtp_off.png', 'sentry/gui'),
        ('sentry/gui/theme.json',  'sentry/gui'),
        ('data/signatures.yaml',   'data'),
        # customtkinter themes and fonts
        (str(ctk_path), 'customtkinter'),
    ],
    hiddenimports=[
        'customtkinter',
        'PIL',
        'PIL.Image',
        'PIL.ImageTk',
        'watchdog.observers',
        'watchdog.observers.polling',
        'watchdog.events',
        'psutil',
        'yaml',
    ],
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
    a.datas,
    [],
    name='Sentry',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon='sentry/gui/icon.ico',
)
