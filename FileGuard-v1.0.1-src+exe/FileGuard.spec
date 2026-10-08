# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置：生成单文件 FileGuard.exe（自带 UAC 管理员清单）。

用法：pyinstaller --noconfirm --clean FileGuard.spec
或直接运行 build.bat
"""
import os

block_cipher = None

HIDDEN = [
    "flask", "flask.json", "flask.json.provider", "flask.sessions",
    "werkzeug", "werkzeug.serving", "werkzeug.routing", "werkzeug.debug",
    "jinja2", "jinja2.ext", "markupsafe", "itsdangerous", "blinker",
    "watchdog", "watchdog.observers", "watchdog.observers.winapi",
    "watchdog.observers.read_directory_changes", "watchdog.utils",
    "win32security", "win32evtlog", "win32file", "win32api", "win32con",
    "win32event", "win32process", "ntsecuritycon", "pywintypes",
    "app", "app.main", "app.audit", "app.web", "app.gui", "app.protector",
    "app.recycle", "app.logger", "app.config", "app.service", "app.paths",
    "app.cli", "app.yamlconf", "app.tray",
    "yaml", "_yaml",
]

EXCLUDES = [
    "matplotlib", "numpy", "pandas", "scipy", "notebook", "IPython",
    "PyQt5", "PyQt6", "PySide2", "PySide6", "wx",
    "tkinter.test", "test",
]

a = Analysis(
    ['run.py'],
    pathex=[os.path.abspath('.')],
    binaries=[],
    datas=[('app/static', 'app/static'), ('assets', 'assets')],
    hiddenimports=HIDDEN,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=EXCLUDES,
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
    name='FileGuard',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,          # 图形界面，不弹黑窗
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,         # 强制以管理员身份运行（审计与 SACL 需要）
    icon='assets/fileguard.ico' if os.path.isfile('assets/fileguard.ico') else None,
)
