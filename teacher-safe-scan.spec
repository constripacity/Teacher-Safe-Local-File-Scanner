# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for a standalone Teacher-Safe Scanner.

The target user is a teacher on a managed school laptop where Python may not be
installed and `pip` may be blocked by policy. A single downloadable executable is
therefore not a nicety — it is the difference between adoption and zero.

Build:
    pip install -e ".[build]"
    pyinstaller teacher-safe-scan.spec

Produces `dist/teacher-safe-scan` (or `.exe` on Windows). One file, no installer.

NOTE ON SIGNING: the binaries this spec produces are UNSIGNED. On macOS,
Gatekeeper will refuse to run them until they are signed and notarised with an
Apple Developer ID; on Windows, SmartScreen will warn. Do not claim otherwise in
release notes.
"""
import sys

block_cipher = None

# tkinter is optional at runtime: the CLI works without it and prints installation
# guidance if the window is requested. It is bundled when available so the frozen
# build has a GUI.
hidden = ["scanner.gui", "scanner.gui_model"]
try:
    import tkinter  # noqa: F401
except ImportError:
    excluded_gui = ["tkinter", "tkinter.ttk", "tkinter.filedialog", "tkinter.messagebox"]
    hidden = ["scanner.gui_model"]
else:
    excluded_gui = []

a = Analysis(
    ["scanner/__main__.py"],
    pathex=["."],
    binaries=[],
    datas=[("examples/generate_benign_samples.py", "examples")],
    hiddenimports=hidden,
    hookspath=[],
    runtime_hooks=[],
    # Nothing here needs numpy/scipy/PIL; excluding them keeps the binary small
    # enough to download over a school network.
    excludes=[
        "numpy", "scipy", "PIL", "matplotlib", "pandas", "setuptools", "pip",
        "pytest", "IPython", "test", "unittest",
    ] + excluded_gui,
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
    name="teacher-safe-scan",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,          # UPX-packed binaries trip antivirus heuristics, which is
                        # a bad look for a security tool.
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,       # the CLI is the primary interface; `gui` opens a window
    disable_windowed_traceback=False,
    argv_emulation=sys.platform == "darwin",
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
