# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec — builds both Oyster artifacts on macOS or Windows.

  * oyster      — one-file CLI binary  (cli/scan.py)
  * Oyster      — windowed desktop app (ui/app.py); a .app bundle on macOS

Build with:  pyinstaller packaging/oyster.spec    (or: python packaging/build.py)

Notes baked in here:
  * `rules/` is bundled at the bundle root so the EICAR/YARA rules load — the
    code resolves them via Path(__file__).parent.parent / "rules".
  * libmagic (for python-magic) is bundled *only if found* on the build host.
    Without it the scanner falls back to extension-based typing, so it's
    optional. ClamAV and Ollama are external programs and are NEVER bundled.
"""
import ctypes.util
import os
import sys

ROOT = os.path.abspath(os.path.join(SPECPATH, os.pardir))  # repo root
IS_WIN = sys.platform.startswith("win")
IS_MAC = sys.platform == "darwin"

# --- bundle the YARA rules directory ----------------------------------------
datas = [(os.path.join(ROOT, "rules"), "rules")]

# --- best-effort: locate and bundle libmagic --------------------------------
binaries = []
_lib = ctypes.util.find_library("magic")
if _lib:
    src = _lib if os.path.isabs(_lib) else None
    if not src:
        for cand in (
            "/opt/homebrew/lib/libmagic.dylib",
            "/usr/local/lib/libmagic.dylib",
            "/usr/lib/libmagic.dylib",
        ):
            if os.path.exists(cand):
                src = cand
                break
    if src and os.path.exists(src):
        binaries.append((src, "."))
        # libmagic needs its compiled magic database too
        for mgc in (
            "/opt/homebrew/share/misc/magic.mgc",
            "/usr/local/share/misc/magic.mgc",
            "/usr/share/misc/magic.mgc",
        ):
            if os.path.exists(mgc):
                datas.append((mgc, "."))
                break

hiddenimports = ["psutil"]

cli_a = Analysis(
    [os.path.join(SPECPATH, "entry_cli.py")],
    pathex=[ROOT],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    noarchive=False,
)
cli_pyz = PYZ(cli_a.pure)
cli_exe = EXE(
    cli_pyz, cli_a.scripts, cli_a.binaries, cli_a.datas, [],
    name="oyster",
    console=True,
    onefile=True,
    upx=False,
)

# CustomTkinter ships JSON themes + bundled fonts as package data, and pulls in
# darkdetect — collect_all grabs all of it so the frozen GUI renders correctly.
from PyInstaller.utils.hooks import collect_all
_ctk_datas, _ctk_bins, _ctk_hidden = collect_all("customtkinter")

# Lucide PNG icons live in ui/assets; iconset.py loads them from <bundle>/ui_assets
_icon_datas = [(os.path.join(ROOT, "ui", "assets"), "ui_assets")]

ui_a = Analysis(
    [os.path.join(SPECPATH, "entry_ui.py")],
    pathex=[ROOT],
    binaries=binaries + _ctk_bins,
    datas=datas + _ctk_datas + _icon_datas,
    hiddenimports=hiddenimports + ["tkinter", "darkdetect", "PIL"] + _ctk_hidden,
    noarchive=False,
)
ui_pyz = PYZ(ui_a.pure)

if IS_MAC:
    # onedir → proper .app bundle (Apple's security model dislikes onefile GUIs)
    ui_exe = EXE(
        ui_pyz, ui_a.scripts, [],
        exclude_binaries=True,
        name="oyster-gui",
        console=False,
        upx=False,
    )
    ui_coll = COLLECT(
        ui_exe, ui_a.binaries, ui_a.datas,
        name="oyster-gui", upx=False,
    )
    app = BUNDLE(
        ui_coll,
        name="Oyster.app",
        icon=os.path.join(ROOT, "branding", "Oyster.icns"),
        bundle_identifier="com.oyster.antivirus",
        info_plist={
            "NSHighResolutionCapable": True,
            "LSMinimumSystemVersion": "11.0",
            "CFBundleName": "Oyster",
            "CFBundleDisplayName": "Oyster",
        },
    )
else:
    # Windows/Linux: a single windowed executable.
    # NOTE: name must differ from the CLI's "oyster" by more than case — macOS
    # and Windows filesystems are case-insensitive, so "Oyster" would clobber it.
    ui_exe = EXE(
        ui_pyz, ui_a.scripts, ui_a.binaries, ui_a.datas, [],
        name="oyster-gui",
        console=False,          # windowed — no terminal pops up
        onefile=True,
        upx=False,
        icon=os.path.join(ROOT, "branding", "oyster.ico"),
    )
