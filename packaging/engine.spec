# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the Oyster engine sidecar (sidecar/server.py).

Produces a single-file `oyster-engine` binary that the Electron app bundles as
an extra resource and drives over stdio. No UI deps — just the core engine.
"""
import ctypes.util
import os
import sys

ROOT = os.path.abspath(os.path.join(SPECPATH, os.pardir))
IS_WIN = sys.platform.startswith("win")

datas = [(os.path.join(ROOT, "rules"), "rules")]
binaries = []

# best-effort libmagic bundling (optional; scanner falls back without it)
_lib = ctypes.util.find_library("magic")
if _lib and os.path.isabs(_lib):
    binaries.append((_lib, "."))
    for mgc in ("/opt/homebrew/share/misc/magic.mgc",
                "/usr/local/share/misc/magic.mgc",
                "/usr/share/misc/magic.mgc"):
        if os.path.exists(mgc):
            datas.append((mgc, "."))
            break

a = Analysis(
    [os.path.join(ROOT, "sidecar", "server.py")],
    pathex=[ROOT],
    binaries=binaries,
    datas=datas,
    hiddenimports=["psutil"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz, a.scripts, a.binaries, a.datas, [],
    name="oyster-engine",
    console=True,          # headless stdio process; no window
    onefile=True,
    upx=False,
)
