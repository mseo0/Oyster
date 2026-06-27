#!/usr/bin/env python3
"""One command to package Oyster into native executables.

    python packaging/build.py            # build CLI binary + UI app
    python packaging/build.py --installer  # also wrap into .pkg (mac) / note (win)

Run this with the SAME Python you use for Oyster (e.g. .venv/bin/python on
macOS, .venv\\Scripts\\python.exe on Windows). PyInstaller cannot cross-compile,
so build the macOS artifacts on a Mac and the Windows .exe on Windows.

Outputs land in  dist/ :
    dist/oyster        (macOS/Linux)   |  dist/oyster.exe   (Windows)  — CLI
    dist/Oyster.app    (macOS)         |  dist/Oyster.exe   (Windows)  — UI
"""
from __future__ import annotations

import argparse
import platform
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "packaging" / "oyster.spec"


def _run(cmd: list[str]) -> None:
    print("  $", " ".join(cmd))
    subprocess.run(cmd, check=True, cwd=ROOT)


def ensure_pyinstaller() -> None:
    try:
        import PyInstaller  # noqa: F401
    except ImportError:
        print(".. installing PyInstaller into the current environment")
        _run([sys.executable, "-m", "pip", "install", "pyinstaller"])


def build() -> None:
    ensure_pyinstaller()
    print(f".. building from {SPEC.relative_to(ROOT)} on {platform.system()}")
    _run([sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean", str(SPEC)])


def make_installer() -> None:
    dist = ROOT / "dist"
    if sys.platform == "darwin":
        app = dist / "Oyster.app"
        if not app.exists():
            print("!! Oyster.app not found; skipping .pkg")
            return
        pkg = dist / "Oyster.pkg"
        if not shutil.which("productbuild"):
            print("!! productbuild not found (need Xcode command line tools)")
            return
        _run([
            "productbuild", "--component", str(app), "/Applications",
            str(pkg),
        ])
        print(f"++ unsigned installer: {pkg.relative_to(ROOT)}")
        print("   To distribute outside your machine you must codesign + "
              "notarize with an Apple Developer ID.")
    elif sys.platform.startswith("win"):
        print("++ dist/Oyster.exe and dist/oyster.exe are ready.")
        print("   For a real installer, feed dist/ to Inno Setup "
              "(https://jrsoftware.org/isinfo.php) or WiX, then sign with "
              "signtool.exe.")
    else:
        print("++ Linux binaries built; no native installer step wired up.")


def main() -> int:
    ap = argparse.ArgumentParser(description="Package Oyster as native executables")
    ap.add_argument("--installer", action="store_true",
                    help="also wrap the UI app into a platform installer")
    args = ap.parse_args()

    build()
    print("\n== built ==")
    for p in sorted((ROOT / "dist").iterdir()):
        print("   dist/" + p.name)

    if args.installer:
        print("\n== installer ==")
        make_installer()

    print("\nReminder: ClamAV and Ollama are separate installs — Oyster shells "
          "out to them and they are not bundled.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
