#!/usr/bin/env bash
# Build, sign, and install Oyster.app to /Applications with a VALID, stable
# signature so a single Full Disk Access grant persists across relaunches.
#
# Why this matters: macOS TCC keys the FDA grant to the app's code signature.
# A broken/ad-hoc-detritus signature won't persist, and copying with `cp -R`
# corrupts it. This script signs cleanly (engine first, then app) and installs
# with `ditto`, which preserves the signature.
#
# For persistence across REBUILDS (and no Gatekeeper prompt), sign with a stable
# identity instead of ad-hoc — see scripts/selfsign-mac.sh or an Apple
# Developer ID. Ad-hoc persists per-build only (the cdhash changes each build).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== building engine (onedir) =="
.venv/bin/python -m PyInstaller --noconfirm --clean packaging/engine.spec

echo "== packaging Electron app =="
cd desktop
env -u ELECTRON_RUN_AS_NODE CSC_IDENTITY_AUTO_DISCOVERY=false npm run dist:mac
APP="dist/mac-arm64/Oyster.app"
ENGINE="$APP/Contents/Resources/engine/oyster-engine/oyster-engine"

echo "== signing (clean, inner-first) =="
xattr -cr "$APP"                       # strip Finder-info/resource-fork detritus
codesign --force --sign - "$ENGINE"    # sign the engine the scanner runs in
codesign --force --deep --sign - "$APP"
codesign --verify --strict "$APP" && echo "  signature valid ✓"

echo "== installing to /Applications =="
pkill -f "Oyster.app" 2>/dev/null || true
sleep 1
rm -rf /Applications/Oyster.app
ditto "$APP" /Applications/Oyster.app  # ditto preserves the signature (cp -R does not)
xattr -cr /Applications/Oyster.app

echo
echo "Installed /Applications/Oyster.app"
echo "Grant Full Disk Access ONCE (System Settings → Privacy & Security →"
echo "Full Disk Access → add Oyster). It now persists across relaunches of this"
echo "build — the engine runs in-process of the app's TCC grant (onedir)."
