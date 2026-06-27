#!/usr/bin/env bash
# Build the engine + Electron app and install a VALID, launchable Oyster.app.
#
# Two macOS gotchas this handles:
#  1) Copying the app (ditto/cp) re-adds com.apple.FinderInfo / provenance /
#     fileprovider xattrs that make codesign reject the bundle ("resource fork,
#     Finder information, or similar detritus"). So we sign AFTER the copy, in
#     place, having run dot_clean + xattr -cr first.
#  2) A broken signature makes LaunchServices silently refuse to launch the app
#     (it runs from a terminal but not from Finder). A clean --deep ad-hoc sign
#     fixes that; codesign --verify --strict must pass.
#
# For a signature that ALSO survives rebuilds + no Gatekeeper prompt, sign with
# an Apple Developer ID (or finish scripts/selfsign-mac.sh) instead of ad-hoc.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== building engine (onedir) =="
.venv/bin/python -m PyInstaller --noconfirm --clean packaging/engine.spec

echo "== packaging Electron app (dmg) =="
( cd desktop && env -u ELECTRON_RUN_AS_NODE CSC_IDENTITY_AUTO_DISCOVERY=false \
    npm run dist:mac )
SRC="desktop/dist/mac-arm64/Oyster.app"
[ -d "$SRC/Contents/Resources/engine/oyster-engine" ] \
  || { echo "!! engine not bundled — build incomplete"; exit 1; }

echo "== installing to /Applications =="
APP="/Applications/Oyster.app"
pkill -f "Oyster.app" 2>/dev/null || true
sleep 1
rm -rf "$APP"
ditto "$SRC" "$APP"

echo "== signing in place (after the copy) =="
dot_clean -m "$APP" 2>/dev/null || true     # strip resource forks / Finder info
xattr -cr "$APP" 2>/dev/null || true         # strip provenance / fileprovider xattrs
codesign --force --deep --sign - "$APP"
codesign --verify --strict "$APP" && echo "  signature valid ✓"
xattr -dr com.apple.quarantine "$APP" 2>/dev/null || true

echo
echo "Installed /Applications/Oyster.app — launch it from Finder/Launchpad."
echo "Grant Full Disk Access (System Settings → Privacy & Security) for"
echo "whole-computer / private-folder scans; it's optional for targeted scans."
