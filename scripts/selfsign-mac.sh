#!/usr/bin/env bash
# Create a STABLE self-signed code-signing identity (once) and sign Oyster.app
# with it. macOS TCC keys the Full Disk Access grant to the signing identity, so
# a stable identity makes the grant persist across relaunches AND rebuilds, and
# lets the grant cover the engine subprocess (signed with the same identity).
#
# Ad-hoc signing can't do this (its identity = the binary's cdhash, which
# changes every build). A self-signed cert in a dedicated keychain gives a fixed
# Designated Requirement without needing an Apple Developer account.
#
#   ./scripts/selfsign-mac.sh /path/to/Oyster.app      # ensure identity + sign
#   ./scripts/selfsign-mac.sh                          # just ensure the identity
set -euo pipefail

KC_NAME="oyster-signing.keychain"
KC="$HOME/Library/Keychains/${KC_NAME}-db"
KCPW="oyster-local"
ID="Oyster Local Signing"

ensure_identity() {
  # NB: query the specific keychain WITHOUT -v — a self-signed cert is untrusted
  # by Gatekeeper (CSSMERR_TP_NOT_TRUSTED) so -v hides it, but codesign can still
  # use it and TCC keys on its stable identity. Trust is irrelevant here.
  if [ -f "$KC" ] && security find-identity -p codesigning "$KC" 2>/dev/null \
       | grep -q "$ID"; then
    echo "signing identity '$ID' already present"; return 0
  fi
  echo "creating self-signed signing identity '$ID'…"
  [ -f "$KC" ] || security create-keychain -p "$KCPW" "$KC_NAME"
  security set-keychain-settings "$KC_NAME" || true
  security unlock-keychain -p "$KCPW" "$KC_NAME" || true
  local T; T="$(mktemp -d)"
  cat > "$T/v3.cnf" <<'EOF'
[req]
distinguished_name = dn
x509_extensions = v3
[dn]
[v3]
basicConstraints = critical, CA:false
keyUsage = critical, digitalSignature
extendedKeyUsage = critical, codeSigning
EOF
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$T/key.pem" -out "$T/cert.pem" \
    -subj "/CN=$ID" -config "$T/v3.cnf" 2>/dev/null
  # -legacy + SHA-1 MAC so macOS's Security framework can import the PKCS#12
  # (OpenSSL 3's default MAC algorithm isn't readable by SecKeychainItemImport).
  openssl pkcs12 -export -legacy -macalg sha1 -out "$T/id.p12" \
    -inkey "$T/key.pem" -in "$T/cert.pem" -name "$ID" -passout "pass:$KCPW" 2>/dev/null
  security import "$T/id.p12" -k "$KC" -P "$KCPW" -A -T /usr/bin/codesign
  # allow codesign to use the key without an interactive prompt
  security set-key-partition-list -S apple-tool:,apple:,codesign: \
    -s -k "$KCPW" "$KC" >/dev/null 2>&1 || true
  # put our keychain in the search list (keep the existing ones)
  security list-keychains -d user -s "$KC" \
    $(security list-keychains -d user | sed -e 's/"//g')
  rm -rf "$T"
  echo "identity created."
}

sign_app() {
  local APP="$1"
  # resolve to the cert's SHA-1 hash so signing is unambiguous even if the
  # keychain ends up with more than one cert of the same name.
  local HASH
  HASH="$(security find-identity -p codesigning "$KC" 2>/dev/null \
          | grep "$ID" | head -1 | awk '{print $2}')"
  [ -n "$HASH" ] || { echo "no signing hash"; return 1; }
  echo "signing $APP with $ID ($HASH)…"
  # dot_clean removes resource forks & Finder-info that make codesign reject
  # bundles ("resource fork, Finder information, or similar detritus"); plain
  # `xattr -c` doesn't remove those.
  dot_clean -m "$APP" 2>/dev/null || true
  find "$APP" -exec xattr -c {} \; 2>/dev/null || true
  local S=(codesign --force --timestamp=none --sign "$HASH" --keychain "$KC")
  # inner-out: helper apps, frameworks, the engine, then the outer app
  find "$APP/Contents/Frameworks" -maxdepth 1 -name "*.app" -print0 2>/dev/null \
    | while IFS= read -r -d '' x; do "${S[@]}" "$x"; done
  find "$APP/Contents/Frameworks" -maxdepth 1 -name "*.framework" -print0 2>/dev/null \
    | while IFS= read -r -d '' x; do "${S[@]}" "$x"; done
  local ENG="$APP/Contents/Resources/engine/oyster-engine/oyster-engine"
  [ -f "$ENG" ] && "${S[@]}" "$ENG"
  "${S[@]}" "$APP"
  codesign --verify --strict "$APP" && echo "signed + verified ✓"
}

ensure_identity
[ "${1:-}" ] && sign_app "$1"
