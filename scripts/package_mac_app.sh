#!/usr/bin/env bash
# Package the macOS release artifact:
#   build/Lethe.app -> dist/Lethe-<version>-macos-<arch>.dmg
# The produced bundle carries its own OpenSSL runtime (see
# bundle_mac_libs.sh), is ad-hoc signed, and is smoke-tested before the
# DMG is cut. A broken bundle never reaches dist/.
set -euo pipefail
cd "$(dirname "$0")/.."

BUILD_DIR="${1:-build}"
VERSION="$(awk '/project\(lethe VERSION/{gsub(/\)|"/,""); print $3}' CMakeLists.txt)"
ARCH="$(uname -m)"
APP_SRC="$BUILD_DIR/lethe.app"
STAGING="dist/staging"
OUT="dist/Lethe-${VERSION}-macos-${ARCH}.dmg"

[[ -d "$APP_SRC" ]] || { echo "error: $APP_SRC not found; build first" >&2; exit 1; }
rm -rf dist; mkdir -p "$STAGING"
cp -R "$APP_SRC" "$STAGING/Lethe.app"
APP="$STAGING/Lethe.app"
MACOS="$APP/Contents/MacOS"
RES="$APP/Contents/Resources"
mkdir -p "$RES"

# The AppKit shell needs no GTK runtime: only OpenSSL (lethe_core) is
# bundled below. Frameworks (Cocoa/WebKit/Network) come from the OS.
scripts/bundle_mac_libs.sh "$APP"

# Remove build-machine OpenSSL rpaths from shipped Mach-O files. The bundled
# @rpath dependencies must resolve to Contents/Frameworks first; leaving a
# Homebrew rpath ahead of the app-local rpath can make the hardened runtime
# load the host's differently-signed OpenSSL instead of the sealed copy.
while IFS= read -r -d '' macho; do
  if file -b "$macho" | grep -q 'Mach-O'; then
    install_name_tool -delete_rpath /opt/homebrew/opt/openssl@3/lib "$macho" 2>/dev/null || true
    install_name_tool -delete_rpath /usr/local/opt/openssl@3/lib "$macho" 2>/dev/null || true
  fi
done < <(find "$APP" -type f -print0)

# HARD ASSERTION: no shipped Mach-O may reference Homebrew anymore.
# (A smoke test alone cannot catch leaks on the build machine, where the
# old paths still resolve.)
LEAKS=$(find "$APP" -type f \( -perm -111 -o -name '*.so' -o -name '*.dylib' \) \
  -exec sh -c 'otool -L "$1" 2>/dev/null | grep -qE "^\t/opt/homebrew|^\t/usr/local/opt" && echo "$1"' _ {} \; \
  | wc -l | tr -d ' ')
if [[ "$LEAKS" != "0" ]]; then
  echo "error: $LEAKS files still reference Homebrew paths" >&2
  find "$APP" -type f \( -perm -111 -o -name '*.so' -o -name '*.dylib' \) \
    -exec sh -c 'otool -L "$1" 2>/dev/null | grep -qE "^\t/opt/homebrew|^\t/usr/local/opt" && echo "  leak: $1"' _ {} \; >&2
  exit 1
fi
echo "[pkg] self-containment assertion passed"

# Ad-hoc sign every nested Mach-O first, then the bundle. Signing only the
# outer bundle with --deep is insufficient when a copied Homebrew dylib still
# carries its original Team ID: the hardened runtime rejects that dependency
# when the host process has an ad-hoc identity. Re-signing the exact shipped
# files also makes the resulting bundle deterministic and ready for a later
# Developer-ID/notarization pass.
codesign --force --deep --sign - "$APP" 2>&1 | grep -v 'replacing existing signature' || true

# Verify the exact bundle that will enter the DMG.  A successful signing
# command alone is not enough: nested WebKit helpers and copied dylibs must
# also form a valid sealed bundle after dependency rewriting.
if ! codesign --verify --deep --strict --verbose=2 "$APP" >/tmp/lethe-codesign-verify.log 2>&1; then
  echo "error: codesign verification failed" >&2
  cat /tmp/lethe-codesign-verify.log >&2
  exit 1
fi
echo "[pkg] strict code-signature verification passed"

# Smoke test: the binary must start with ONLY bundled libraries.
LOG="/tmp/lethe-dmg-smoke.log"
perl -e 'alarm 8; exec @ARGV' "$MACOS/lethe" --version >"$LOG" 2>&1 || true
if ! grep -q 'Lethe Browser v' "$LOG" || grep -q 'Library not loaded' "$LOG"; then
  echo "BUNDLE_SMOKE_FAIL:"; tail -30 "$LOG"; exit 1
fi
echo "[pkg] bundle smoke test passed (dylibs self-contained)"

# DMG with drag-to-Applications layout.
ln -s /Applications "$STAGING/Applications"
hdiutil create -volname "Lethe $VERSION" -srcfolder "$STAGING" \
  -ov -format UDZO -fs HFS+ "$OUT" >/dev/null
echo "[pkg] wrote $OUT ($(du -h "$OUT" | cut -f1))"
