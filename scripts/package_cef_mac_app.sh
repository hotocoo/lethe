#!/usr/bin/env bash
# Package validated Blink/CEF macOS app:
#   build-cef/lethe-cef.app -> dist/Lethe-<version>-blink-macos-<arch>.dmg
set -euo pipefail
cd "$(dirname "$0")/.."

BUILD_DIR="${1:-build-cef}"
VERSION="$(awk '/project\(lethe VERSION/{gsub(/\)|"/,""); print $3}' CMakeLists.txt)"
ARCH="$(uname -m)"
APP_SRC="$BUILD_DIR/lethe-cef.app"
STAGING="dist/staging-blink"
OUT="dist/Lethe-${VERSION}-blink-macos-${ARCH}.dmg"

[[ -d "$APP_SRC" ]] || { echo "error: $APP_SRC not found; build first" >&2; exit 1; }
rm -rf "$STAGING" "$OUT"
mkdir -p "$STAGING"
cp -R "$APP_SRC" "$STAGING/Lethe-Blink.app"
APP="$STAGING/Lethe-Blink.app"

# Lethe core still links OpenSSL; CEF itself ships its Chromium runtime.
scripts/bundle_mac_libs.sh "$APP"

# No host-specific Homebrew dependency may survive anywhere in nested CEF
# helpers/frameworks. System frameworks and @rpath are allowed.
LEAKS=0
while IFS= read -r -d '' bin; do
  if otool -L "$bin" 2>/dev/null | grep -qE '^\t/opt/homebrew|^\t/usr/local/opt'; then
    echo "error: Homebrew dependency: ${bin#$APP/}" >&2
    otool -L "$bin" >&2
    LEAKS=$((LEAKS + 1))
  fi
done < <(find "$APP" -type f -perm -111 -print0)
[[ "$LEAKS" -eq 0 ]] || exit 1
echo "[pkg-blink] self-containment assertion passed"

codesign --force --deep --sign - "$APP" 2>&1 | grep -v 'replacing existing signature' || true

LOG="/tmp/lethe-blink-dmg-smoke.log"
perl -e 'alarm 8; exec @ARGV' "$APP/Contents/MacOS/lethe-cef" --version >"$LOG" 2>&1 || true
if ! grep -q 'Lethe Browser v' "$LOG" || grep -q 'Library not loaded' "$LOG"; then
  echo "BUNDLE_SMOKE_FAIL:"; tail -30 "$LOG"; exit 1
fi
echo "[pkg-blink] bundle smoke test passed"

ln -s /Applications "$STAGING/Applications"
hdiutil create -volname "Lethe Blink $VERSION" -srcfolder "$STAGING" \
  -ov -format UDZO -fs HFS+ "$OUT" >/dev/null
echo "[pkg-blink] wrote $OUT ($(du -h "$OUT" | cut -f1))"
