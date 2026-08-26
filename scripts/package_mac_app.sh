#!/usr/bin/env bash
# Package the macOS release artifact:
#   build/Lethe.app -> dist/Lethe-<version>-macos-<arch>.dmg
# The produced bundle carries its own GTK/OpenSSL runtime (see
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

# Ship the GTK runtime resources: pixbuf loaders (image codecs), the icon
# themes GTK expects, and glib schemas. Link-time deps of all of these get
# rewritten by bundle_mac_libs.sh below.
HB="$(brew --prefix)"
LOADERS_SRC="$HB/lib/gdk-pixbuf-2.0"/2.10.0/loaders
if [[ -d "$LOADERS_SRC" ]]; then
  mkdir -p "$RES/pixbuf-loaders"
  cp -L "$LOADERS_SRC"/*.so "$RES/pixbuf-loaders/"
fi
[[ -x "$HB/bin/gdk-pixbuf-query-loaders" ]] && cp "$HB/bin/gdk-pixbuf-query-loaders" "$MACOS/"
for item in icons/Adwaita icons/hicolor glib-2.0/schemas mime; do
  [[ -e "$HB/share/$item" ]] || continue
  mkdir -p "$RES/share/$(dirname "$item")"
  cp -R "$HB/share/$item" "$RES/share/$item"
done

# Real binary becomes lethe-bin; 'lethe' becomes a launcher that points

# Real binary becomes lethe-bin; 'lethe' becomes a launcher that points
# gdk-pixbuf/glib at the bundled resources before exec'ing it.
mv "$MACOS/lethe" "$MACOS/lethe-bin"
cat > "$MACOS/lethe" <<EOF
#!/bin/bash
HERE="\$(cd "\$(dirname "\$0")" && pwd)"
RES="\$HERE/../Resources"
export XDG_DATA_DIRS="\$RES/share:/usr/share"
export GDK_PIXBUF_MODULEDIR="\$RES/pixbuf-loaders"
CACHE="\$HOME/Library/Caches/Lethe"
mkdir -p "\$CACHE"
if [[ -x "\$HERE/gdk-pixbuf-query-loaders" && -d "\$GDK_PIXBUF_MODULEDIR" ]]; then
  # Regenerate every run: the cache embeds absolute loader paths that are
  # only valid for the current mount point of the app bundle.
  "\$HERE/gdk-pixbuf-query-loaders" "\$GDK_PIXBUF_MODULEDIR" > "\$CACHE/gdk-pixbuf.loaders" 2>/dev/null || true
fi
[[ -f "\$CACHE/gdk-pixbuf.loaders" ]] && export GDK_PIXBUF_MODULE_FILE="\$CACHE/gdk-pixbuf.loaders"
exec "\$HERE/lethe-bin" "\$@"
EOF
chmod +x "$MACOS/lethe"

scripts/bundle_mac_libs.sh "$APP"

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

# Ad-hoc sign everything we modified (required on Apple Silicon).
codesign --force --deep --sign - "$APP" 2>&1 | grep -v 'replacing existing signature' || true

# Smoke test: engine must fully initialize with ONLY bundled libraries.
# Launch through the 'lethe' launcher — that is what users execute — so the
# runtime env (XDG_DATA_DIRS, pixbuf loader cache) is exercised exactly as
# shipped.
LOG="/tmp/lethe-dmg-smoke.log"
perl -e 'alarm 8; exec @ARGV' "$MACOS/lethe" --help >"$LOG" 2>&1 || true
if ! grep -q 'Lethe Browser v' "$LOG" || grep -q 'Library not loaded' "$LOG" || grep -q 'Gtk:ERROR' "$LOG"; then
  echo "BUNDLE_SMOKE_FAIL:"; tail -30 "$LOG"; exit 1
fi
echo "[pkg] bundle smoke test passed (dylibs self-contained)"

# DMG with drag-to-Applications layout.
ln -s /Applications "$STAGING/Applications"
hdiutil create -volname "Lethe $VERSION" -srcfolder "$STAGING" \
  -ov -format UDZO -fs HFS+ "$OUT" >/dev/null
echo "[pkg] wrote $OUT ($(du -h "$OUT" | cut -f1))"
