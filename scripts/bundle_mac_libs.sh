#!/usr/bin/env bash
# Bundle every non-system dylib the app needs INTO the .app bundle and
# rewrite all load paths to @rpath, so Lethe runs on machines without
# Homebrew.
#
# Strategy: sweep EVERY Mach-O in the bundle repeatedly until a full sweep
# performs zero rewrites (fixed point). This catches libraries reached only
# through runtime-loaded plugins (gdk-pixbuf loaders), not just the binary's
# static link graph. Ad-hoc re-signing is left to the caller (mandatory on
# Apple Silicon).
#
#   usage: bundle_mac_libs.sh <path-to-Lethe.app>
set -euo pipefail

APP="$1"
MACOS="$APP/Contents/MacOS"
FW="$APP/Contents/Frameworks"
RES="$APP/Contents/Resources"
mkdir -p "$FW"

HB_PREFIX="$(brew --prefix)"   # /opt/homebrew on Apple Silicon

# All Mach-O files we ship: executables + plugins + already-copied dylibs.
all_macho() {
  find "$MACOS" "$RES" -type f \( -perm -111 -o -name '*.so' \) -print
  ls "$FW"/*.dylib 2>/dev/null || true
}

sweep() { # prints number of rewrites performed
  local changes=0 bin dep name dest own_id
  while IFS= read -r bin; do
    [[ -n "$bin" ]] || continue
    # otool -L's first library line is the file's OWN install ID (LC_ID_DYLIB).
    # -change cannot rewrite it (and exits 0 doing nothing); -id must. Fix it
    # here and exclude it from dependency parsing below.
    own_id="$(otool -D "$bin" 2>/dev/null | sed -n 2p || true)"
    if [[ "$own_id" == "$HB_PREFIX"/* || "$own_id" == /usr/local/opt/* ]]; then
      install_name_tool -id "@rpath/$(basename "$own_id")" "$bin"
      [[ "${LETHE_BUNDLE_DEBUG:-0}" = "1" ]] && echo "    id: ${bin#$APP/} :: $own_id" >&2
      changes=$((changes + 1))
      own_id="@rpath/$(basename "$own_id")"
    fi
    while IFS= read -r dep; do
      [[ -n "$own_id" && "$dep" == "$own_id" ]] && continue
      [[ "$dep" == "$HB_PREFIX"/* || "$dep" == /usr/local/opt/* ]] || continue
      name="$(basename "$dep")"
      dest="$FW/$name"
      if [[ ! -f "$dest" ]]; then
        cp -L "$dep" "$dest"
        chmod u+w "$dest"
        install_name_tool -id "@rpath/$name" "$dest" 2>/dev/null || true
      fi
      install_name_tool -change "$dep" "@rpath/$name" "$bin"
      if ! otool -L "$bin" | grep -Fq "@rpath/$name"; then
        echo "error: -change did not take effect: $bin :: $dep" >&2
        exit 1
      fi
      [[ "${LETHE_BUNDLE_DEBUG:-0}" = "1" ]] && echo "    rw: ${bin#$APP/} :: $dep" >&2
      changes=$((changes + 1))
    done < <(otool -L "$bin" | awk 'NR>1 {print $1}' | grep '^/')
  done < <(all_macho)
  echo "$changes"
}

# Fixed point: keep sweeping until nothing changes anymore.
round=0
while :; do
  round=$((round + 1))
  n="$(sweep)"
  echo "[bundle] sweep $round rewrote $n references (Frameworks: $(ls "$FW" | wc -l | tr -d ' ') dylibs)"
  [[ "$n" -eq 0 ]] && break
  [[ "$round" -ge "${LETHE_BUNDLE_MAX_ROUNDS:-20}" ]] && { echo 'error: bundling did not converge' >&2; exit 1; }
done

# rpath on executables and plugins so @rpath resolves to our Frameworks.
while IFS= read -r bin; do
  [[ -n "$bin" ]] || continue
  install_name_tool -add_rpath '@executable_path/../Frameworks' "$bin" 2>/dev/null || true
done < <(find "$MACOS" "$RES" -type f \( -perm -111 -o -name '*.so' \) -print)

echo "[bundle] self-contained: $(ls "$FW" | wc -l | tr -d ' ') dylibs shipped"
