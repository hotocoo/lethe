#!/bin/bash -euo pipefail
# fetch_cef.sh - populate third_party/cef/ with the pinned CEF binary dist.
#
# The CEF shell (lethe-cef, the Blink engine) builds against a prebuilt
# Chromium Embedded Framework distribution. This script downloads the pinned
# version for the host platform and unpacks it into third_party/cef/ with the
# layout the root CMakeLists expects (include/, libcef_dll/, Release/).
#
# Pin rationale (2026-08-29): CEF 151 carries upstream cef#4001 - the
# browser-info handshake race that leaves every frame in a NEW renderer
# process without browser info (proposed fix declined upstream; reproduces
# 100% on M4 Max). CEF 135 predates the regression and loads real pages
# through the policy proxy. Revisit when a release ships the fix.
#
# Usage: scripts/fetch_cef.sh

cd "$(dirname "$0")/.."

CEF_VERSION="135.0.22+g442c600+chromium-135.0.7049.115"

case "$(uname -s)-$(uname -m)" in
    Darwin-arm64) PLATFORM="macosarm64" ;;
    Darwin-x86_64) PLATFORM="macosx64" ;;
    Linux-x86_64) PLATFORM="linux64" ;;
    Linux-aarch64) PLATFORM="linuxarm64" ;;
    *) echo "unsupported platform" >&2; exit 1 ;;
esac

# The CEF builds CDN URL-encodes the '+' signs in the version.
ENCODED=${CEF_VERSION//+/%2B}
URL="https://cef-builds.spotifycdn.com/cef_binary_${ENCODED}_${PLATFORM}_minimal.tar.bz2"

DEST="third_party/cef"
if [ -f "$DEST/include/cef_version.h" ] &&
   grep -q "$CEF_VERSION" "$DEST/include/cef_version.h"; then
    echo "[fetch_cef] $DEST already has $CEF_VERSION"
    exit 0
fi

echo "[fetch_cef] downloading $URL"
mkdir -p "$DEST.tmp"
curl -L --retry 5 --retry-delay 2 -C - -o "$DEST.tmp/cef.tar.bz2" "$URL"

echo "[fetch_cef] unpacking"
tar -xjf "$DEST.tmp/cef.tar.bz2" -C "$DEST.tmp" --strip-components=1
rm -rf "$DEST"
mv "$DEST.tmp" "$DEST"
rm -f "$DEST/cef.tar.bz2"

echo "[fetch_cef] installed CEF $CEF_VERSION into $DEST"
