#!/usr/bin/env bash
# Package the Linux release artifact:
#   <build-dir>/bin-style targets -> dist/lethe-<version>-linux-<arch>[.<id>].tar.gz
# Layout inside the tarball:
#   lethe-<version>/bin/{lethe,lethe-vpn-server,lethe-vpn-e2e-client}
#   lethe-<version>/{README.md,LICENSE}
set -euo pipefail
cd "$(dirname "$0")/.."

BUILD_DIR="${1:-build-linux}"
DIST_ID="${2:-}"
VERSION="$(awk '/project\(lethe VERSION/{gsub(/\)|"/,""); print $3}' CMakeLists.txt)"
ARCH="$(uname -m)"
NAME="lethe-${VERSION}-linux-${ARCH}${DIST_ID:+-$DIST_ID}"
STAGE="dist/$NAME"

for b in lethe lethe-vpn-server lethe-vpn-e2e-client; do
  [[ -f "$BUILD_DIR/$b" ]] || { echo "error: $BUILD_DIR/$b missing" >&2; exit 1; }
done
mkdir -p "$STAGE/bin"
install -m755 "$BUILD_DIR/lethe" "$STAGE/bin/lethe"
install -m755 "$BUILD_DIR/lethe-vpn-server" "$STAGE/bin/lethe-vpn-server"
install -m755 "$BUILD_DIR/lethe-vpn-e2e-client" "$STAGE/bin/lethe-vpn-e2e-client"
install -m644 README.md LICENSE "$STAGE/"
tar czf "dist/$NAME.tar.gz" -C dist "$NAME"
rm -rf "$STAGE"
echo "[pkg] wrote dist/$NAME.tar.gz ($(du -h "dist/$NAME.tar.gz" | cut -f1))"
