#!/bin/bash -euo pipefail
# build.sh — Build Lethe browser
#
# Builds the Lethe core library, GUI application (if UI framework available),
# and test suite.

cd "$(dirname "$0")"

# Add Homebrew Cellar bin directories to PATH for cmake/ninja if not found.
add_cellar_bins() {
    local tool="$1"
    if ! command -v "$tool" &> /dev/null; then
        local cellar_path
        cellar_path=$(ls -d /opt/homebrew/Cellar/$tool/*/bin 2>/dev/null | head -1)
        if [ -n "$cellar_path" ]; then
            export PATH="$cellar_path:$PATH"
        fi
    fi
}

add_cellar_bins cmake
add_cellar_bins ninja

echo "[lethe] Building..."

# Detect build tool.
if command -v ninja &> /dev/null; then
    BUILD_TOOL="-G Ninja"
    BUILD_CMD="ninja"
else
    BUILD_CMD="make"
fi

mkdir -p build
cd build

cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_HARDENED=${LETHE_HARDENED:-1} \
    -DBUILD_WITH_SANDBOX=${LETHE_SANDBOX:-1} \
    $BUILD_TOOL

# Determine CPU count.
if command -v nproc &> /dev/null; then
    CPUS=$(nproc)
elif command -v sysctl &> /dev/null; then
    CPUS=$(sysctl -n hw.ncpu)
else
    CPUS=4
fi

$BUILD_CMD -j"$CPUS" lethe_core lethe_tests

if [ -x "$(command -v ninja)" ]; then
    # Also build the GUI app if it was configured.
    $BUILD_CMD -j"$CPUS" lethe 2>/dev/null || echo "[lethe] GUI app not built (no UI framework)"
else
    make -j"$CPUS" lethe 2>/dev/null || echo "[lethe] GUI app not built (no UI framework)"
fi

echo "[lethe] Build complete."

# Run tests if available.
if [ -f "./lethe_tests" ] || [ -f "./lethe_tests.app/Contents/MacOS/lethe_tests" ]; then
    echo "[lethe] Running tests..."
    ./lethe_tests || exit 1
fi

