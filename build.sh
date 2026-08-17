#!/bin/bash -euo pipefail
set -x

cd "$(dirname "$0")"

echo "[lethe] Building..."

if [ ! -d "build" ]; then
    mkdir build
fi

cd build

cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_HARDENED=${LETHE_HARDENED:1} \
    -DBUILD_WITH_SANDBOX=${LETHE_SANDBOX:1} \
    -G Ninja || cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_HARDENED=${LETHE_HARDENED:1} \
        -DBUILD_WITH_SANDBOX=${LETHE_SANDBOX:1}

if [ -x "$(command -v ninja)" ]; then
    ninja -j$(nproc) lethe || echo "Ninja failed, falling back to make"
else
    make -j$(nproc) lethe
fi

echo "[lethe] Build complete."
