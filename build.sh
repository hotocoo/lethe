#!/bin/bash -euo pipefail
cd "$(dirname "$0")"

echo "[lethe] Building..."

mkdir -p build
cd build

cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_HARDENED=${LETHE_HARDENED:-1} \
    -DBUILD_WITH_SANDBOX=${LETHE_SANDBOX:-1} \
    -G Ninja || cmake .. \
        -DCMAKE_BUILD_TYPE=Release \
        -DBUILD_HARDENED=${LETHE_HARDENED:-1} \
        -DBUILD_WITH_SANDBOX=${LETHE_SANDBOX:-1}

if [ -x "$(command -v ninja)" ]; then
    ninja -j$(nproc) lethe || make -j$(nproc) lethe
else
    make -j$(nproc) lethe
fi

echo "[lethe] Build complete."
