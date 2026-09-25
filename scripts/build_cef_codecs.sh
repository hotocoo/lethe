#!/bin/bash -euo pipefail
# build_cef_codecs.sh - build CEF from source with proprietary codecs.
#
# The prebuilt CEF distribution (scripts/fetch_cef.sh) is compiled with
# proprietary_codecs=false, so the Blink shell cannot decode H.264, HEVC,
# AAC or ALAC. `tools/bench/bench.mjs --suite media` measures this: the
# prebuilt lethe-cef answers "no" to canPlayType/MSE for all four, while
# Chrome and the WebKit shell play them. The only fix is a source build with
# the codec GN flags below. This script drives CEF's own automate-git.py.
#
# Cost: roughly 100-150 GB of disk (shallow: no Chromium git history) and several hours on Apple Silicon.
# Licensing: shipping H.264/HEVC/AAC decoders can require patent licenses
# in some jurisdictions. Check before you distribute the resulting build.
#
# Usage:
#   scripts/build_cef_codecs.sh [download-dir]
# then re-run cmake with -DCEF_ROOT=<printed distrib path>, or copy that
# distribution over third_party/cef/.

cd "$(dirname "$0")/.."

# Keep this in step with CEF_VERSION in scripts/fetch_cef.sh.
CEF_BRANCH="${CEF_BRANCH:-7922}"
CEF_COMMIT="${CEF_COMMIT:-2384915}"
WORK="${1:-$HOME/cef-src}"

case "$(uname -m)" in
    arm64) ARCH_FLAG="--arm64-build" ;;
    x86_64) ARCH_FLAG="--x64-build" ;;
    *) echo "unsupported arch" >&2; exit 1 ;;
esac

free_gb=$(df -g "$(dirname "$WORK")" | awk 'NR==2 {print $4}')
if [ "${free_gb:-0}" -lt 150 ] && [ -z "${LETHE_CEF_FORCE:-}" ]; then
    echo "[cef-codecs] only ${free_gb} GB free under $(dirname "$WORK"); need ~150 GB." >&2
    echo "[cef-codecs] set LETHE_CEF_FORCE=1 to try anyway." >&2
    exit 1
fi

mkdir -p "$WORK"
if [ ! -f "$WORK/automate-git.py" ]; then
    curl -fsSL -o "$WORK/automate-git.py" \
        "https://raw.githubusercontent.com/chromiumembedded/cef/master/tools/automate/automate-git.py"
fi

# CEF's runhooks.patch only edits the Windows toolchain scripts and does not
# apply cleanly to every Chromium tag; it has no effect on macOS/Linux.
if ! grep -q "LETHE: skip runhooks" "$WORK/automate-git.py"; then
    python3 - "$WORK/automate-git.py" <<'PY'
import sys
p = sys.argv[1]; s = open(p).read()
a = "  apply_patch('runhooks')"
s = s.replace(a, "  if platform != 'windows':  # LETHE: skip runhooks (Windows-only)\n    return\n" + a, 1)
open(p, 'w').write(s)
PY
fi

export GN_DEFINES="is_official_build=true proprietary_codecs=true ffmpeg_branding=Chrome"
export CEF_ARCHIVE_FORMAT=tar.bz2

python3 "$WORK/automate-git.py" \
    --download-dir="$WORK" \
    --branch="$CEF_BRANCH" \
    --checkout="$CEF_COMMIT" \
    --minimal-distrib \
    --client-distrib \
    --no-debug-build \
    --no-chromium-history \
    --force-update \
    --force-build \
    "$ARCH_FLAG"

echo "[cef-codecs] distributions:"
ls -d "$WORK"/chromium/src/cef/binary_distrib/cef_binary_*_minimal 2>/dev/null || true
