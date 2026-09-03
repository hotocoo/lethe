#include "renderer/media_upscaler.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <limits>
#include <vector>

#if defined(__APPLE__)
extern "C" bool lethe_metalfx_upscale_rgba8(const uint8_t* src,
                                             size_t srcWidth,
                                             size_t srcHeight,
                                             uint8_t* dst,
                                             size_t dstWidth,
                                             size_t dstHeight);
extern "C" bool lethe_metalfx_available();
#endif

namespace lethe {

namespace {

void linearUpscale(const uint8_t* src, size_t sw, size_t sh,
                   uint8_t* dst, size_t dw, size_t dh) {
    if (!src || !dst || sw == 0 || sh == 0 || dw == 0 || dh == 0) return;
    // Precompute fixed-point coordinates once per axis. This removes the
    // floating-point coordinate math from the pixel hot loop while retaining
    // the same centered bilinear sampling rule and edge clamping.
    constexpr uint32_t kFracBits = 16;
    constexpr uint32_t kOne = 1u << kFracBits;
    struct AxisSample { size_t i0, i1; uint32_t w; };
    std::vector<AxisSample> xs(dw), ys(dh);
    const auto buildAxis = [](size_t srcSize, size_t dstSize,
                              std::vector<AxisSample>& out) {
        const uint64_t scale = (static_cast<uint64_t>(srcSize) << kFracBits) /
                               static_cast<uint64_t>(dstSize);
        const int64_t half = static_cast<int64_t>(kOne >> 1);
        for (size_t d = 0; d < dstSize; ++d) {
            const int64_t pos = static_cast<int64_t>(
                static_cast<uint64_t>(d) * scale + (scale >> 1)) - half;
            const int64_t clamped = std::max<int64_t>(0, pos);
            size_t i0 = static_cast<size_t>(clamped >> kFracBits);
            if (i0 >= srcSize) i0 = srcSize - 1;
            const size_t i1 = std::min(srcSize - 1, i0 + 1);
            uint32_t w = static_cast<uint32_t>(clamped & (kOne - 1));
            if (i0 == i1) w = 0;
            out[d] = {i0, i1, w};
        }
    };
    buildAxis(sw, dw, xs);
    buildAxis(sh, dh, ys);

    for (size_t y = 0; y < dh; ++y) {
        const AxisSample ay = ys[y];
        const uint8_t* row0 = src + ay.i0 * sw * 4;
        const uint8_t* row1 = src + ay.i1 * sw * 4;
        uint8_t* out = dst + y * dw * 4;
        const uint32_t wy = ay.w;
        const uint32_t iy = kOne - wy;
        for (size_t x = 0; x < dw; ++x) {
            const AxisSample ax = xs[x];
            const uint8_t* p00 = row0 + ax.i0 * 4;
            const uint8_t* p10 = row0 + ax.i1 * 4;
            const uint8_t* p01 = row1 + ax.i0 * 4;
            const uint8_t* p11 = row1 + ax.i1 * 4;
            const uint32_t wx = ax.w;
            const uint32_t ix = kOne - wx;
            uint8_t* px = out + x * 4;
            for (int c = 0; c < 4; ++c) {
                const uint32_t top = static_cast<uint32_t>(p00[c]) * ix +
                                     static_cast<uint32_t>(p10[c]) * wx;
                const uint32_t bot = static_cast<uint32_t>(p01[c]) * ix +
                                     static_cast<uint32_t>(p11[c]) * wx;
                const uint64_t value = static_cast<uint64_t>(top) * iy +
                                       static_cast<uint64_t>(bot) * wy;
                px[c] = static_cast<uint8_t>((value + (1ull << 31)) >> 32);
            }
        }
    }
}

} // namespace

MediaUpscaler::MediaUpscaler() = default;

MediaUpscaler::~MediaUpscaler() { shutdown(); }

bool MediaUpscaler::initialize(MediaUpscalerMode mode) {
    requestedMode_ = mode;
    activeMode_ = MediaUpscalerMode::None;
#if defined(__APPLE__)
    if (mode == MediaUpscalerMode::MetalFX && lethe_metalfx_available()) {
        activeMode_ = MediaUpscalerMode::MetalFX;
        return true;
    }
#endif
    if (mode == MediaUpscalerMode::Linear || mode == MediaUpscalerMode::MetalFX) {
        activeMode_ = MediaUpscalerMode::Linear;
        return true;
    }
    return mode == MediaUpscalerMode::None;
}

void MediaUpscaler::shutdown() {
    activeMode_ = MediaUpscalerMode::None;
    requestedMode_ = MediaUpscalerMode::None;
}

void MediaUpscaler::setMode(MediaUpscalerMode mode) { (void)initialize(mode); }

bool MediaUpscaler::upscaleRGBA8(const uint8_t* src, size_t sw, size_t sh,
                                 uint8_t* dst, size_t dw, size_t dh) {
    if (!src || !dst || sw == 0 || sh == 0 || dw == 0 || dh == 0) return false;
    // Keep all byte-count arithmetic overflow-safe and bound the native
    // enhancement API independently of the browser-side canvas guard. The
    // latter protects page-created WebGL resources; this protects callers
    // feeding native RGBA buffers directly into the renderer.
    constexpr size_t kMaxPixels = 64u * 1024u * 1024u;
    if (sw > kMaxPixels / sh || dw > kMaxPixels / dh) return false;
    const size_t srcPixels = sw * sh;
    const size_t dstPixels = dw * dh;
    if (srcPixels > std::numeric_limits<size_t>::max() / 4 ||
        dstPixels > std::numeric_limits<size_t>::max() / 4) return false;
    const size_t srcBytes = srcPixels * 4;
    const size_t dstBytes = dstPixels * 4;

    // The API is intentionally synchronous, and both the CPU fallback and
    // Metal upload/readback assume disjoint buffers. Avoid pointer subtraction
    // (which is only defined for pointers into the same allocation) and use
    // uintptr_t interval arithmetic with explicit overflow guards instead.
    // If either endpoint cannot be represented safely, fail closed.
    const uintptr_t srcBegin = reinterpret_cast<uintptr_t>(src);
    const uintptr_t dstBegin = reinterpret_cast<uintptr_t>(dst);
    if (srcBegin > std::numeric_limits<uintptr_t>::max() - srcBytes ||
        dstBegin > std::numeric_limits<uintptr_t>::max() - dstBytes) return false;
    const uintptr_t srcEnd = srcBegin + srcBytes;
    const uintptr_t dstEnd = dstBegin + dstBytes;
    if (srcBegin < dstEnd && dstBegin < srcEnd) return false;

    if (sw == dw && sh == dh) {
        std::memcpy(dst, src, srcBytes);
        return true;
    }
    if (activeMode_ == MediaUpscalerMode::MetalFX) {
#if defined(__APPLE__)
        if (lethe_metalfx_upscale_rgba8(src, sw, sh, dst, dw, dh)) return true;
#endif
        linearUpscale(src, sw, sh, dst, dw, dh);
        return true;
    }
    if (activeMode_ == MediaUpscalerMode::Linear) {
        linearUpscale(src, sw, sh, dst, dw, dh);
        return true;
    }
    return false;
}

} // namespace lethe
