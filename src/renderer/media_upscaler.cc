#include "renderer/media_upscaler.h"

#include <algorithm>
#include <cmath>
#include <cstring>
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
    const double sx = static_cast<double>(sw) / static_cast<double>(dw);
    const double sy = static_cast<double>(sh) / static_cast<double>(dh);
    for (size_t y = 0; y < dh; ++y) {
        const double fy = (static_cast<double>(y) + 0.5) * sy - 0.5;
        const size_t y0 = static_cast<size_t>(std::max(0.0, std::floor(fy)));
        const size_t y1 = std::min(sh - 1, y0 + 1);
        const double wy = std::clamp(fy - std::floor(fy), 0.0, 1.0);
        for (size_t x = 0; x < dw; ++x) {
            const double fx = (static_cast<double>(x) + 0.5) * sx - 0.5;
            const size_t x0 = static_cast<size_t>(std::max(0.0, std::floor(fx)));
            const size_t x1 = std::min(sw - 1, x0 + 1);
            const double wx = std::clamp(fx - std::floor(fx), 0.0, 1.0);
            const uint8_t* p00 = src + (y0 * sw + x0) * 4;
            const uint8_t* p10 = src + (y0 * sw + x1) * 4;
            const uint8_t* p01 = src + (y1 * sw + x0) * 4;
            const uint8_t* p11 = src + (y1 * sw + x1) * 4;
            uint8_t* out = dst + (y * dw + x) * 4;
            for (int c = 0; c < 4; ++c) {
                const double a = p00[c] * (1.0 - wx) + p10[c] * wx;
                const double b = p01[c] * (1.0 - wx) + p11[c] * wx;
                out[c] = static_cast<uint8_t>(std::clamp(std::lround(a * (1.0 - wy) + b * wy), 0L, 255L));
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
    if (sw == dw && sh == dh) {
        std::memcpy(dst, src, sw * sh * 4);
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
