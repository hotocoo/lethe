#include "test_framework.h"
#include "renderer/media_upscaler.h"

#include <cstdint>
#include <limits>
#include <vector>

LETHE_TEST_CASE(media_upscaler_linear_scales_rgba_frame) {
    lethe::MediaUpscaler scaler;
    CHECK(scaler.initialize(lethe::MediaUpscalerMode::Linear));

    const std::vector<uint8_t> src = {
        255, 0, 0, 255,   0, 255, 0, 255,
        0, 0, 255, 255,   255, 255, 255, 255,
    };
    std::vector<uint8_t> dst(4 * 4 * 4, 0);
    CHECK(scaler.upscaleRGBA8(src.data(), 2, 2, dst.data(), 4, 4));
    CHECK_EQ(dst.size(), static_cast<size_t>(64));
    CHECK_EQ(dst[3], static_cast<uint8_t>(255));
}

LETHE_TEST_CASE(media_upscaler_metalfx_or_fallback_scales_rgba_frame) {
    lethe::MediaUpscaler scaler;
    CHECK(scaler.initialize(lethe::MediaUpscalerMode::MetalFX));

    const std::vector<uint8_t> src(8 * 8 * 4, 127);
    std::vector<uint8_t> dst(16 * 16 * 4, 0);
    CHECK(scaler.upscaleRGBA8(src.data(), 8, 8, dst.data(), 16, 16));
    CHECK_EQ(dst.size(), static_cast<size_t>(1024));
}

LETHE_TEST_CASE(media_upscaler_rejects_overflowing_dimensions) {
    lethe::MediaUpscaler scaler;
    CHECK(scaler.initialize(lethe::MediaUpscalerMode::Linear));

    const uint8_t pixel[4] = {0, 0, 0, 255};
    uint8_t output[4] = {0, 0, 0, 0};
    const size_t huge = std::numeric_limits<size_t>::max();
    CHECK(!scaler.upscaleRGBA8(pixel, huge, 2, output, 1, 1));
    CHECK(!scaler.upscaleRGBA8(pixel, 1, 1, output, huge, 2));
}
