#ifndef LETHE_RENDERER_MEDIA_UPSCALER_H
#define LETHE_RENDERER_MEDIA_UPSCALER_H

#include <cstddef>
#include <cstdint>

namespace lethe {

// Spatial scaling modes exposed by the browser settings. MetalFX is the
// preferred macOS implementation; Linear is the portable fallback.
enum class MediaUpscalerMode : int {
    None = 0,
    Linear = 1,
    MetalFX = 2,
};

class MediaUpscaler {
public:
    MediaUpscaler();
    ~MediaUpscaler();

    MediaUpscaler(const MediaUpscaler&) = delete;
    MediaUpscaler& operator=(const MediaUpscaler&) = delete;

    bool initialize(MediaUpscalerMode mode);
    void shutdown();
    void setMode(MediaUpscalerMode mode);

    MediaUpscalerMode requestedMode() const { return requestedMode_; }
    MediaUpscalerMode activeMode() const { return activeMode_; }

    // Scale one tightly-packed RGBA8 frame. The same API is used for still
    // images and video frames, so callers do not need separate media paths.
    // src and dst may not overlap; overlapping buffers are rejected rather
    // than relying on undefined behavior in the GPU upload or memcpy path.
    bool upscaleRGBA8(const uint8_t* src, size_t srcWidth, size_t srcHeight,
                      uint8_t* dst, size_t dstWidth, size_t dstHeight);

private:
    MediaUpscalerMode requestedMode_ = MediaUpscalerMode::None;
    MediaUpscalerMode activeMode_ = MediaUpscalerMode::None;
};

} // namespace lethe

#endif // LETHE_RENDERER_MEDIA_UPSCALER_H
