#ifndef LETHE_RENDERER_SKIA_RENDERER_H
#define LETHE_RENDERER_SKIA_RENDERER_H

#include "renderer/config.h"
#include "renderer/media_upscaler.h"
#include <memory>
#include <vector>

namespace lethe {

class SkiaRenderer {
public:
    SkiaRenderer();
    ~SkiaRenderer();

    bool initialize(const RendererConfig& cfg);
    void shutdown();
    bool render(const void* data, size_t width, size_t height);

    void setMediaUpscaler(MediaUpscalerMode mode);
    MediaUpscalerMode mediaUpscalerMode() const { return media_upscaler_.activeMode(); }
    bool upscaleMediaFrameRGBA8(const uint8_t* src, size_t srcWidth, size_t srcHeight,
                                uint8_t* dst, size_t dstWidth, size_t dstHeight);
    
    bool isInitialized() const { return initialized_; }
    bool isHardwareAccelerated() const { return config_.hardware_acceleration; }

private:
    bool initializeSoftwareRenderer();
    bool initializeHardwareRenderer();
    
    RendererConfig config_;
    bool initialized_ = false;
    MediaUpscaler media_upscaler_;
};

} // namespace lethe

#endif // LETHE_RENDERER_SKIA_RENDERER_H
