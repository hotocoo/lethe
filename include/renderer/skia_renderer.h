#ifndef LETHE_RENDERER_SKIA_RENDERER_H
#define LETHE_RENDERER_SKIA_RENDERER_H

#include "renderer/config.h"
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
    
    bool isInitialized() const { return initialized_; }
    bool isHardwareAccelerated() const { return config_.hardware_acceleration; }

private:
    bool initializeSoftwareRenderer();
    bool initializeHardwareRenderer();
    
    RendererConfig config_;
    bool initialized_ = false;
};

} // namespace lethe

#endif // LETHE_RENDERER_SKIA_RENDERER_H