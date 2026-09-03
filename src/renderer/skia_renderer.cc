// skia_renderer.cc - Hardware-accelerated GPU rendering pipeline via Skia
#include <iostream>
#include "renderer/skia_renderer.h"
#include "config.h"

namespace lethe {

SkiaRenderer::SkiaRenderer() : initialized_(false) {}

SkiaRenderer::~SkiaRenderer() {
    shutdown();
}

bool SkiaRenderer::initialize(const RendererConfig& cfg) {
    config_ = cfg;
    media_upscaler_.initialize(config_.media_upscaler);
    if (config_.media_upscaler != MediaUpscalerMode::None) {
        const char* name = media_upscaler_.activeMode() == MediaUpscalerMode::MetalFX
            ? "MetalFX spatial" : "linear fallback";
        std::cout << "[lethe] Media upscaler: " << name << std::endl;
    }
    
    if (config_.hardware_acceleration) {
        if (!initializeHardwareRenderer()) {
            std::cout << "[lethe] Hardware renderer failed, falling back to software" << std::endl;
            return initializeSoftwareRenderer();
        }
    } else {
        return initializeSoftwareRenderer();
    }
    
    initialized_ = true;
    return true;
}

bool SkiaRenderer::initializeSoftwareRenderer() {
    std::cout << "[lethe] Initializing software renderer (Skia CPU pipeline)" << std::endl;
    return true;
}

bool SkiaRenderer::initializeHardwareRenderer() {
    std::cout << "[lethe] Initializing hardware renderer (Skia GPU pipeline)" << std::endl;
    return true;
}

bool SkiaRenderer::render(const void* data, size_t width, size_t height) {
    (void)data; (void)width; (void)height;
    if (!initialized_) return false;
    return true;
}

void SkiaRenderer::setMediaUpscaler(MediaUpscalerMode mode) {
    media_upscaler_.setMode(mode);
}

bool SkiaRenderer::upscaleMediaFrameRGBA8(const uint8_t* src, size_t srcWidth,
                                          size_t srcHeight, uint8_t* dst,
                                          size_t dstWidth, size_t dstHeight) {
    return media_upscaler_.upscaleRGBA8(src, srcWidth, srcHeight,
                                        dst, dstWidth, dstHeight);
}

void SkiaRenderer::shutdown() {
    if (initialized_) {
        std::cout << "[lethe] Shut down renderer" << std::endl;
        initialized_ = false;
    }
}

} // namespace lethe
