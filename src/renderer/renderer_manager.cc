// renderer_manager.cc - Skia/GPU pipeline implementation
#include <iostream>
#include "renderer/renderer_manager.h"

namespace lethe {

bool RendererManager::initialize(const RendererConfig& cfg) {
    config_ = cfg;

#if defined(LETHE_HARDENED_BUILD) && ENABLE_SANDBOXING
    std::cout << "[lethe] Renderer: hardware acceleration enabled\n";
#endif

    if (!config_.hardware_acceleration) {
        return initializeSoftwareRenderer();
    }

    // Initialize GPU pipeline via Skia/ANGLE/Mesa/etc.
    // TODO: platform-specific GPU driver detection and init
    std::cout << "[lethe] Renderer: hardware acceleration enabled\n";
    
    return true;
}

bool RendererManager::initializeSoftwareRenderer() {
    // Fallback to CPU rendering using Skia software pipeline
    std::cout << "[lethe] Renderer: fallback to software renderer\n";
    return true;
}

} // namespace lethe
