#ifndef LETHE_RENDERER_RENDERER_MANAGER_H
#define LETHE_RENDERER_RENDERER_MANAGER_H

#include <memory>
#include "config.h"

namespace lethe {

struct RendererConfig {
    bool hardware_acceleration;
    int gpu_device_id; // -1 = auto-detect
};

class RendererManager {
public:
    RendererManager() {}
    
    // Initialize renderer subsystem with GPU acceleration
    bool initialize(const RendererConfig& cfg);
};

} // namespace lethe

#endif // LETHE_RENDERER_RENDERER_MANAGER_H
