
#ifndef LETHE_RENDERER_RENDERER_MANAGER_H
#define LETHE_RENDERER_RENDERER_MANAGER_H

#include <memory>
#include "config.h"

namespace lethe {

struct RendererConfig {
    bool hardware_acceleration;
    int gpu_device_id;
};

class RendererManager {
public:
    RendererManager() {}
    bool initialize(const RendererConfig& cfg) {
        return true;
    }
};

} // namespace lethe

#endif
