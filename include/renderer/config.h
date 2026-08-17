#ifndef LETHE_RENDERER_CONFIG_H
#define LETHE_RENDERER_CONFIG_H

#include <string>
#include <vector>

namespace lethe {

enum class RendererBackend {
    SKIA_GLES,   // GPU via OpenGL ES / ANGLE
    SKIA_SW     // CPU fallback
};

struct RendererConfig {
    bool hardware_acceleration = true;
    int gpu_device_id = -1; // -1 = auto-detect
    
    std::vector<std::string> preferred_backends;
    
    RendererConfig() {
        preferred_backends.push_back("gles");
        preferred_backends.push_back("sw");
    }
};

} // namespace lethe

#endif // LETHE_RENDERER_CONFIG_H
