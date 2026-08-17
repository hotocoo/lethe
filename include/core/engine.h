#ifndef LETHE_CORE_ENGINE_H
#define LETHE_CORE_ENGINE_H

#include "core/config.h"

namespace lethe {

class Engine {
public:
    Engine();
    ~Engine();

    // Initialize engine with given config. Returns 0 on success.
    int init(const Config& cfg);

    // Start the renderer subsystem
    bool startRenderer();

    // Graceful shutdown
    void shutdown();

private:
    Config config_;
};

} // namespace lethe

#endif // LETHE_CORE_ENGINE_H
