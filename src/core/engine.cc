// engine.cc — Core engine initialization & lifecycle
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <memory>
#include "config.h"
#include "core/engine.h"

namespace lethe {

Engine::Engine() = default;
Engine::~Engine() = default;

int Engine::init(const Config& cfg) {
    config_ = cfg;
    
    // Install signal handlers for graceful shutdown
    std::signal(SIGINT, [](int) {
        std::cerr << "[lethe] Received SIGINT, shutting down...\n";
        exit(0);
    });
    
    if (!startRenderer()) {
        return -1;
    }
    
    return 0;
}

bool Engine::startRenderer() {
#ifdef LETHE_SANDBOX_ENABLED
    std::cout << "[lethe] Starting renderer with sandbox enabled\n";
#endif
    
    // TODO: Spawn isolated renderer process with seccomp-bpf/pledge
    // For now, inline render loop in main process (TODO: fix!)
    
    return true;
}

void Engine::shutdown() {
    // Graceful shutdown of all components
}

} // namespace lethe
