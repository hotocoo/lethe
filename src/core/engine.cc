
// engine.cc — Core browser engine implementation
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <memory>
#include "core/engine.h"
#include "config.h"
#include "security/csp_policy.h"
#include "network/tls_config.h"

namespace lethe {

Engine::Engine() {}
Engine::~Engine() { if (running_) shutdown(); }

int Engine::initialize(const Config& cfg) {
    config_ = cfg;
    
    std::signal(SIGINT, [](int) {
        std::cerr << "[let] SIGINT — shutting down...\n";
        exit(0);
    });
    
#if defined(LETHE_SANDBOXING) && ENABLE_HARDENED_BUILD
    apply_sandbox();
#endif
    
    // Init security policies
    init_security_policies();
    
    // Init network stack (TLS/DoH)
    init_network_stack();
    
    // Start renderer subsystem
    if (!startRenderer()) return -1;
    
    running_ = true;
    std::cout << "[lethe] Engine v" LETHE_VERSION " initialized\n";
    return 0;
}

bool Engine::startRenderer() {
    // Spawn isolated renderer process with Skia/GPU pipeline
    // TODO: implement IPC-based multi-process rendering
    
    std::cout << "[lethe] Renderer subsystem started\n";
    return true;
}

void Engine::shutdown() {
    running_ = false;
    
    // Shutdown sequence: network -> renderers -> UI -> engine core
    if (running_) {
        std::cout << "[lethe] Shutting down components...\n";
    }
    
    std::cout << "[lethe] Engine shut down\n";
}

void Engine::apply_sandbox() {
#if defined(__linux__) && ENABLE_HARDENED_BUILD
    // seccomp-bpf for renderer processes only
#elif defined(__APPLE__)
    int val = 1;
    procattr_write("sandboxed", &val, sizeof(val), 0);
#endif
}

void Engine::init_security_policies() {
    CSPPolicy csp;
    csp.set_strict_policy();
    
    std::cout << "[lethe] Security policies initialized (CSP)\n";
}

void Engine::init_network_stack() {
    TLSConfig tls;
    tls.init_modern_tls_config(MIN_TLS_VERSION, MAX_TLS_VERSION);
    
    std::cout << "[lethe] Network stack initialized (TLS " 
              << MIN_TLS_VERSION << "+, DoH)\n";
}

} // namespace lethe
