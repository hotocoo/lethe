
#include <iostream>
#include "core/engine.h"
#include "security/csp_policy.h"
#include "network/tls_config.h"

int main(int argc, char** argv) {
    std::cout << "Lethe Browser v" LETHE_VERSION "\n";
    
    // Parse args
    lethe::Config cfg;
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--sandbox") {
            cfg.sandboxEnabled = true;
        } else if (std::string(argv[i]) == "--incognito") {
            cfg.incognitoMode = true;
        } else if (std::string(argv[i]) == "--dns-provider") {
            ++i;
            if (i < argc) cfg.dnsProvider = argv[i];
        } else if (!argv[i][0] && argv[i][1] != '-') {
            // Treat as initial URL to load
            cfg.initialUrl = argv[i];
        }
    }
    
    // Initialize engine with config
    lethe::Engine engine;
    int rc = engine.initialize(cfg);
    if (rc != 0) {
        std::cerr << "[lethe] Engine init failed: " << rc << "\n";
        return 1;
    }
    
    // Set strict CSP by default
    lethe::CSPPolicy csp;
    csp.set_strict_policy();
    
    // Apply modern TLS config (TLS 1.2+, strict cipher suites)
    lethe::TLSConfig tls;
    tls.init_modern_tls_config(LETHE_MIN_TLS_VERSION, LETHE_MAX_TLS_VERSION);
    
    // TODO: event loop & UI integration (Qt/SDL/EFL/GTK)
    
    engine.shutdown();
    return 0;
}
