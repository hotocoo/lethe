#include <iostream>
#include "core/engine.h"
#include "core/config.h"
#include "security/csp.h"
#include "browser/state.h"
#include "network/tls_config.h"

int main(int argc, char** argv) {
    std::cout << "Lethe Browser v" LETHE_VERSION "\n";
    
    // Parse config & args
    lethe::Config cfg;
    cfg.parseArgs(argc, argv);
    
    // Initialize engine
    lethe::Engine engine;
    int rc = engine.init(cfg);
    if (rc != 0) {
        std::cerr << "[lethe] Engine init failed: " << rc << "\n";
        return 1;
    }
    
    // Create browser state (tabs/windows)
    lethe::BrowserState bs;
    
    // Apply strict CSP by default
    lethe::CSPPolicy csp;
    csp.setDefaultPolicy();
    
    // Set modern TLS config
    lethe::TLSConfig tls;
    tls.initModernStrict();
    
    // Navigate if URL specified in config
    if (!cfg.urlToLoad.empty()) {
        bs.navigate(1, cfg.urlToLoad);
    }
    
    // TODO: event loop & UI integration (Qt/SDL/EFL/GTK)
    
    engine.shutdown();
    return 0;
}
