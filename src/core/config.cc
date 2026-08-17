// config.cc — Engine configuration management
#include <cstdlib>
#include "core/config.h"

namespace lethe {

Config::Config() {
    sandboxEnabled = (std::getenv("LETHE_SANDBOX") != nullptr);
    
    const char* dnsEnv = std::getenv("LETHE_DNS_PROVIDER");
    if (dnsEnv) {
        dnsProvider = dnsEnv;
    } else {
        dnsProvider = "https://cloudflare-dns.com";
    }
    
    const char* uaMode = std::getenv("LETHE_USER_AGENT_MODE");
    if (uaMode && std::string(uaMode) == "stealth") {
        userAgentMode = UA_STEALTH;
    } else {
        userAgentMode = UA_STANDARD;
    }
}

void Config::parseArgs(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        std::string arg(argv[i]);
        
        if (arg == "--disable-sandbox") {
            sandboxEnabled = false;
        } else if (arg == "--incognito") {
            incognitoMode = true;
        } else if (arg == "--dns-provider") {
            ++i;
            if (i < argc) dnsProvider = argv[i];
        } else if (arg == "--ua-mode") {
            ++i;
            if (i < argc && std::string(argv[i]) == "stealth")
                userAgentMode = UA_STEALTH;
        } else if (!arg.empty() && arg[0] != '-') {
            // Treat as initial URL to load
            urlToLoad = argv[i];
        }
    }
}

std::string Config::getUserAgent() const {
    switch (userAgentMode) {
        case UA_STEALTH:
            return "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36";
        case UA_STANDARD:
            return LETHE_USER_AGENT;
    }
    return LETHE_USER_AGENT;
}

} // namespace lethe
