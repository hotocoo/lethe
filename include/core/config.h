#ifndef LETHE_CORE_CONFIG_H
#define LETHE_CORE_CONFIG_H

#include <string>

namespace lethe {

enum UserAgentMode {
    UA_STANDARD,
    UA_STEALTH,
};

struct Config {
    // Security & sandboxing
    bool sandboxEnabled;
    
    // Privacy
    bool incognitoMode;
    std::string dnsProvider;
    UserAgentMode userAgentMode;
    
    // Initial state
    std::string urlToLoad;
    
    Config();
    
    // Parse command-line arguments
    void parseArgs(int argc, char** argv);
    
    // Get user agent string based on configured mode
    std::string getUserAgent() const;
};

} // namespace lethe

#endif // LETHE_CORE_CONFIG_H
