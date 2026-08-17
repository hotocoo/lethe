#ifndef LETHE_CORE_ENGINE_H
#define LETHE_CORE_ENGINE_H

#include <memory>
#include "config.h"
#include "browser/tab_manager.h"
#include "browser/navigation_history.h"

namespace lethe {

struct Config {
    bool sandboxEnabled = true;
    bool incognitoMode = true;
    std::string dnsProvider = "https://cloudflare-dns.com/dns-query";
    std::string userAgentMode = "standard"; // standard|stealth
    std::string initialUrl = "";
};

class Engine {
public:
    Engine();
    ~Engine();
    int initialize(const Config& cfg);
    bool startRenderer();
    void shutdown();

private:
    void apply_sandbox();
    void init_security_policies();
    void init_network_stack();

    Config config_;
    TabManager* tabManager_ = nullptr;
    NavigationHistory* history_ = nullptr;
    bool running_ = false;
};

} // namespace lethe

#endif // LETHE_CORE_ENGINE_H