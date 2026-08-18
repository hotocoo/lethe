#ifndef LETHE_CORE_ENGINE_H
#define LETHE_CORE_ENGINE_H

#include <memory>
#include <string>
#include "config.h"
#include "browser/tab_manager.h"
#include "renderer/skia_renderer.h"
#include "network/http_client.h"
#include "network/vpn/vpn_tunnel.h"
#include "network/vpn/vpn_config.h"
#include "browser/navigation_history.h"

namespace lethe {

struct Config {
    bool sandboxEnabled = true;
    bool incognitoMode = true;
    std::string dnsProvider = "https://cloudflare-dns.com/dns-query";
    std::string userAgentMode = "standard";
    std::string initialUrl = "";
    bool useHardwareAcceleration = true;
    int maxOpenConnections = 128;

    // Built-in VPN
    bool vpnEnabled = false;
    vpn::VpnConfig vpnConfig;  // VPN configuration (used when vpnEnabled)
};

class Engine {
public:
    Engine();
    ~Engine();
    
    int initialize(const Config& cfg);
    void start();
    void shutdown();
    
    // Accessors
    TabManager* tabManager() { return tabManager_.get(); }
    SkiaRenderer* renderer() { return skia_renderer_.get(); }
    HttpClient* httpClient() { return httpClient_.get(); }
    NavigationHistory* history() { return history_.get(); }
    vpn::VpnTunnel* vpnTunnel() { return vpnTunnel_.get(); }
    
    bool isRunning() const { return running_; }
    const Config& config() const { return config_; }

    // Built-in VPN control
    bool enableVpn(const vpn::VpnConfig& cfg);
    bool disableVpn();
    bool isVpnConnected() const;

private:
    void apply_sandbox();
    void init_security_policies();
    void init_network_stack();
    void init_renderer();
    void init_browser_state();
    void init_vpn();
    
    Config config_;
    std::unique_ptr<TabManager> tabManager_;
    std::unique_ptr<SkiaRenderer> skia_renderer_;
    std::unique_ptr<HttpClient> httpClient_;
    std::unique_ptr<NavigationHistory> history_;
    std::unique_ptr<vpn::VpnTunnel> vpnTunnel_;
    bool running_ = false;
};

} // namespace lethe

#endif // LETHE_CORE_ENGINE_H