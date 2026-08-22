#ifndef LETHE_CORE_ENGINE_H
#define LETHE_CORE_ENGINE_H

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include "config.h"
#include "browser/tab_manager.h"
#include "renderer/skia_renderer.h"
#include "network/http_client.h"
#include "network/udp_transport.h"
#include "network/vpn/vpn_tunnel.h"
#include "network/vpn/vpn_config.h"
#include "browser/navigation_history.h"

namespace lethe {

struct Config {
    bool sandboxEnabled = true;
    bool incognitoMode = true;
    std::string dnsProvider = "https://cloudflare-dns.com/dns-query";
    // Optional PEM bundle of extra trust anchors for TLS verification
    // (empty = system default store). Verification stays ON regardless.
    std::string caBundlePath = "";
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
    // Periodic VPN upkeep: rekeys before session expiry, retries failed
    // handshakes (throttled), and sends keepalives to hold NAT mappings.
    // Call regularly from the application event loop (or status polling).
    void pumpVpnMaintenance();

private:
    void apply_sandbox();
    void init_security_policies();
    void init_network_stack();
    void init_renderer();
    void init_browser_state();
    void init_vpn();
    // Real handshake over the engine's UDP transport.
    bool performVpnHandshake();
    // One encrypted keepalive datagram to the endpoint.
    void sendVpnKeepalive();
    // Steady-clock milliseconds since process start (for maintenance).
    uint64_t nowMs() const;

    Config config_;
    std::unique_ptr<TabManager> tabManager_;
    std::unique_ptr<SkiaRenderer> skia_renderer_;
    std::unique_ptr<HttpClient> httpClient_;
    std::unique_ptr<NavigationHistory> history_;
    std::unique_ptr<vpn::VpnTunnel> vpnTunnel_;
    std::unique_ptr<UdpTransport> vpnTransport_;
    uint64_t lastHandshakeAttemptMs_ = 0;
    uint64_t lastKeepaliveMs_ = 0;
    bool running_ = false;
};

} // namespace lethe

#endif // LETHE_CORE_ENGINE_H