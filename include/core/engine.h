#ifndef LETHE_CORE_ENGINE_H
#define LETHE_CORE_ENGINE_H

#include <chrono>
#include <cstdint>
#include <map>
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
#include "security/cert_pinner.h"
#include "security/cookie_jar.h"
#include "security/hsts_cache.h"

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

    // Private-network isolation (SSRF guard): fetches whose RESOLVED
    // destination lands in a non-loopback private scope (RFC1918, CGNAT,
    // link-local/cloud-metadata, IPv6 ULA, embedded-IPv4 wrappers,
    // reserved ranges) fail closed. Loopback stays reachable for local
    // development; trusted intranet names can be re-admitted explicitly.
    bool isolatePrivateNetworks = true;
    std::vector<std::string> privateNetworkAllowedHosts;

    // Certificate pinning: per-host SPKI SHA-256 pins ("sha256-<base64>").
    // A pinned host accepts only TLS chains containing at least one
    // certificate whose SubjectPublicKeyInfo hashes to a listed pin.
    // Additive to certificate verification; enforced on every hop.
    std::map<std::string, std::vector<std::string>> certPins;

    // Built-in VPN. vpnEnabled defaults to TRUE: the engine ships a
    // fail-closed loopback tunnel (no external endpoint) so every byte
    // routes through the policy path even before the user supplies a
    // real WireGuard endpoint. Set LETHE_VPN=0 to disable entirely.
    // No telemetry, no logging of destination hosts: the VPN's only
    // job is to ensure there is no network code path that bypasses
    // Lethe's policy gates.
    bool vpnEnabled = true;
    vpn::VpnConfig vpnConfig;  // endpoint/keys (used when vpnEnabled)
};

// Merge LETHE_* environment variables into \p cfg (see README):
//   LETHE_SANDBOX=0|false|off|no   -> sandboxEnabled=false
//   LETHE_SANDBOX=<anything else>  -> sandboxEnabled=true
//   LETHE_DNS_PROVIDER=<url>       -> DoH provider URL
//   LETHE_DNS_PROVIDER=none|off    -> DoH disabled (empty provider)
//   LETHE_USER_AGENT_MODE=standard|stealth
//   LETHE_PRIVATE_NET_MODE=isolate|open -> private-network SSRF guard
//       (isolate = default; open = legacy unrestricted fetching)
//   LETHE_PRIVATE_NET_ALLOW=a,b,c  -> exact intranet hostnames the guard
//       re-admits despite private-scope answers (case-insensitive)
//   LETHE_CERT_PINS=host1=sha256-A,sha256-B;host2=sha256-C
//       per-host certificate pins (SPKI SHA-256); malformed entries are
//       skipped with a warning - they never silently disable a pin
// Callers apply this BEFORE command-line parsing so explicit arguments win.
void applyEnvironmentOverrides(Config& cfg);

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
    // Shared UDP transport used for tunnel relay exchanges (full-web proxy).
    UdpTransport* vpnTransport() { return vpnTransport_.get(); }
    CookieJar* cookieJar() { return cookieJar_.get(); }
    HstsCache* hstsCache() { return hstsCache_.get(); }
    CertPinner* certPinner() { return certPinner_.get(); }
    
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
    std::unique_ptr<CookieJar> cookieJar_;
    std::unique_ptr<HstsCache> hstsCache_;
    std::unique_ptr<CertPinner> certPinner_;
    std::unique_ptr<UdpTransport> vpnTransport_;
    uint64_t lastHandshakeAttemptMs_ = 0;
    uint64_t lastKeepaliveMs_ = 0;
    bool running_ = false;
};

} // namespace lethe

#endif // LETHE_CORE_ENGINE_H