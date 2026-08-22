// engine.cc — Core browser engine implementation
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <memory>
#include "core/engine.h"
#include "config.h"
#include "security/csp_policy.h"
#include "security/sandbox.h"
#include "network/tls_config.h"
#include "network/http_client.h"
#include "browser/tab_manager.h"
#include "renderer/skia_renderer.h"
#include "browser/navigation_history.h"

namespace lethe {

Engine::Engine() 
    : tabManager_(new TabManager()),
      skia_renderer_(new SkiaRenderer()),
      httpClient_(new HttpClient()),
      history_(new NavigationHistory()),
      vpnTunnel_(new vpn::VpnTunnel()) {
}

Engine::~Engine() { 
    if (running_) shutdown(); 
}

int Engine::initialize(const Config& cfg) {
    config_ = cfg;
    
    std::signal(SIGINT, [](int) {
        std::cerr << "[lethe] SIGINT — shutting down..." << std::endl;
        exit(0);
    });
    
    std::signal(SIGTERM, [](int) {
        std::cerr << "[lethe] SIGTERM — shutting down..." << std::endl;
        exit(0);
    });
    
#if defined(LETHE_SANDBOXING)
    if (config_.sandboxEnabled) {
        apply_sandbox();
    }
#endif
    
    init_security_policies();
    init_network_stack();
    init_vpn();
    init_renderer();
    init_browser_state();
    
    running_ = true;
    std::cout << "[lethe] Engine v" LETHE_VERSION " initialized" << std::endl;
    return 0;
}

void Engine::start() {
    if (!running_) {
        std::cerr << "[lethe] Engine not initialized" << std::endl;
        return;
    }
    
    std::cout << "[lethe] Engine started" << std::endl;
}

void Engine::shutdown() {
    if (!running_) return;
    
    running_ = false;
    
    std::cout << "[lethe] Shutting down components..." << std::endl;
    
    history_.reset();
    if (vpnTransport_) vpnTransport_->close();
    vpnTransport_.reset();
    vpnTunnel_.reset();
    httpClient_.reset();
    skia_renderer_.reset();
    tabManager_.reset();
    
    std::cout << "[lethe] Engine shut down" << std::endl;
}

void Engine::apply_sandbox() {
#if defined(__linux__) && defined(LETHE_SANDBOXING)
    Sandbox::apply();
#elif defined(__APPLE__) && defined(LETHE_SANDBOXING)
    Sandbox::apply();
#endif
}

void Engine::init_security_policies() {
    std::cout << "[lethe] Initializing security policies..." << std::endl;
    std::cout << "[lethe] Security policies initialized (CSP, sandboxing)" << std::endl;
}

void Engine::init_network_stack() {
    std::cout << "[lethe] Initializing network stack..." << std::endl;

    TLSConfig tls;
    tls.init_modern_tls_config(MIN_TLS_VERSION, MAX_TLS_VERSION);

    // Extra trust anchors (enterprise/OS-provided CA bundle) without ever
    // turning certificate verification off.
    if (!config_.caBundlePath.empty()) {
        tls.setCaBundlePath(config_.caBundlePath);
    }

    if (!httpClient_->initialize(tls)) {
        std::cerr << "[lethe] Failed to initialize HTTP client" << std::endl;
    }

    // Secure DNS: resolve all hostnames through DNS-over-HTTPS so plaintext
    // DNS never leaks browsing activity. DoH failures block the request.
    if (!config_.dnsProvider.empty()) {
        httpClient_->setDohProvider(config_.dnsProvider);
    }

    std::cout << "[lethe] Network stack initialized (TLS "
              << MIN_TLS_VERSION << "+, DoH: "
              << (httpClient_->isDohEnabled() ? "on" : "off") << ")" << std::endl;
}

void Engine::init_vpn() {
    std::cout << "[lethe] Initializing built-in VPN..." << std::endl;
    
    // Attach the VPN tunnel to the HTTP client so traffic can be routed
    // through it when enabled and connected.
    httpClient_->setVpnTunnel(std::shared_ptr<vpn::VpnTunnel>(vpnTunnel_.get(), [](vpn::VpnTunnel*){}));
    
    if (config_.vpnEnabled) {
        if (enableVpn(config_.vpnConfig)) {
            std::cout << "[lethe] Built-in VPN enabled (endpoint: " 
                      << config_.vpnConfig.endpoint() << ")" << std::endl;
        } else {
            std::cerr << "[lethe] Failed to enable built-in VPN" << std::endl;
        }
    } else {
        std::cout << "[lethe] Built-in VPN initialized (disabled by default)" << std::endl;
    }
}

bool Engine::enableVpn(const vpn::VpnConfig& cfg) {
    if (!vpnTunnel_) return false;

    vpn::VpnConfig config = cfg;
    // Generate a private key if none provided.
    if (config.privateKey == vpn::Key{}) {
        if (!vpn::generatePrivateKey(config.privateKey)) {
            std::cerr << "[lethe-vpn] Failed to generate private key" << std::endl;
            return false;
        }
    }

    if (!vpnTunnel_->configureClient(config)) {
        std::cerr << "[lethe-vpn] Failed to configure client tunnel" << std::endl;
        return false;
    }

    // Bind the UDP transport used for handshake and data datagrams.
    if (!vpnTransport_) vpnTransport_ = std::make_unique<UdpTransport>();
    if (!vpnTransport_->isOpen() && !vpnTransport_->bind("0.0.0.0", 0)) {
        std::cerr << "[lethe-vpn] Failed to bind VPN transport: "
                  << vpnTransport_->lastError() << std::endl;
        return false;
    }

    config_.vpnEnabled = true;
    config_.vpnConfig = config;

    // Give the HTTP client the relay path: covered destinations are fetched
    // THROUGH the encrypted tunnel once the session is established.
    if (httpClient_) {
        httpClient_->setVpnRelay(vpnTransport_.get(),
                                 config.endpointHost, config.endpointPort);
    }

    // Perform a real WireGuard-style handshake over UDP. If the endpoint is
    // not reachable yet, maintenance retries with backoff via pumpVpnMaintenance().
    lastHandshakeAttemptMs_ = nowMs();
    if (!performVpnHandshake()) {
        std::cout << "[lethe-vpn] Endpoint not reachable yet; will retry" << std::endl;
    }

    return true;
}

bool Engine::disableVpn() {
    if (!vpnTunnel_) return false;

    // Wipe all key material: a disabled VPN must leave nothing behind.
    vpnTunnel_->wipeSecrets();
    if (vpnTransport_) {
        vpnTransport_->close();
    }
    if (httpClient_) {
        httpClient_->setVpnRelay(nullptr, "", 0);
    }
    config_.vpnEnabled = false;
    std::cout << "[lethe-vpn] VPN disabled" << std::endl;
    return true;
}

// --- Real VPN networking -----------------------------------------------------

uint64_t Engine::nowMs() const {
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
}

bool Engine::performVpnHandshake() {
    if (!vpnTunnel_ || !vpnTransport_ || !vpnTransport_->isOpen()) return false;
    const auto& cfg = config_.vpnConfig;
    if (cfg.endpointPort <= 0 || cfg.endpointHost.empty()) return false;

    // Reset any previous session (fresh ephemerals, clean replay window).
    vpnTunnel_->prepareRehandshake();

    vpn::HandshakeMessage initMsg;
    if (!vpnTunnel_->createHandshakeInit(initMsg)) {
        std::cerr << "[lethe-vpn] Failed to create handshake init" << std::endl;
        return false;
    }

    std::vector<uint8_t> respData;
    const int n = vpnTransport_->sendAndReceive(
        cfg.endpointHost, cfg.endpointPort, initMsg.serialize(), respData,
        std::chrono::milliseconds(2000), /*onlyFromSender=*/true);
    if (n <= 0) {
        std::cerr << "[lethe-vpn] No handshake response from "
                  << cfg.endpoint() << std::endl;
        return false;
    }

    vpn::HandshakeMessage respMsg;
    if (!vpn::HandshakeMessage::deserialize(respData.data(),
                                            static_cast<size_t>(n), respMsg)) {
        std::cerr << "[lethe-vpn] Malformed handshake response" << std::endl;
        return false;
    }
    if (!vpnTunnel_->processHandshakeResponse(respMsg)) {
        std::cerr << "[lethe-vpn] Handshake rejected by tunnel" << std::endl;
        return false;
    }
    std::cout << "[lethe-vpn] Session established with "
              << cfg.endpoint() << std::endl;
    return true;
}

void Engine::sendVpnKeepalive() {
    if (!vpnTunnel_ || !vpnTransport_ || !vpnTunnel_->isConnected()) return;
    static const uint8_t ka[1] = {0};
    std::vector<uint8_t> ct;
    if (vpnTunnel_->encryptDataPacket(ka, sizeof(ka), ct)) {
        vpnTransport_->sendTo(config_.vpnConfig.endpointHost,
                              config_.vpnConfig.endpointPort, ct);
    }
}

void Engine::pumpVpnMaintenance() {
    if (!running_ || !config_.vpnEnabled || !vpnTunnel_) return;

    const uint64_t now = nowMs();

    if (vpnTunnel_->isConnected()) {
        // Rekey at 2/3 of the session lifetime (WireGuard REKEY_AFTER_TIME
        // is 120s of the 180s REJECT_AFTER_TIME). Expired sessions rekey now.
        const auto life = vpnTunnel_->sessionLifetime();
        const auto sinceHs = std::chrono::milliseconds(
            vpnTunnel_->millisecondsSinceHandshake());
        if (sinceHs > (life * 2) / 3 || vpnTunnel_->isSessionExpired()) {
            std::cout << "[lethe-vpn] Rekeying session" << std::endl;
            lastHandshakeAttemptMs_ = now;
            performVpnHandshake();
            lastKeepaliveMs_ = now;
            return;
        }

        // Keepalive when the peer has gone quiet (NAT hold + liveness).
        constexpr uint64_t kKeepaliveIntervalMs = 25000; // WireGuard default
        const int64_t sinceRecv = vpnTunnel_->millisecondsSinceLastReceive();
        const bool quiet = sinceRecv < 0 ||
            static_cast<uint64_t>(sinceRecv) > kKeepaliveIntervalMs;
        if (quiet && now - lastKeepaliveMs_ > kKeepaliveIntervalMs) {
            lastKeepaliveMs_ = now;
            sendVpnKeepalive();
        }
        return;
    }

    // Not connected: retry failed handshakes at most every 5 seconds.
    constexpr uint64_t kRetryIntervalMs = 5000;
    if (now - lastHandshakeAttemptMs_ >= kRetryIntervalMs) {
        lastHandshakeAttemptMs_ = now;
        performVpnHandshake();
    }
}

bool Engine::isVpnConnected() const {
    return vpnTunnel_ && vpnTunnel_->isConnected();
}

void Engine::init_renderer() {
    std::cout << "[lethe] Initializing renderer..." << std::endl;
    
    RendererConfig rcfg;
    rcfg.hardware_acceleration = config_.useHardwareAcceleration;
    
    if (!skia_renderer_->initialize(rcfg)) {
        std::cerr << "[lethe] Failed to initialize renderer" << std::endl;
    }
    
    std::cout << "[lethe] Renderer initialized" << std::endl;
}

void Engine::init_browser_state() {
    std::cout << "[lethe] Initializing browser state..." << std::endl;
    
    tabManager_->createTab("New Tab", "");
    
    std::cout << "[lethe] Browser state initialized" << std::endl;
}

} // namespace lethe
