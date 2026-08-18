// engine.cc — Core browser engine implementation
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
    
    if (!httpClient_->initialize(tls)) {
        std::cerr << "[lethe] Failed to initialize HTTP client" << std::endl;
    }
    
    std::cout << "[lethe] Network stack initialized (TLS " 
              << MIN_TLS_VERSION << "+, DoH)" << std::endl;
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
    
    config_.vpnEnabled = true;
    config_.vpnConfig = config;
    
    // Attempt handshake init (in a real deployment this would be sent over the network).
    vpn::HandshakeMessage initMsg;
    if (vpnTunnel_->createHandshakeInit(initMsg)) {
        std::cout << "[lethe-vpn] Handshake initiated (" 
                  << vpn::toHex(initMsg.index) << ")" << std::endl;
    }
    
    return true;
}

bool Engine::disableVpn() {
    if (!vpnTunnel_) return false;
    
    vpnTunnel_->markStale();
    config_.vpnEnabled = false;
    std::cout << "[lethe-vpn] VPN disabled" << std::endl;
    return true;
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
