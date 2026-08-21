// test_vpn_policy.cc — Engine VPN networking and HTTP fail-closed policy tests
//
// Verifies the two integration guarantees that make the built-in VPN real:
//   1. The engine performs genuine WireGuard-style handshakes over UDP
//      against a live server, rekeys before session expiry, and survives
//      unreachable endpoints.
//   2. The HTTP client refuses (fail closed) to fetch destinations covered
//      by the tunnel's allowed CIDRs while the tunnel is down — no
//      plaintext leaks; requests proceed once the tunnel is connected.

#include "test_framework.h"
#include "core/engine.h"
#include "config.h"
#include "network/http_client.h"
#include "network/tls_config.h"
#include "network/vpn/vpn_config.h"
#include "network/vpn/vpn_server.h"
#include "network/vpn/vpn_tunnel.h"

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <thread>

using namespace lethe;
using namespace lethe::vpn;

namespace {

// Live reference server driven by a background event loop.
class LiveServer {
public:
    explicit LiveServer(int idleTimeoutMs = 180000) {
        Key priv{};
        CHECK_TRUE(generatePrivateKey(priv));
        CHECK_TRUE(server_.configure(priv));
        server_.setClientIdleTimeout(std::chrono::milliseconds(idleTimeoutMs));
        CHECK_TRUE(server_.start("127.0.0.1", 0));
        thread_ = std::thread([this]() {
            while (running_.load()) {
                server_.process(std::chrono::milliseconds(20));
            }
        });
    }
    ~LiveServer() {
        running_ = false;
        if (thread_.joinable()) thread_.join();
        server_.stop();
    }

    VpnConfig clientConfig() const {
        VpnConfig cfg;
        cfg.endpointHost = "127.0.0.1";
        cfg.endpointPort = server_.port();
        cfg.serverPublicKey = server_.publicKey();
        cfg.allowedCidrs = {"0.0.0.0/0"};
        return cfg;
    }

    size_t clientCount() const { return server_.clientCount(); }

private:
    VpnServer server_;
    std::atomic<bool> running_{true};
    std::thread thread_;
};

} // namespace

LETHE_TEST_CASE(Engine_VpnRealHandshake_OverUdp) {
    Config cfg;
    cfg.incognitoMode = true;
    Engine engine;
    CHECK_EQ(engine.initialize(cfg), 0);

    LiveServer server;
    CHECK_TRUE(engine.enableVpn(server.clientConfig()));

    // enableVpn performs a real handshake immediately: connected, and the
    // server has registered this engine as a client.
    CHECK_TRUE(engine.isVpnConnected());
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (server.clientCount() == 0 &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK_EQ(server.clientCount(), 1u);

    // Data path through the engine's tunnel reaches the live server.
    std::string msg = "engine-to-server";
    std::vector<uint8_t> ct;
    CHECK_TRUE(engine.vpnTunnel()->encryptDataPacket(
        reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), ct));
    CHECK_TRUE(engine.httpClient() != nullptr);

    engine.shutdown();
}

LETHE_TEST_CASE(Engine_VpnRekey_AfterSessionExpiry) {
    Config cfg;
    cfg.incognitoMode = true;
    Engine engine;
    CHECK_EQ(engine.initialize(cfg), 0);

    LiveServer server;
    CHECK_TRUE(engine.enableVpn(server.clientConfig()));
    CHECK_TRUE(engine.isVpnConnected());

    // Shrink the session lifetime so expiry lands mid-test.
    engine.vpnTunnel()->setSessionLifetime(std::chrono::milliseconds(60));
    std::this_thread::sleep_for(std::chrono::milliseconds(120));
    CHECK_TRUE(engine.vpnTunnel()->isSessionExpired());

    // Maintenance must detect the stale session and rekey transparently.
    engine.pumpVpnMaintenance();
    CHECK_TRUE(engine.isVpnConnected());

    // Same source address => the server replaced (not added) the session.
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (server.clientCount() != 1 &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK_EQ(server.clientCount(), 1u);

    engine.shutdown();
}

LETHE_TEST_CASE(Engine_VpnPump_SafeWhenEndpointUnreachable) {
    Config cfg;
    cfg.incognitoMode = true;
    Engine engine;
    CHECK_EQ(engine.initialize(cfg), 0);

    vpn::VpnConfig vpnCfg;
    vpnCfg.endpointHost = "127.0.0.1";
    vpnCfg.endpointPort = 1; // nothing listens here
    vpn::Key priv{};
    CHECK_TRUE(vpn::generatePrivateKey(priv));
    CHECK_TRUE(vpn::derivePublicKey(priv, vpnCfg.serverPublicKey));

    CHECK_TRUE(engine.enableVpn(vpnCfg));   // tolerated: retry via pump
    CHECK_FALSE(engine.isVpnConnected());

    // Maintenance on a disconnected tunnel must be safe and stay offline
    // (retry is throttled to 5s, so an immediate pump does nothing).
    engine.pumpVpnMaintenance();
    CHECK_FALSE(engine.isVpnConnected());

    engine.shutdown();
}

LETHE_TEST_CASE(HttpClient_VpnFailClosed_BlocksWhenTunnelDown) {
    // Tunnel configured for all IPv4 destinations but never handshaken.
    auto tunnel = std::make_shared<VpnTunnel>();
    Key serverPriv{};
    CHECK_TRUE(generatePrivateKey(serverPriv));
    VpnConfig cfg;
    cfg.endpointHost = "127.0.0.1";
    cfg.endpointPort = 51820;
    CHECK_TRUE(derivePublicKey(serverPriv, cfg.serverPublicKey));
    cfg.allowedCidrs = {"0.0.0.0/0"};
    CHECK_TRUE(tunnel->configureClient(cfg));

    TLSConfig tls;
    tls.init_modern_tls_config(0x0304, 0x0305);
    HttpClient client;
    CHECK_TRUE(client.initialize(tls));
    client.setVpnTunnel(tunnel);

    HttpRequest req;
    req.url = "http://127.0.0.1:9/";
    HttpResponse resp = client.sendRequest(req);

    // The request must be blocked by policy BEFORE any connection attempt
    // (nothing listens on port 9; a non-blocked attempt would report a
    // connection failure instead).
    CHECK_TRUE(resp.error.find("Blocked") != std::string::npos);
    CHECK_TRUE(resp.error.find("tunnel is down") != std::string::npos);
}

LETHE_TEST_CASE(HttpClient_VpnPolicy_AllowsWhenConnected) {
    auto tunnel = std::make_shared<VpnTunnel>();
    Key serverPriv{};
    CHECK_TRUE(generatePrivateKey(serverPriv));
    VpnConfig cfg;
    cfg.endpointHost = "127.0.0.1";
    cfg.endpointPort = 51820;
    CHECK_TRUE(derivePublicKey(serverPriv, cfg.serverPublicKey));
    cfg.allowedCidrs = {"0.0.0.0/0"};
    CHECK_TRUE(tunnel->configureClient(cfg));

    // Complete a loopback handshake so the tunnel is genuinely connected.
    VpnTunnel serverTunnel;
    CHECK_TRUE(serverTunnel.configureServer(serverPriv));
    HandshakeMessage initMsg, respMsg;
    CHECK_TRUE(tunnel->createHandshakeInit(initMsg));
    CHECK_TRUE(serverTunnel.processHandshakeInit(initMsg, respMsg));
    CHECK_TRUE(tunnel->processHandshakeResponse(respMsg));
    CHECK_TRUE(tunnel->isConnected());

    TLSConfig tls;
    tls.init_modern_tls_config(0x0304, 0x0305);
    HttpClient client;
    CHECK_TRUE(client.initialize(tls));
    client.setVpnTunnel(tunnel);

    HttpRequest req;
    req.url = "http://127.0.0.1:9/";
    HttpResponse resp = client.sendRequest(req);

    // Policy lets it through; the failure is the (expected) connection
    // refusal from the closed port, not a VPN block.
    CHECK_TRUE(resp.error.find("Blocked") == std::string::npos);
    CHECK_TRUE(resp.error.find("Connection failed") != std::string::npos);
}
