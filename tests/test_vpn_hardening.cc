// test_vpn_hardening.cc — Security-hardening tests for the built-in VPN
//
// Covers the WireGuard-style protections that make the tunnel safe on a
// hostile network:
//   - explicit wire counter + sliding-window anti-replay (duplicates,
//     reordering, too-old packets)
//   - failed authentication must not move the replay window
//   - session lifetime (REJECT_AFTER_TIME) forces rekey
//   - server DoS hardening: idle eviction, client cap, handshake rate limit

#include "test_framework.h"
#include "network/vpn/vpn_config.h"
#include "network/vpn/vpn_server.h"
#include "network/vpn/vpn_tunnel.h"
#include "network/udp_transport.h"

#include <atomic>
#include <chrono>
#include <string>
#include <thread>
#include <vector>

using namespace lethe;
using namespace lethe::vpn;

namespace {

// Runs server.process() in the background until destroyed. The server is
// event-loop driven: without this, no handshake or data ever gets handled.
struct ServerLoop {
    VpnServer* server;
    std::atomic<bool> running{true};
    std::thread thread;
    explicit ServerLoop(VpnServer* s) : server(s) {
        thread = std::thread([this]() {
            while (running.load()) {
                server->process(std::chrono::milliseconds(20));
            }
        });
    }
    ~ServerLoop() {
        running = false;
        if (thread.joinable()) thread.join();
    }
};

// Complete a WireGuard-style handshake between two in-process tunnels.
void handshakeLoopback(VpnTunnel& client, VpnTunnel& server) {
    Key serverPriv{};
    CHECK_TRUE(generatePrivateKey(serverPriv));
    CHECK_TRUE(server.configureServer(serverPriv));

    VpnConfig config;
    config.endpointHost = "127.0.0.1";
    config.endpointPort = 51820;
    config.serverPublicKey = server.localPublicKey();
    config.allowedCidrs = {"0.0.0.0/0"};
    CHECK_TRUE(client.configureClient(config));

    HandshakeMessage initMsg, respMsg;
    CHECK_TRUE(client.createHandshakeInit(initMsg));
    CHECK_TRUE(server.processHandshakeInit(initMsg, respMsg));
    CHECK_TRUE(client.processHandshakeResponse(respMsg));
    CHECK_TRUE(client.isConnected());
    CHECK_TRUE(server.isConnected());
}

std::vector<uint8_t> packetFromClient(VpnTunnel& client, const std::string& msg) {
    std::vector<uint8_t> ct;
    CHECK_TRUE(client.encryptDataPacket(
        reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), ct));
    return ct;
}

} // namespace

LETHE_TEST_CASE(VpnTunnel_ReplayWindow_DuplicateRejected) {
    VpnTunnel client, server;
    handshakeLoopback(client, server);

    auto p0 = packetFromClient(client, "packet-0");
    auto p1 = packetFromClient(client, "packet-1");
    auto p2 = packetFromClient(client, "packet-2");

    std::vector<uint8_t> pt;
    CHECK_TRUE(server.decryptDataPacket(p0.data(), p0.size(), pt));
    CHECK_TRUE(server.decryptDataPacket(p1.data(), p1.size(), pt));
    CHECK_TRUE(server.decryptDataPacket(p2.data(), p2.size(), pt));

    // Replaying any already-seen packet must fail.
    CHECK_FALSE(server.decryptDataPacket(p1.data(), p1.size(), pt));
    CHECK_FALSE(server.decryptDataPacket(p0.data(), p0.size(), pt));
    CHECK_FALSE(server.decryptDataPacket(p2.data(), p2.size(), pt));
}

LETHE_TEST_CASE(VpnTunnel_ReplayWindow_ReorderedAccepted) {
    VpnTunnel client, server;
    handshakeLoopback(client, server);

    auto p0 = packetFromClient(client, "packet-0");
    auto p1 = packetFromClient(client, "packet-1");
    auto p2 = packetFromClient(client, "packet-2");
    auto p3 = packetFromClient(client, "packet-3");

    // Out-of-order delivery within the window must succeed.
    std::vector<uint8_t> pt;
    CHECK_TRUE(server.decryptDataPacket(p3.data(), p3.size(), pt));
    CHECK_EQ(std::string(pt.begin(), pt.end()), "packet-3");
    CHECK_TRUE(server.decryptDataPacket(p1.data(), p1.size(), pt));
    CHECK_EQ(std::string(pt.begin(), pt.end()), "packet-1");
    CHECK_TRUE(server.decryptDataPacket(p2.data(), p2.size(), pt));
    CHECK_TRUE(server.decryptDataPacket(p0.data(), p0.size(), pt));
}

LETHE_TEST_CASE(VpnTunnel_ReplayWindow_TooOldRejected) {
    VpnTunnel client, server;
    handshakeLoopback(client, server);

    // Push more than a full window (2048) of packets through.
    std::vector<std::vector<uint8_t>> packets;
    constexpr size_t COUNT = 2100;
    for (size_t i = 0; i < COUNT; i++) {
        packets.push_back(packetFromClient(client, "p" + std::to_string(i)));
    }
    std::vector<uint8_t> pt;
    for (size_t i = 0; i < COUNT; i++) {
        CHECK_TRUE(server.decryptDataPacket(packets[i].data(), packets[i].size(), pt));
    }

    // The very first packet is now far outside the window: rejected.
    CHECK_FALSE(server.decryptDataPacket(packets[0].data(), packets[0].size(), pt));
    // A recent duplicate is rejected too (seen within the window).
    CHECK_FALSE(server.decryptDataPacket(packets[COUNT - 2].data(),
                                         packets[COUNT - 2].size(), pt));
    // A genuinely new packet still passes.
    auto fresh = packetFromClient(client, "after-window");
    CHECK_TRUE(server.decryptDataPacket(fresh.data(), fresh.size(), pt));
}

LETHE_TEST_CASE(VpnTunnel_ReplayWindow_AuthFailure_DoesNotMoveWindow) {
    VpnTunnel client, server;
    handshakeLoopback(client, server);

    auto p0 = packetFromClient(client, "packet-0");
    auto p1 = packetFromClient(client, "packet-1");
    std::vector<uint8_t> pt;
    CHECK_TRUE(server.decryptDataPacket(p0.data(), p0.size(), pt));
    CHECK_TRUE(server.decryptDataPacket(p1.data(), p1.size(), pt));

    // Tamper a packet carrying counter 2.
    auto p2 = packetFromClient(client, "packet-2");
    std::vector<uint8_t> tampered = p2;
    tampered[tampered.size() - 1] ^= 0xFF;
    CHECK_FALSE(server.decryptDataPacket(tampered.data(), tampered.size(), pt));

    // The failed packet must not have consumed counter 2's slot.
    CHECK_TRUE(server.decryptDataPacket(p2.data(), p2.size(), pt));
    CHECK_EQ(std::string(pt.begin(), pt.end()), "packet-2");
}

LETHE_TEST_CASE(VpnTunnel_SessionExpiry_RejectsDataAfterLifetime) {
    VpnTunnel client, server;
    handshakeLoopback(client, server);

    // Shorten the session lifetime (test hook; default is 180s).
    client.setSessionLifetime(std::chrono::milliseconds(30));
    server.setSessionLifetime(std::chrono::milliseconds(30));

    std::vector<uint8_t> ct, pt;
    CHECK_TRUE(client.encryptDataPacket(
        reinterpret_cast<const uint8_t*>("in-time"), 7, ct));
    CHECK_TRUE(server.decryptDataPacket(ct.data(), ct.size(), pt));

    std::this_thread::sleep_for(std::chrono::milliseconds(80));

    CHECK_TRUE(client.isSessionExpired());
    CHECK_TRUE(server.isSessionExpired());
    // Expired sessions refuse both directions (forces rekey).
    CHECK_FALSE(client.encryptDataPacket(
        reinterpret_cast<const uint8_t*>("too-late"), 8, ct));
    CHECK_FALSE(server.decryptDataPacket(ct.data(), ct.size(), pt));
    CHECK_EQ(client.state(), TunnelState::Stale);
}

LETHE_TEST_CASE(VpnTunnel_SessionLifetime_Tracking) {
    VpnTunnel client, server;
    handshakeLoopback(client, server);

    CHECK_GE(client.millisecondsSinceHandshake(), 0);
    CHECK_LT(client.millisecondsSinceHandshake(), 5000);
    CHECK_LT(client.millisecondsSinceLastReceive(), 0); // nothing received yet

    auto p0 = packetFromClient(client, "hello");
    std::vector<uint8_t> pt;
    CHECK_TRUE(server.decryptDataPacket(p0.data(), p0.size(), pt));
    CHECK_GE(server.millisecondsSinceLastReceive(), 0);
}

LETHE_TEST_CASE(VpnServer_IdleClient_Evicted) {
    Key serverPriv{};
    CHECK_TRUE(generatePrivateKey(serverPriv));
    VpnServer server;
    CHECK_TRUE(server.configure(serverPriv));
    server.setClientIdleTimeout(std::chrono::milliseconds(100));
    CHECK_TRUE(server.start("127.0.0.1", 0));
    const int serverPort = server.port();
    ServerLoop loop(&server);

    // Connect one real UDP client.
    VpnConfig config;
    config.endpointHost = "127.0.0.1";
    config.endpointPort = serverPort;
    config.serverPublicKey = server.publicKey();
    VpnTunnel client;
    CHECK_TRUE(client.configureClient(config));
    UdpTransport transport;
    CHECK_TRUE(transport.bind("127.0.0.1", 0));

    HandshakeMessage initMsg, respMsg;
    CHECK_TRUE(client.createHandshakeInit(initMsg));
    std::vector<uint8_t> respData;
    CHECK_TRUE(transport.sendAndReceive("127.0.0.1", serverPort, initMsg.serialize(),
                                        respData, std::chrono::milliseconds(3000), true) > 0);
    CHECK_TRUE(HandshakeMessage::deserialize(respData.data(), respData.size(), respMsg));
    CHECK_TRUE(client.processHandshakeResponse(respMsg));

    // Wait until the client is registered by the background loop.
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (server.clientCount() == 0 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK_EQ(server.clientCount(), 1u);

    // Let the idle timeout lapse; the background loop's sweep evicts.
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    CHECK_EQ(server.clientCount(), 0u);
    CHECK_EQ(server.sweepIdleClients(), 0u); // already gone
}

LETHE_TEST_CASE(VpnServer_MaxClients_Cap) {
    Key serverPriv{};
    CHECK_TRUE(generatePrivateKey(serverPriv));
    VpnServer server;
    CHECK_TRUE(server.configure(serverPriv));
    server.setMaxClients(1);
    CHECK_TRUE(server.start("127.0.0.1", 0));
    const int serverPort = server.port();
    ServerLoop loop(&server);

    auto connect = [&](UdpTransport& transport, VpnTunnel& client) -> bool {
        VpnConfig config;
        config.endpointHost = "127.0.0.1";
        config.endpointPort = serverPort;
        config.serverPublicKey = server.publicKey();
        if (!client.configureClient(config)) return false;
        if (!transport.bind("127.0.0.1", 0)) return false;
        HandshakeMessage initMsg, respMsg;
        if (!client.createHandshakeInit(initMsg)) return false;
        std::vector<uint8_t> respData;
        int n = transport.sendAndReceive("127.0.0.1", serverPort, initMsg.serialize(),
                                         respData, std::chrono::milliseconds(500), true);
        if (n <= 0) return false;
        if (!HandshakeMessage::deserialize(respData.data(), respData.size(), respMsg))
            return false;
        return client.processHandshakeResponse(respMsg);
    };

    VpnTunnel clientA;
    UdpTransport transportA;
    CHECK_TRUE(connect(transportA, clientA));
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (server.clientCount() == 0 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK_EQ(server.clientCount(), 1u);

    // Second client: the server is at cap, the handshake is dropped silently.
    VpnTunnel clientB;
    UdpTransport transportB;
    CHECK_TRUE(transportB.bind("127.0.0.1", 0));
    VpnConfig configB;
    configB.endpointHost = "127.0.0.1";
    configB.endpointPort = serverPort;
    configB.serverPublicKey = server.publicKey();
    CHECK_TRUE(clientB.configureClient(configB));
    HandshakeMessage initB;
    CHECK_TRUE(clientB.createHandshakeInit(initB));
    std::vector<uint8_t> respB;
    int n = transportB.sendAndReceive("127.0.0.1", serverPort, initB.serialize(),
                                      respB, std::chrono::milliseconds(500), true);
    CHECK_TRUE(n < 0); // no response: dropped, not amplified
    CHECK_EQ(server.clientCount(), 1u); // cap held
}

LETHE_TEST_CASE(VpnServer_HandshakeRateLimit) {
    Key serverPriv{};
    CHECK_TRUE(generatePrivateKey(serverPriv));
    VpnServer server;
    CHECK_TRUE(server.configure(serverPriv));
    server.setHandshakeRateLimit(2, std::chrono::seconds(10));
    CHECK_TRUE(server.start("127.0.0.1", 0));
    const int serverPort = server.port();
    ServerLoop loop(&server);

    auto attempt = [&](UdpTransport& transport) -> bool {
        VpnConfig config;
        config.endpointHost = "127.0.0.1";
        config.endpointPort = serverPort;
        config.serverPublicKey = server.publicKey();
        VpnTunnel client;
        if (!client.configureClient(config)) return false;
        HandshakeMessage initMsg;
        if (!client.createHandshakeInit(initMsg)) return false;
        std::vector<uint8_t> respData;
        int n = transport.sendAndReceive("127.0.0.1", serverPort, initMsg.serialize(),
                                         respData, std::chrono::milliseconds(500), true);
        if (n <= 0) return false;
        HandshakeMessage respMsg;
        if (!HandshakeMessage::deserialize(respData.data(), respData.size(), respMsg))
            return false;
        return client.processHandshakeResponse(respMsg);
    };

    UdpTransport t1, t2, t3;
    CHECK_TRUE(t1.bind("127.0.0.1", 0));
    CHECK_TRUE(t2.bind("127.0.0.1", 0));
    CHECK_TRUE(t3.bind("127.0.0.1", 0));

    CHECK_TRUE(attempt(t1)); // 1st handshake: allowed
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (server.clientCount() == 0 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK_TRUE(attempt(t2)); // 2nd: allowed (limit is 2 per window)
    deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (server.clientCount() < 2 && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK_EQ(server.clientCount(), 2u);

    CHECK_FALSE(attempt(t3)); // 3rd from same host: rate limited, no response
    CHECK_EQ(server.clientCount(), 2u);
}
