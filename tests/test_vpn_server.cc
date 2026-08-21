// test_vpn_server.cc — End-to-end tests for the reference VPN server over real UDP
//
// These tests exercise the full network transport layer: a real UDP server
// socket and a real UDP client socket exchanging WireGuard-style handshake
// and encrypted data packets over loopback.

#include "test_framework.h"
#include "network/vpn/vpn_server.h"
#include "network/vpn/vpn_tunnel.h"
#include "network/vpn/vpn_config.h"
#include "network/udp_transport.h"

#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>
#include <vector>
#include <utility>

using namespace lethe::vpn;
using namespace lethe;

namespace {

// Wait up to timeoutMs for the predicate to become true.
bool waitFor(std::function<bool()> pred, int timeoutMs) {
    auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return pred();
}

} // namespace

LETHE_TEST_CASE(VpnServer_Handshake_OverRealUdp) {
    // Server with a background event-loop thread.
    Key serverPriv{};
    CHECK_TRUE(generatePrivateKey(serverPriv));
    VpnServer server;
    CHECK_TRUE(server.configure(serverPriv));
    CHECK_TRUE(server.start("127.0.0.1", 0));
    int serverPort = server.port();
    CHECK_TRUE(serverPort > 0);

    std::atomic<bool> serverRunning{true};
    std::thread serverThread([&]() {
        while (serverRunning.load()) {
            server.process(std::chrono::milliseconds(50));
        }
    });

    // Client configured to talk to the server.
    VpnConfig config;
    config.endpointHost = "127.0.0.1";
    config.endpointPort = serverPort;
    config.serverPublicKey = server.publicKey();
    config.allowedCidrs = {"0.0.0.0/0"};

    VpnTunnel client;
    CHECK_TRUE(client.configureClient(config));

    UdpTransport clientTransport;
    CHECK_TRUE(clientTransport.bind("127.0.0.1", 0));

    // Perform the handshake over the wire.
    HandshakeMessage initMsg;
    CHECK_TRUE(client.createHandshakeInit(initMsg));
    std::vector<uint8_t> initData = initMsg.serialize();

    std::vector<uint8_t> respData;
    int n = clientTransport.sendAndReceive("127.0.0.1", serverPort, initData,
                                           respData, std::chrono::milliseconds(3000),
                                           /*onlyFromSender=*/true);
    CHECK_TRUE(n > 0);

    HandshakeMessage respMsg;
    CHECK_TRUE(HandshakeMessage::deserialize(respData.data(), respData.size(), respMsg));
    CHECK_EQ(static_cast<int>(respMsg.type), static_cast<int>(HandshakeType::Response));
    CHECK_TRUE(client.processHandshakeResponse(respMsg));
    CHECK_TRUE(client.isConnected());

    // Server should have registered the client.
    CHECK_TRUE(waitFor([&]() { return server.clientCount() == 1; }, 2000));

    serverRunning = false;
    serverThread.join();
}

LETHE_TEST_CASE(VpnServer_DataPath_ClientToServer_OverUdp) {
    Key serverPriv{};
    CHECK_TRUE(generatePrivateKey(serverPriv));
    VpnServer server;
    CHECK_TRUE(server.configure(serverPriv));
    CHECK_TRUE(server.start("127.0.0.1", 0));
    int serverPort = server.port();

    // Capture decrypted client data.
    std::mutex dataMutex;
    std::vector<std::pair<std::string, std::string>> received;
    server.setDataCallback([&](const std::string& clientKey, const uint8_t* data, size_t len) {
        std::lock_guard<std::mutex> lock(dataMutex);
        received.emplace_back(clientKey,
                              std::string(reinterpret_cast<const char*>(data), len));
    });

    std::atomic<bool> serverRunning{true};
    std::thread serverThread([&]() {
        while (serverRunning.load()) {
            server.process(std::chrono::milliseconds(50));
        }
    });

    // Client + handshake.
    VpnConfig config;
    config.endpointHost = "127.0.0.1";
    config.endpointPort = serverPort;
    config.serverPublicKey = server.publicKey();
    VpnTunnel client;
    CHECK_TRUE(client.configureClient(config));
    UdpTransport clientTransport;
    CHECK_TRUE(clientTransport.bind("127.0.0.1", 0));

    HandshakeMessage initMsg;
    CHECK_TRUE(client.createHandshakeInit(initMsg));
    std::vector<uint8_t> respData;
    int n = clientTransport.sendAndReceive("127.0.0.1", serverPort, initMsg.serialize(),
                                           respData, std::chrono::milliseconds(3000), true);
    CHECK_TRUE(n > 0);
    HandshakeMessage respMsg;
    CHECK_TRUE(HandshakeMessage::deserialize(respData.data(), respData.size(), respMsg));
    CHECK_TRUE(client.processHandshakeResponse(respMsg));
    CHECK_TRUE(waitFor([&]() { return server.clientCount() == 1; }, 2000));

    // Client sends an encrypted packet over UDP.
    std::string message = "Hello over real UDP through the VPN!";
    std::vector<uint8_t> ciphertext;
    CHECK_TRUE(client.encryptDataPacket(
        reinterpret_cast<const uint8_t*>(message.data()), message.size(), ciphertext));
    CHECK_TRUE(clientTransport.sendTo("127.0.0.1", serverPort, ciphertext));

    // Server should decrypt and deliver it.
    CHECK_TRUE(waitFor([&]() {
        std::lock_guard<std::mutex> lock(dataMutex);
        return !received.empty();
    }, 3000));

    {
        std::lock_guard<std::mutex> lock(dataMutex);
        CHECK_EQ(received[0].second, message);
    }

    serverRunning = false;
    serverThread.join();
}

LETHE_TEST_CASE(VpnServer_DataPath_ServerToClient_OverUdp) {
    Key serverPriv{};
    CHECK_TRUE(generatePrivateKey(serverPriv));
    VpnServer server;
    CHECK_TRUE(server.configure(serverPriv));
    CHECK_TRUE(server.start("127.0.0.1", 0));
    int serverPort = server.port();

    std::atomic<bool> serverRunning{true};
    std::thread serverThread([&]() {
        while (serverRunning.load()) {
            server.process(std::chrono::milliseconds(50));
        }
    });

    // Client + handshake.
    VpnConfig config;
    config.endpointHost = "127.0.0.1";
    config.endpointPort = serverPort;
    config.serverPublicKey = server.publicKey();
    VpnTunnel client;
    CHECK_TRUE(client.configureClient(config));
    UdpTransport clientTransport;
    CHECK_TRUE(clientTransport.bind("127.0.0.1", 0));

    HandshakeMessage initMsg;
    CHECK_TRUE(client.createHandshakeInit(initMsg));
    std::vector<uint8_t> respData;
    int n = clientTransport.sendAndReceive("127.0.0.1", serverPort, initMsg.serialize(),
                                           respData, std::chrono::milliseconds(3000), true);
    CHECK_TRUE(n > 0);
    HandshakeMessage respMsg;
    CHECK_TRUE(HandshakeMessage::deserialize(respData.data(), respData.size(), respMsg));
    CHECK_TRUE(client.processHandshakeResponse(respMsg));
    CHECK_TRUE(waitFor([&]() { return server.clientCount() == 1; }, 2000));

    // Server sends an encrypted packet to the client over UDP.
    std::vector<std::string> clients = server.connectedClients();
    CHECK_EQ(clients.size(), 1u);
    std::string serverMsg = "Reply from the server over UDP!";
    CHECK_TRUE(server.sendToClient(clients[0],
                                   reinterpret_cast<const uint8_t*>(serverMsg.data()),
                                   serverMsg.size()));

    // Client receives and decrypts.
    std::vector<uint8_t> ct;
    std::string fromHost;
    int fromPort = 0;
    int m = clientTransport.recvFrom(ct, std::chrono::milliseconds(3000), fromHost, fromPort);
    CHECK_TRUE(m > 0);

    std::vector<uint8_t> plaintext;
    CHECK_TRUE(client.decryptDataPacket(ct.data(), ct.size(), plaintext));
    CHECK_EQ(std::string(plaintext.begin(), plaintext.end()), serverMsg);

    serverRunning = false;
    serverThread.join();
}

LETHE_TEST_CASE(VpnServer_MultipleClients_OverUdp) {
    Key serverPriv{};
    CHECK_TRUE(generatePrivateKey(serverPriv));
    VpnServer server;
    CHECK_TRUE(server.configure(serverPriv));
    CHECK_TRUE(server.start("127.0.0.1", 0));
    int serverPort = server.port();

    std::atomic<bool> serverRunning{true};
    std::thread serverThread([&]() {
        while (serverRunning.load()) {
            server.process(std::chrono::milliseconds(50));
        }
    });

    // Connect 3 clients.
    std::vector<std::unique_ptr<VpnTunnel>> clients;
    std::vector<std::unique_ptr<UdpTransport>> transports;
    for (int i = 0; i < 3; i++) {
        auto client = std::make_unique<VpnTunnel>();
        auto transport = std::make_unique<UdpTransport>();

        VpnConfig config;
        config.endpointHost = "127.0.0.1";
        config.endpointPort = serverPort;
        config.serverPublicKey = server.publicKey();
        CHECK_TRUE(client->configureClient(config));
        CHECK_TRUE(transport->bind("127.0.0.1", 0));

        HandshakeMessage initMsg;
        CHECK_TRUE(client->createHandshakeInit(initMsg));
        std::vector<uint8_t> respData;
        int n = transport->sendAndReceive("127.0.0.1", serverPort, initMsg.serialize(),
                                          respData, std::chrono::milliseconds(3000), true);
        CHECK_TRUE(n > 0);
        HandshakeMessage respMsg;
        CHECK_TRUE(HandshakeMessage::deserialize(respData.data(), respData.size(), respMsg));
        CHECK_TRUE(client->processHandshakeResponse(respMsg));
        CHECK_TRUE(client->isConnected());

        clients.push_back(std::move(client));
        transports.push_back(std::move(transport));
    }

    // Server should have 3 connected clients.
    CHECK_TRUE(waitFor([&]() { return server.clientCount() == 3; }, 3000));

    serverRunning = false;
    serverThread.join();
}

LETHE_TEST_CASE(VpnServer_TamperedPacket_Rejected_OverUdp) {
    Key serverPriv{};
    CHECK_TRUE(generatePrivateKey(serverPriv));
    VpnServer server;
    CHECK_TRUE(server.configure(serverPriv));
    CHECK_TRUE(server.start("127.0.0.1", 0));
    int serverPort = server.port();

    std::mutex dataMutex;
    int deliveredCount = 0;
    server.setDataCallback([&](const std::string&, const uint8_t*, size_t) {
        std::lock_guard<std::mutex> lock(dataMutex);
        deliveredCount++;
    });

    std::atomic<bool> serverRunning{true};
    std::thread serverThread([&]() {
        while (serverRunning.load()) {
            server.process(std::chrono::milliseconds(50));
        }
    });

    // Client + handshake.
    VpnConfig config;
    config.endpointHost = "127.0.0.1";
    config.endpointPort = serverPort;
    config.serverPublicKey = server.publicKey();
    VpnTunnel client;
    CHECK_TRUE(client.configureClient(config));
    UdpTransport clientTransport;
    CHECK_TRUE(clientTransport.bind("127.0.0.1", 0));

    HandshakeMessage initMsg;
    CHECK_TRUE(client.createHandshakeInit(initMsg));
    std::vector<uint8_t> respData;
    int n = clientTransport.sendAndReceive("127.0.0.1", serverPort, initMsg.serialize(),
                                           respData, std::chrono::milliseconds(3000), true);
    CHECK_TRUE(n > 0);
    HandshakeMessage respMsg;
    CHECK_TRUE(HandshakeMessage::deserialize(respData.data(), respData.size(), respMsg));
    CHECK_TRUE(client.processHandshakeResponse(respMsg));
    CHECK_TRUE(waitFor([&]() { return server.clientCount() == 1; }, 2000));

    // Encrypt a packet, then tamper with it.
    std::string message = "Sensitive data";
    std::vector<uint8_t> ciphertext;
    CHECK_TRUE(client.encryptDataPacket(
        reinterpret_cast<const uint8_t*>(message.data()), message.size(), ciphertext));
    ciphertext[5] ^= 0xFF; // tamper

    CHECK_TRUE(clientTransport.sendTo("127.0.0.1", serverPort, ciphertext));

    // Give the server time to process (and reject) the tampered packet.
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    {
        std::lock_guard<std::mutex> lock(dataMutex);
        // The tampered packet must NOT be delivered.
        CHECK_EQ(deliveredCount, 0);
    }

    serverRunning = false;
    serverThread.join();
}

