// test_vpn_tunnel.cc — Tests for the built-in VPN tunnel handshake

#include "test_framework.h"
#include "network/vpn/vpn_tunnel.h"
#include "network/vpn/vpn_config.h"

using namespace lethe::vpn;

LETHE_TEST_CASE(VpnTunnel_Handshake_Loopback) {
    // Set up a server with a known key.
    Key serverPriv{};
    CHECK_TRUE(generatePrivateKey(serverPriv));

    VpnTunnel server;
    CHECK_TRUE(server.configureServer(serverPriv));

    // Set up a client pointing at the server.
    VpnConfig config;
    config.endpointHost = "127.0.0.1";
    config.endpointPort = 51820;
    config.serverPublicKey = server.localPublicKey();
    config.allowedCidrs = {"0.0.0.0/0"};

    VpnTunnel client;
    CHECK_TRUE(client.configureClient(config));

    // Client initiates handshake.
    HandshakeMessage initMsg;
    CHECK_TRUE(client.createHandshakeInit(initMsg));
    CHECK_EQ(static_cast<int>(initMsg.type), static_cast<int>(HandshakeType::Init));
    CHECK_EQ(client.state(), TunnelState::Handshaking);

    // Server processes the init and responds.
    HandshakeMessage respMsg;
    CHECK_TRUE(server.processHandshakeInit(initMsg, respMsg));
    CHECK_EQ(static_cast<int>(respMsg.type), static_cast<int>(HandshakeType::Response));
    CHECK_EQ(server.state(), TunnelState::Connected);

    // Client processes the response.
    CHECK_TRUE(client.processHandshakeResponse(respMsg));
    CHECK_EQ(client.state(), TunnelState::Connected);

    // Both should be connected.
    CHECK_TRUE(client.isConnected());
    CHECK_TRUE(server.isConnected());
}

LETHE_TEST_CASE(VpnTunnel_DataPath_ClientToServer) {
    Key serverPriv{};
    CHECK_TRUE(generatePrivateKey(serverPriv));

    VpnTunnel server;
    CHECK_TRUE(server.configureServer(serverPriv));

    VpnConfig config;
    config.endpointHost = "127.0.0.1";
    config.serverPublicKey = server.localPublicKey();

    VpnTunnel client;
    CHECK_TRUE(client.configureClient(config));

    HandshakeMessage initMsg, respMsg;
    CHECK_TRUE(client.createHandshakeInit(initMsg));
    CHECK_TRUE(server.processHandshakeInit(initMsg, respMsg));
    CHECK_TRUE(client.processHandshakeResponse(respMsg));

    // Client encrypts, server decrypts.
    std::string message = "Hello from client through the VPN!";
    std::vector<uint8_t> ciphertext;
    CHECK_TRUE(client.encryptDataPacket(
        reinterpret_cast<const uint8_t*>(message.data()), message.size(), ciphertext));

    // Ciphertext should be larger (wire counter + tag added).
    CHECK_EQ(ciphertext.size(), message.size() + COUNTER_BYTES + TAG_BYTES);

    // The counter travels explicitly in the header (little-endian).
    uint64_t wireCounter = 0;
    for (size_t i = 0; i < COUNTER_BYTES; i++) {
        wireCounter |= static_cast<uint64_t>(ciphertext[i]) << (8 * i);
    }
    CHECK_EQ(wireCounter, 0u); // First data packet uses counter 0.

    std::vector<uint8_t> plaintext;
    CHECK_TRUE(server.decryptDataPacket(ciphertext.data(), ciphertext.size(), plaintext));

    std::string decrypted(plaintext.begin(), plaintext.end());
    CHECK_EQ(decrypted, message);
}

LETHE_TEST_CASE(VpnTunnel_DataPath_ServerToClient) {
    Key serverPriv{};
    CHECK_TRUE(generatePrivateKey(serverPriv));

    VpnTunnel server;
    CHECK_TRUE(server.configureServer(serverPriv));

    VpnConfig config;
    config.endpointHost = "127.0.0.1";
    config.serverPublicKey = server.localPublicKey();

    VpnTunnel client;
    CHECK_TRUE(client.configureClient(config));

    HandshakeMessage initMsg, respMsg;
    CHECK_TRUE(client.createHandshakeInit(initMsg));
    CHECK_TRUE(server.processHandshakeInit(initMsg, respMsg));
    CHECK_TRUE(client.processHandshakeResponse(respMsg));

    // Server encrypts, client decrypts.
    std::string message = "Hello from server through the VPN!";
    std::vector<uint8_t> ciphertext;
    CHECK_TRUE(server.encryptDataPacket(
        reinterpret_cast<const uint8_t*>(message.data()), message.size(), ciphertext));

    std::vector<uint8_t> plaintext;
    CHECK_TRUE(client.decryptDataPacket(ciphertext.data(), ciphertext.size(), plaintext));

    std::string decrypted(plaintext.begin(), plaintext.end());
    CHECK_EQ(decrypted, message);
}

LETHE_TEST_CASE(VpnTunnel_Bidirectional_MultiplePackets) {
    Key serverPriv{};
    CHECK_TRUE(generatePrivateKey(serverPriv));

    VpnTunnel server;
    CHECK_TRUE(server.configureServer(serverPriv));

    VpnConfig config;
    config.endpointHost = "127.0.0.1";
    config.serverPublicKey = server.localPublicKey();

    VpnTunnel client;
    CHECK_TRUE(client.configureClient(config));

    HandshakeMessage initMsg, respMsg;
    CHECK_TRUE(client.createHandshakeInit(initMsg));
    CHECK_TRUE(server.processHandshakeInit(initMsg, respMsg));
    CHECK_TRUE(client.processHandshakeResponse(respMsg));

    // Send multiple packets in both directions.
    for (int i = 0; i < 10; i++) {
        std::string msg = "Packet " + std::to_string(i);

        // Client -> Server
        std::vector<uint8_t> ct1;
        CHECK_TRUE(client.encryptDataPacket(
            reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), ct1));
        std::vector<uint8_t> pt1;
        CHECK_TRUE(server.decryptDataPacket(ct1.data(), ct1.size(), pt1));
        CHECK_EQ(std::string(pt1.begin(), pt1.end()), msg);

        // Server -> Client
        std::string msg2 = "Reply " + std::to_string(i);
        std::vector<uint8_t> ct2;
        CHECK_TRUE(server.encryptDataPacket(
            reinterpret_cast<const uint8_t*>(msg2.data()), msg2.size(), ct2));
        std::vector<uint8_t> pt2;
        CHECK_TRUE(client.decryptDataPacket(ct2.data(), ct2.size(), pt2));
        CHECK_EQ(std::string(pt2.begin(), pt2.end()), msg2);
    }
}

LETHE_TEST_CASE(VpnTunnel_TamperedPacket_Detected) {
    Key serverPriv{};
    CHECK_TRUE(generatePrivateKey(serverPriv));

    VpnTunnel server;
    CHECK_TRUE(server.configureServer(serverPriv));

    VpnConfig config;
    config.endpointHost = "127.0.0.1";
    config.serverPublicKey = server.localPublicKey();

    VpnTunnel client;
    CHECK_TRUE(client.configureClient(config));

    HandshakeMessage initMsg, respMsg;
    CHECK_TRUE(client.createHandshakeInit(initMsg));
    CHECK_TRUE(server.processHandshakeInit(initMsg, respMsg));
    CHECK_TRUE(client.processHandshakeResponse(respMsg));

    // Client encrypts a packet.
    std::string message = "Important data";
    std::vector<uint8_t> ciphertext;
    CHECK_TRUE(client.encryptDataPacket(
        reinterpret_cast<const uint8_t*>(message.data()), message.size(), ciphertext));

    // Tamper with it.
    ciphertext[5] ^= 0xFF;

    // Server should detect the tampering.
    std::vector<uint8_t> plaintext;
    CHECK_FALSE(server.decryptDataPacket(ciphertext.data(), ciphertext.size(), plaintext));
}

LETHE_TEST_CASE(VpnTunnel_WrongServerKey_Fails) {
    // Client uses the wrong server public key; handshake should fail.
    Key serverPriv{};
    CHECK_TRUE(generatePrivateKey(serverPriv));

    VpnTunnel server;
    CHECK_TRUE(server.configureServer(serverPriv));

    VpnConfig config;
    config.endpointHost = "127.0.0.1";
    // Use a wrong public key.
    Key wrongPub{};
    CHECK_TRUE(generatePrivateKey(wrongPub));
    CHECK_TRUE(derivePublicKey(wrongPub, config.serverPublicKey));

    VpnTunnel client;
    CHECK_TRUE(client.configureClient(config));

    HandshakeMessage initMsg;
    CHECK_TRUE(client.createHandshakeInit(initMsg));

    // Server should reject the handshake (index won't match).
    HandshakeMessage respMsg;
    CHECK_FALSE(server.processHandshakeInit(initMsg, respMsg));
}

LETHE_TEST_CASE(VpnTunnel_CIDR_Routing) {
    // Test CIDR routing decisions.
    VpnTunnel tunnel;

    Key serverPriv{};
    CHECK_TRUE(generatePrivateKey(serverPriv));
    CHECK_TRUE(tunnel.configureServer(serverPriv));

    // Full tunnel (0.0.0.0/0) routes everything.
    VpnConfig fullConfig;
    fullConfig.endpointHost = "127.0.0.1";
    fullConfig.serverPublicKey = tunnel.localPublicKey();
    fullConfig.allowedCidrs = {"0.0.0.0/0"};

    VpnTunnel fullTunnel;
    CHECK_TRUE(fullTunnel.configureClient(fullConfig));
    CHECK_TRUE(fullTunnel.shouldRouteThroughVpn("8.8.8.8"));
    CHECK_TRUE(fullTunnel.shouldRouteThroughVpn("192.168.1.1"));
    CHECK_TRUE(fullTunnel.shouldRouteThroughVpn("10.0.0.1"));

    // Specific CIDR.
    VpnConfig specificConfig;
    specificConfig.endpointHost = "127.0.0.1";
    specificConfig.serverPublicKey = tunnel.localPublicKey();
    specificConfig.allowedCidrs = {"10.0.0.0/8"};

    VpnTunnel specificTunnel;
    CHECK_TRUE(specificTunnel.configureClient(specificConfig));
    CHECK_TRUE(specificTunnel.shouldRouteThroughVpn("10.1.2.3"));
    CHECK_TRUE(specificTunnel.shouldRouteThroughVpn("10.255.255.255"));
    CHECK_FALSE(specificTunnel.shouldRouteThroughVpn("11.0.0.1"));
    CHECK_FALSE(specificTunnel.shouldRouteThroughVpn("8.8.8.8"));
}

LETHE_TEST_CASE(VpnTunnel_MTU_Enforcement) {
    Key serverPriv{};
    CHECK_TRUE(generatePrivateKey(serverPriv));

    VpnTunnel server;
    CHECK_TRUE(server.configureServer(serverPriv));

    VpnConfig config;
    config.endpointHost = "127.0.0.1";
    config.serverPublicKey = server.localPublicKey();
    config.mtu = 1420;

    VpnTunnel client;
    CHECK_TRUE(client.configureClient(config));

    HandshakeMessage initMsg, respMsg;
    CHECK_TRUE(client.createHandshakeInit(initMsg));
    CHECK_TRUE(server.processHandshakeInit(initMsg, respMsg));
    CHECK_TRUE(client.processHandshakeResponse(respMsg));

    // Packet within MTU should work.
    std::string smallMsg(1000, 'A');
    std::vector<uint8_t> ct1;
    CHECK_TRUE(client.encryptDataPacket(
        reinterpret_cast<const uint8_t*>(smallMsg.data()), smallMsg.size(), ct1));

    // Packet exceeding MTU should fail.
    std::string largeMsg(2000, 'B');
    std::vector<uint8_t> ct2;
    CHECK_FALSE(client.encryptDataPacket(
        reinterpret_cast<const uint8_t*>(largeMsg.data()), largeMsg.size(), ct2));
}

