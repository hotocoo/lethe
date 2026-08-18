// test_engine_vpn.cc — Tests for engine VPN integration

#include "test_framework.h"
#include "core/engine.h"
#include "config.h"

using namespace lethe;

LETHE_TEST_CASE(Engine_InitializeWithVpn) {
    Config cfg;
    cfg.incognitoMode = true;
    cfg.vpnEnabled = false;  // Start with VPN disabled

    Engine engine;
    CHECK_EQ(engine.initialize(cfg), 0);
    CHECK_TRUE(engine.isRunning());

    // VPN tunnel should exist but not be connected.
    CHECK_TRUE(engine.vpnTunnel() != nullptr);
    CHECK_FALSE(engine.isVpnConnected());

    engine.shutdown();
    CHECK_FALSE(engine.isRunning());
}

LETHE_TEST_CASE(Engine_EnableVpn) {
    Config cfg;
    cfg.incognitoMode = true;
    cfg.vpnEnabled = false;

    Engine engine;
    CHECK_EQ(engine.initialize(cfg), 0);

    // Enable VPN with a config.
    vpn::VpnConfig vpnCfg;
    vpnCfg.endpointHost = "vpn.aletheia.os";
    vpnCfg.endpointPort = 51820;
    // Generate a server public key for the test.
    vpn::Key tempPriv{};
    CHECK_TRUE(vpn::generatePrivateKey(tempPriv));
    CHECK_TRUE(vpn::derivePublicKey(tempPriv, vpnCfg.serverPublicKey));
    vpnCfg.allowedCidrs = {"0.0.0.0/0"};

    CHECK_TRUE(engine.enableVpn(vpnCfg));
    CHECK_TRUE(engine.config().vpnEnabled);

    // The tunnel should be configured (state Handshaking after init).
    CHECK_TRUE(engine.vpnTunnel() != nullptr);

    engine.shutdown();
}

LETHE_TEST_CASE(Engine_DisableVpn) {
    Config cfg;
    cfg.incognitoMode = true;

    Engine engine;
    CHECK_EQ(engine.initialize(cfg), 0);

    vpn::VpnConfig vpnCfg;
    vpnCfg.endpointHost = "vpn.aletheia.os";
    vpn::Key tempPriv{};
    CHECK_TRUE(vpn::generatePrivateKey(tempPriv));
    CHECK_TRUE(vpn::derivePublicKey(tempPriv, vpnCfg.serverPublicKey));

    CHECK_TRUE(engine.enableVpn(vpnCfg));
    CHECK_TRUE(engine.config().vpnEnabled);

    CHECK_TRUE(engine.disableVpn());
    CHECK_FALSE(engine.config().vpnEnabled);

    engine.shutdown();
}

LETHE_TEST_CASE(Engine_FullVpnHandshakeLoopback) {
    // Simulate a full VPN handshake between the engine's client tunnel
    // and a server tunnel.
    Config cfg;
    cfg.incognitoMode = true;

    Engine engine;
    CHECK_EQ(engine.initialize(cfg), 0);

    // Set up a server tunnel.
    vpn::Key serverPriv{};
    CHECK_TRUE(vpn::generatePrivateKey(serverPriv));
    vpn::VpnTunnel server;
    CHECK_TRUE(server.configureServer(serverPriv));

    // Configure the engine's VPN with the server's public key.
    vpn::VpnConfig vpnCfg;
    vpnCfg.endpointHost = "127.0.0.1";
    vpnCfg.serverPublicKey = server.localPublicKey();
    vpnCfg.allowedCidrs = {"0.0.0.0/0"};

    CHECK_TRUE(engine.enableVpn(vpnCfg));

    // Perform the handshake: engine's tunnel is the client.
    vpn::HandshakeMessage initMsg;
    CHECK_TRUE(engine.vpnTunnel()->createHandshakeInit(initMsg));

    vpn::HandshakeMessage respMsg;
    CHECK_TRUE(server.processHandshakeInit(initMsg, respMsg));

    CHECK_TRUE(engine.vpnTunnel()->processHandshakeResponse(respMsg));

    // Now the engine's VPN should be connected.
    CHECK_TRUE(engine.isVpnConnected());

    // Test data path through the engine's tunnel.
    std::string msg = "Engine VPN test message";
    std::vector<uint8_t> ct;
    CHECK_TRUE(engine.vpnTunnel()->encryptDataPacket(
        reinterpret_cast<const uint8_t*>(msg.data()), msg.size(), ct));

    std::vector<uint8_t> pt;
    CHECK_TRUE(server.decryptDataPacket(ct.data(), ct.size(), pt));
    CHECK_EQ(std::string(pt.begin(), pt.end()), msg);

    engine.shutdown();
}

