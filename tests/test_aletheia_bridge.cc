// test_aletheia_bridge.cc — Tests for the Aletheia OS bridge

#include "test_framework.h"
#include "aletheia/aletheia_bridge.h"
#include "core/engine.h"

using namespace lethe;
using namespace lethe::aletheia;

LETHE_TEST_CASE(AletheiaBridge_Initialize) {
    Config cfg;
    cfg.incognitoMode = true;

    Engine engine;
    CHECK_EQ(engine.initialize(cfg), 0);

    AletheiaBridge bridge(&engine);

    // Bridge should be initialized with the engine.
    auto status = bridge.getStatus();
    CHECK_TRUE(status.running);
    CHECK_FALSE(status.vpnConnected);

    engine.shutdown();
}

LETHE_TEST_CASE(AletheiaBridge_OpenUrl) {
    Config cfg;
    cfg.incognitoMode = true;

    Engine engine;
    CHECK_EQ(engine.initialize(cfg), 0);

    AletheiaBridge bridge(&engine);

    // Open a URL.
    CHECK_TRUE(bridge.openUrl("https://aletheia.os"));

    // Current URL should be set.
    CHECK_EQ(bridge.getCurrentUrl(), std::string("https://aletheia.os"));

    engine.shutdown();
}

LETHE_TEST_CASE(AletheiaBridge_Navigate) {
    Config cfg;
    cfg.incognitoMode = true;

    Engine engine;
    CHECK_EQ(engine.initialize(cfg), 0);

    AletheiaBridge bridge(&engine);

    // Open an initial URL.
    CHECK_TRUE(bridge.openUrl("https://aletheia.os"));

    // Navigate to a new URL.
    CHECK_TRUE(bridge.navigate("https://example.com"));
    CHECK_EQ(bridge.getCurrentUrl(), std::string("https://example.com"));

    engine.shutdown();
}

LETHE_TEST_CASE(AletheiaBridge_OpenNewTab) {
    Config cfg;
    cfg.incognitoMode = true;

    Engine engine;
    CHECK_EQ(engine.initialize(cfg), 0);

    AletheiaBridge bridge(&engine);

    size_t initialTabs = bridge.getStatus().tabCount;

    // Open a new tab.
    CHECK_TRUE(bridge.openUrl("https://newtab.com", true));

    size_t newTabs = bridge.getStatus().tabCount;
    CHECK_TRUE(newTabs > initialTabs);

    engine.shutdown();
}

LETHE_TEST_CASE(AletheiaBridge_VpnControl) {
    Config cfg;
    cfg.incognitoMode = true;

    Engine engine;
    CHECK_EQ(engine.initialize(cfg), 0);

    AletheiaBridge bridge(&engine);

    // Initially not connected.
    CHECK_FALSE(bridge.isVpnConnected());

    // Enable VPN.
    vpn::VpnConfig vpnCfg;
    vpnCfg.endpointHost = "vpn.aletheia.os";
    vpn::Key tempPriv{};
    CHECK_TRUE(vpn::generatePrivateKey(tempPriv));
    CHECK_TRUE(vpn::derivePublicKey(tempPriv, vpnCfg.serverPublicKey));

    CHECK_TRUE(bridge.enableVpn(vpnCfg));

    // Disable VPN.
    CHECK_TRUE(bridge.disableVpn());

    engine.shutdown();
}

LETHE_TEST_CASE(AletheiaBridge_LlmSearchAvailable) {
    Config cfg;
    cfg.incognitoMode = true;

    Engine engine;
    CHECK_EQ(engine.initialize(cfg), 0);

    AletheiaBridge bridge(&engine);

    // LLM search should be available (returns empty on failure, not crash).
    auto results = bridge.llmWebSearch("test query");
    (void)results;

    // Read page should return an error (no real network), not crash.
    auto content = bridge.llmReadPage("https://example.com");
    (void)content;

    engine.shutdown();
}

LETHE_TEST_CASE(AletheiaBridge_Status) {
    Config cfg;
    cfg.incognitoMode = true;

    Engine engine;
    CHECK_EQ(engine.initialize(cfg), 0);

    AletheiaBridge bridge(&engine);

    auto status = bridge.getStatus();
    CHECK_TRUE(status.running);
    CHECK_TRUE(status.tabCount >= 1);
    CHECK_TRUE(status.activeTabId > 0);

    engine.shutdown();
}

