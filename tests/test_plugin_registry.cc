// test_plugin_registry.cc — the plugin registry: every feature as a plugin.
//
// Layer 1 (structure): built-ins register once, ids are unique, every spec
// has the fields the shells' UIs are generated from.
// Layer 2 (state): defaults, explicit overrides, and tolerance for unknown
// ids in the overrides JSON.
// Layer 3 (round-trip): toJson/loadOverridesJson preserve overrides exactly.
// Layer 4 (live apply): applyTo flips only the flags it honestly owns.

#include "test_framework.h"
#include "plugins/plugin_registry.h"
#include "browser/shell_context.h"

#include <set>
#include <string>

using lethe::PluginRegistry;
using lethe::PluginSpec;
using lethe::ShellContext;

namespace {

// The registry is a process-wide singleton; tests that mutate state set it
// explicitly first, and clear overrides at the end so test order never
// matters.
struct OverrideGuard {
    explicit OverrideGuard(PluginRegistry& r) : reg(r) {}
    ~OverrideGuard() {
        for (const auto& p : reg.plugins()) reg.clearOverride(p.id);
    }
    PluginRegistry& reg;
};

} // namespace

LETHE_TEST_CASE(PluginRegistry_BuiltinsRegistered) {
    PluginRegistry& r = PluginRegistry::instance();
    r.registerBuiltins();
    r.registerBuiltins();  // idempotent: a second call must not duplicate
    CHECK(r.plugins().size() >= 18);
    std::set<std::string> ids;
    for (const auto& p : r.plugins()) {
        CHECK(!p.id.empty());
        CHECK(!p.name.empty());
        CHECK(!p.description.empty());
        CHECK(!p.group.empty());
        CHECK(ids.insert(p.id).second);  // unique
    }
    // The feature families the user toggles are all present.
    for (const char* id : {"tracker-block", "https-first", "https-only",
                           "stealth-ua", "do-not-track", "fingerprint-shield",
                           "third-party-cookie-block", "referer-strip",
                           "webrtc-block", "oblivion-windows",
                           "persistent-cookies", "secure-dns", "doh-cache",
                           "doh-pool", "policy-proxy", "private-net-isolation",
                           "vpn", "javascript", "hardware-accel",
                           "high-refresh", "telemetry", "crash-reports"}) {
        CHECK(r.find(id) != nullptr);
    }
}

LETHE_TEST_CASE(PluginRegistry_DefaultsAndOverrides) {
    PluginRegistry& r = PluginRegistry::instance();
    r.registerBuiltins();
    OverrideGuard guard(r);
    // Defaults come from the spec...
    CHECK(r.enabled("tracker-block") == true);
    CHECK(r.enabled("https-only") == false);
    CHECK(r.enabled("telemetry") == false);
    // ...an override wins over the default...
    r.setEnabled("https-only", true);
    CHECK(r.enabled("https-only") == true);
    r.setEnabled("tracker-block", false);
    CHECK(r.enabled("tracker-block") == false);
    // ...clearing restores the default...
    r.clearOverride("tracker-block");
    CHECK(r.enabled("tracker-block") == true);
    // ...and an unknown id defaults to off rather than crashing.
    CHECK(r.enabled("no-such-plugin") == false);
    // hasOverride reflects only explicit user choices.
    CHECK(r.hasOverride("https-only"));
    CHECK(!r.hasOverride("tracker-block"));
}

LETHE_TEST_CASE(PluginRegistry_JsonRoundTrip) {
    PluginRegistry& r = PluginRegistry::instance();
    r.registerBuiltins();
    OverrideGuard guard(r);
    r.setEnabled("vpn", false);
    r.setEnabled("https-only", true);
    r.setEnabled("telemetry", true);
    const std::string json = r.toJson();

    // A fresh load on top of cleared state must land on the same choices.
    for (const auto& p : r.plugins()) r.clearOverride(p.id);
    CHECK(r.enabled("vpn") == true);   // back to default first
    r.loadOverridesJson(json);
    CHECK(r.enabled("vpn") == false);
    CHECK(r.enabled("https-only") == true);
    CHECK(r.enabled("telemetry") == true);
    CHECK(r.enabled("tracker-block") == true);  // untouched default
}

LETHE_TEST_CASE(PluginRegistry_UnknownIdsIgnored) {
    PluginRegistry& r = PluginRegistry::instance();
    r.registerBuiltins();
    OverrideGuard guard(r);
    r.loadOverridesJson("{\"plugins\":[{\"id\":\"future-plugin\",\"enabled\":true},"
                        "{\"id\":\"vpn\",\"enabled\":false},{\"garbage\"}]}");
    CHECK(r.find("future-plugin") == nullptr);  // not registered: ignored
    CHECK(r.enabled("vpn") == false);           // known id still applied
}

LETHE_TEST_CASE(PluginRegistry_ApplyToFlipsLiveFlags) {
    PluginRegistry& r = PluginRegistry::instance();
    r.registerBuiltins();
    OverrideGuard guard(r);
    r.setEnabled("https-first", false);
    r.setEnabled("tracker-block", false);
    r.setEnabled("stealth-ua", true);
    r.setEnabled("vpn", false);  // has an apply hook, but engine is null here

    ShellContext ctx;
    ctx.httpsFirst = true;
    ctx.trackerBlocking = true;
    ctx.cfg.userAgentMode = "standard";
    r.applyTo(ctx);
    CHECK(ctx.httpsFirst == false);
    CHECK(ctx.trackerBlocking == false);
    CHECK(ctx.cfg.userAgentMode == "stealth");  // stealth-ua applied
}

LETHE_TEST_CASE(PluginRegistry_RestartHonesty) {
    // Plugins that cannot be applied to a running shell must say so, so no
    // settings surface promises a live toggle the engine cannot deliver.
    PluginRegistry& r = PluginRegistry::instance();
    r.registerBuiltins();
    for (const char* id : {"policy-proxy", "secure-dns", "doh-cache", "doh-pool",
                           "private-net-isolation", "persistent-cookies",
                           "hardware-accel"}) {
        const PluginSpec* p = r.find(id);
        CHECK(p != nullptr);
        CHECK(p->requiresRestart);
    }
    // The live-toggled ones must not carry the restart flag.
    for (const char* id : {"https-first", "tracker-block", "stealth-ua", "vpn"}) {
        const PluginSpec* p = r.find(id);
        CHECK(p != nullptr);
        CHECK(!p->requiresRestart);
        CHECK(p->apply != nullptr);
    }
}
