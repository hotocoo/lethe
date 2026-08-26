// test_env_config.cc - LETHE_* environment overrides and UA mode selection.
//
// applyEnvironmentOverrides is the documented runtime configuration path
// (README "Configuration"): environment first, command line second. These
// tests pin each variable's accepted values and the cleanup discipline so
// no test leaks state into another.

#include "test_framework.h"
#include "config.h"
#include "core/engine.h"
#include "network/http_client.h"
#include "network/tls_config.h"

#include <cstdlib>
#include <string>

using namespace lethe;

namespace {

struct EnvGuard {
    explicit EnvGuard(const char* name) : name_(name) { ::unsetenv(name_); }
    ~EnvGuard() { ::unsetenv(name_); }
    const char* name_;
};

} // namespace

LETHE_TEST_CASE(Env_NoVariablesLeavesConfigUntouched) {
    Config cfg;
    cfg.sandboxEnabled = true;
    cfg.dnsProvider = "https://custom.example/dns-query";
    cfg.userAgentMode = "standard";
    applyEnvironmentOverrides(cfg);
    CHECK(cfg.sandboxEnabled == true);
    CHECK(cfg.dnsProvider == "https://custom.example/dns-query");
    CHECK(cfg.userAgentMode == "standard");
}

LETHE_TEST_CASE(Env_SandboxDisableValues) {
    for (const char* off : {"0", "false", "OFF", "no", "No"}) {
        EnvGuard g("LETHE_SANDBOX");
        ::setenv("LETHE_SANDBOX", off, 1);
        Config cfg; // defaults to sandboxEnabled = true
        applyEnvironmentOverrides(cfg);
        CHECK(cfg.sandboxEnabled == false);
    }
}

LETHE_TEST_CASE(Env_SandboxEnableValue) {
    EnvGuard g("LETHE_SANDBOX");
    ::setenv("LETHE_SANDBOX", "1", 1);
    Config cfg;
    cfg.sandboxEnabled = false; // caller wanted off, env forces on
    applyEnvironmentOverrides(cfg);
    CHECK(cfg.sandboxEnabled == true);

    ::setenv("LETHE_SANDBOX", "yes", 1);
    Config cfg2;
    cfg2.sandboxEnabled = false;
    applyEnvironmentOverrides(cfg2);
    CHECK(cfg2.sandboxEnabled == true);
}

LETHE_TEST_CASE(Env_DnsProviderOverride) {
    EnvGuard g("LETHE_DNS_PROVIDER");
    ::setenv("LETHE_DNS_PROVIDER", "https://dns.quad9.net/dns-query", 1);
    Config cfg;
    cfg.dnsProvider = "https://cloudflare-dns.com/dns-query";
    applyEnvironmentOverrides(cfg);
    CHECK(cfg.dnsProvider == "https://dns.quad9.net/dns-query");
}

LETHE_TEST_CASE(Env_DnsProviderDisableValues) {
    for (const char* off : {"none", "off"}) {
        EnvGuard g("LETHE_DNS_PROVIDER");
        ::setenv("LETHE_DNS_PROVIDER", off, 1);
        Config cfg;
        cfg.dnsProvider = "https://cloudflare-dns.com/dns-query";
        applyEnvironmentOverrides(cfg);
        CHECK(cfg.dnsProvider.empty()); // DoH disabled
    }
}

LETHE_TEST_CASE(Env_UserAgentModeStealth) {
    EnvGuard g("LETHE_USER_AGENT_MODE");
    ::setenv("LETHE_USER_AGENT_MODE", "stealth", 1);
    Config cfg;
    cfg.userAgentMode = "standard";
    applyEnvironmentOverrides(cfg);
    CHECK(cfg.userAgentMode == "stealth");

    ::setenv("LETHE_USER_AGENT_MODE", "STEALTH", 1); // case-insensitive
    Config cfg2;
    applyEnvironmentOverrides(cfg2);
    CHECK(cfg2.userAgentMode == "stealth");
}

LETHE_TEST_CASE(Env_UserAgentModeStandardAndUnknown) {
    EnvGuard g("LETHE_USER_AGENT_MODE");
    ::setenv("LETHE_USER_AGENT_MODE", "standard", 1);
    Config cfg;
    cfg.userAgentMode = "stealth";
    applyEnvironmentOverrides(cfg);
    CHECK(cfg.userAgentMode == "standard");

    ::setenv("LETHE_USER_AGENT_MODE", "turbo-mode", 1); // unknown -> standard
    Config cfg2;
    cfg2.userAgentMode = "stealth";
    applyEnvironmentOverrides(cfg2);
    CHECK(cfg2.userAgentMode == "standard");
}

LETHE_TEST_CASE(Env_CertPinsParsing) {
    EnvGuard g("LETHE_CERT_PINS");
    ::setenv("LETHE_CERT_PINS",
             "Example.com=sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA,"
             "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB;"
             "OTHER.test=sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC;"
             "broken;=;=sha256-DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD",
             1);
    Config cfg;
    applyEnvironmentOverrides(cfg);

    CHECK_EQ(cfg.certPins.size(), static_cast<size_t>(2)); // malformed skipped
    CHECK_TRUE(cfg.certPins.count("example.com") == 1);    // lowercased
    CHECK_TRUE(cfg.certPins.count("other.test") == 1);
    CHECK_EQ(cfg.certPins["example.com"].size(), static_cast<size_t>(2));
    CHECK_EQ(cfg.certPins["example.com"][0],
             "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    CHECK_EQ(cfg.certPins["example.com"][1],
             "sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB");
    CHECK_EQ(cfg.certPins["other.test"].size(), static_cast<size_t>(1));
}

LETHE_TEST_CASE(Env_CertPinsUnsetLeavesConfigUntouched) {
    EnvGuard g("LETHE_CERT_PINS"); // unset
    Config cfg;
    cfg.certPins["preset.test"].push_back(
        "sha256-EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE");
    applyEnvironmentOverrides(cfg);
    CHECK_TRUE(cfg.certPins.count("preset.test") == 1);
}

LETHE_TEST_CASE(Ua_ModesResolveToDistinctStrings) {
    const std::string standard = userAgentForMode("standard");
    const std::string stealth = userAgentForMode("stealth");
    const std::string unknown = userAgentForMode("something-else");

    CHECK(!standard.empty());
    CHECK(!stealth.empty());
    CHECK_EQ(userAgentForMode(""), standard);      // default fallback
    CHECK_EQ(unknown, standard);                   // unknown falls back
    // Stealth must be identical on every platform (fixed profile).
    CHECK_EQ(stealth, std::string(
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"));
}
