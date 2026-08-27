// main_mac.mm - Lethe entry point on macOS (native AppKit shell)

#import <Cocoa/Cocoa.h>

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

#include "browser/url_input.h"
#include "core/engine.h"
#include "network/policy_proxy.h"
#include "network/tls_config.h"
#include "ui/mac/LetheShell.h"

namespace {

void printHelp() {
    std::cout <<
        "Lethe Browser v" LETHE_VERSION "\n"
        "usage: lethe [options] [url-or-search]\n"
        "  --persistent            keep cookies/site data between runs\n"
        "                          (default: ephemeral, incognito)\n"
        "  --disable-sandbox       do not apply the Seatbelt profile\n"
        "  --dns-provider <url>    DoH provider (default Cloudflare)\n"
        "  --no-proxy              do not route WebKit traffic through the\n"
        "                          local policy proxy (macOS 14+ only)\n"
        "  --e2e-script <file>     run a scripted browsing session and exit\n"
        "  --version, --help\n"
        "Environment: LETHE_SANDBOX, LETHE_DNS_PROVIDER, LETHE_USER_AGENT_MODE,\n"
        "  LETHE_PRIVATE_NET_MODE, LETHE_PRIVATE_NET_ALLOW, LETHE_CERT_PINS\n";
}

} // namespace

int main(int argc, char** argv) {
    lethe::Config cfg;
    cfg.sandboxEnabled = true;
    cfg.incognitoMode = true;
    lethe::applyEnvironmentOverrides(cfg);

    bool persistent = false;
    bool useProxy = true;
    std::string e2eScript;
    if (const char* e = std::getenv("LETHE_MAC_PROXY")) {
        const std::string v(e);
        useProxy = !(v == "0" || v == "off" || v == "false" || v == "no");
    }
    for (int i = 1; i < argc; i++) {
        const std::string a = argv[i];
        if (a == "--help" || a == "-h") { printHelp(); return 0; }
        if (a == "--version") { std::cout << "Lethe Browser v" LETHE_VERSION "\n"; return 0; }
        if (a == "--incognito") { persistent = false; cfg.incognitoMode = true; continue; }
        if (a == "--persistent") { persistent = true; cfg.incognitoMode = false; continue; }
        if (a == "--disable-sandbox") { cfg.sandboxEnabled = false; continue; }
        if (a == "--disable-hardware-acceleration") { cfg.useHardwareAcceleration = false; continue; }
        if (a == "--no-proxy") { useProxy = false; continue; }
        if (a == "--dns-provider" && i + 1 < argc) { cfg.dnsProvider = argv[++i]; continue; }
        if (a == "--e2e-script" && i + 1 < argc) { e2eScript = argv[++i]; continue; }
        if (a.rfind("-psn_", 0) == 0) continue;  // Finder/LaunchServices token
        if (!a.empty() && a[0] != '-') cfg.initialUrl = lethe::normalizeAddressInput(a);
    }

    std::cout << "Lethe Browser v" LETHE_VERSION << std::endl;

    lethe::Engine engine;
    if (engine.initialize(cfg) != 0) {
        std::cerr << "[lethe] Engine init failed" << std::endl;
        return 1;
    }

    lethe::TLSConfig tls;
    tls.init_modern_tls_config(LETHE_MIN_TLS_VERSION, LETHE_MAX_TLS_VERSION);
    if (!cfg.caBundlePath.empty()) tls.setCaBundlePath(cfg.caBundlePath);

    lethe::ShellContext ctx;
    ctx.engine = &engine;
    ctx.cfg = cfg;
    ctx.tls = tls;
    ctx.persistent = persistent;
    ctx.e2eScript = e2eScript;

    lethe::PolicyProxyServer proxy;
    if (useProxy) {
        lethe::PolicyProxyServer::Options po;
        po.tls = tls;
        po.dohProvider = cfg.dnsProvider;
        po.privateNet.isolatePrivateNetworks = cfg.isolatePrivateNetworks;
        for (const auto& h : cfg.privateNetworkAllowedHosts)
            po.privateNet.allowedHosts.insert(h);
        po.vpnTunnel = engine.vpnTunnel();
        po.udpTransport = engine.vpnTransport();
        po.relayHost = cfg.vpnConfig.endpointHost;
        po.relayPort = cfg.vpnConfig.endpointPort;
        if (proxy.start(po)) {
            ctx.proxyPort = proxy.port();
            std::cout << "[lethe] policy proxy listening on 127.0.0.1:"
                      << ctx.proxyPort << std::endl;
        } else {
            std::cerr << "[lethe] policy proxy failed to start: "
                      << proxy.lastError() << " (navigation gate still active)"
                      << std::endl;
        }
    }

    // [NSApp terminate:] never returns from -run; shut down from the
    // delegate's applicationWillTerminate instead.
    ctx.onTerminate = [&]() {
        proxy.stop();
        engine.shutdown();
    };

    @autoreleasepool {
        NSApplication* app = [NSApplication sharedApplication];
        [app setActivationPolicy:NSApplicationActivationPolicyRegular];
        LetheAppDelegate* delegate = [[LetheAppDelegate alloc] initWithContext:&ctx];
        app.delegate = delegate;
        [app run];
    }
    return 0;
}
