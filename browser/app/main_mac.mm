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
        "  --no-https-first        do not upgrade top-level http:// to https://\n"
        "  --no-tracker-block      disable the built-in third-party tracker rules\n"
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
    bool httpsFirst = true;
    bool trackerBlock = true;
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
        if (a == "--no-https-first") { httpsFirst = false; continue; }
        if (a == "--no-tracker-block") { trackerBlock = false; continue; }
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
    ctx.httpsFirst = httpsFirst;
    ctx.trackerBlocking = trackerBlock;
    if (const char* tb = std::getenv("LETHE_TRACKER_BLOCK"); tb && trackerBlock)
        ctx.trackerBlocking = !(std::string(tb) == "0" || std::string(tb) == "off");
    // One DoH answer cache for the whole browser: gate, reader and every
    // proxied connection resolve a hostname once per TTL.
    // LETHE_DOH_SHARED_CACHE=0 disables it (per-connection resolution, as
    // in 0.1.0) so the effect can be measured with tools/bench.
    if (const char* sc = std::getenv("LETHE_DOH_SHARED_CACHE");
        !(sc && (std::string(sc) == "0" || std::string(sc) == "off")))
        ctx.dohCache = std::make_shared<lethe::SharedDohCache>();
    // Keep-alive resolver pool: DoH queries ride a few persistent TLS
    // connections to the provider instead of one handshake per query.
    // LETHE_DOH_POOL=0 disables the pool (per-query provider handshakes, as
    // in 0.1.0) so its effect can be measured with tools/bench.
    const char* poolEnv = std::getenv("LETHE_DOH_POOL");
    const bool usePool = !(poolEnv && (std::string(poolEnv) == "0" || std::string(poolEnv) == "off"));
    if (!cfg.dnsProvider.empty() && usePool) {
        const lethe::TLSConfig rtls = tls;
        const std::string provider = cfg.dnsProvider;
        auto cache = ctx.dohCache;
        ctx.dohResolver = std::make_shared<lethe::SharedDohResolver>([rtls, provider, cache]() {
            auto c = std::make_unique<lethe::HttpClient>();
            c->initialize(rtls);
            c->setDohProvider(provider);
            if (cache) c->setSharedDohCache(cache);
            return c;
        });
    }

    lethe::PolicyProxyServer proxy;
    if (useProxy) {
        lethe::PolicyProxyServer::Options po;
        po.tls = tls;
        po.dohProvider = cfg.dnsProvider;
        po.dohCache = ctx.dohCache;
        po.dohResolver = ctx.dohResolver;
        po.disableDohResolverPool = !usePool;
        po.privateNet.isolatePrivateNetworks = cfg.isolatePrivateNetworks;
        for (const auto& h : cfg.privateNetworkAllowedHosts)
            po.privateNet.allowedHosts.insert(h);
        po.vpnTunnel = engine.vpnTunnel();
        po.udpTransport = engine.vpnTransport();
        po.relayHost = cfg.vpnConfig.endpointHost;
        po.relayPort = cfg.vpnConfig.endpointPort;
        po.authToken = lethe::PolicyProxyServer::generateAuthToken();
        if (po.authToken.empty()) {
            std::cerr << "[lethe] cannot generate proxy auth token (CSPRNG failure)" << std::endl;
            engine.shutdown();
            return 1;
        }
        if (proxy.start(po)) {
            ctx.proxyPort = proxy.port();
            ctx.proxyAuthToken = po.authToken;
            std::cout << "[lethe] policy proxy listening on 127.0.0.1:"
                      << ctx.proxyPort << " (per-launch auth token)" << std::endl;
        } else {
            // Fail closed: without the proxy only top-level navigations are
            // gated and every subresource would bypass policy. Refuse to run
            // half-protected; --no-proxy is the explicit opt-out.
            std::cerr << "[lethe] policy proxy failed to start: " << proxy.lastError()
                      << "\n[lethe] refusing to run without transport enforcement "
                         "(pass --no-proxy to accept navigation-gate-only mode)" << std::endl;
            engine.shutdown();
            return 1;
        }
    }
    if (const char* hf = std::getenv("LETHE_HTTPS_FIRST"); hf && httpsFirst)
        ctx.httpsFirst = !(std::string(hf) == "0" || std::string(hf) == "off");

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
