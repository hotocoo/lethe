// shell_bootstrap.cc - see shell_bootstrap.h

#include "app/shell_bootstrap.h"

#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>

#include "browser/url_input.h"
#include "network/http_client.h"
#include "plugins/plugin_registry.h"

namespace lethe {

namespace {

void printHelp() {
    std::cout <<
        "Lethe Browser v" LETHE_VERSION "\n"
        "usage: lethe [options] [url-or-search]\n"
        "  --persistent            keep cookies/site data between runs\n"
        "                          (default: ephemeral, incognito)\n"
        "  --disable-sandbox       do not apply the Seatbelt profile\n"
        "  --dns-provider <url>    DoH provider (default Cloudflare)\n"
        "  --no-proxy              do not route engine traffic through the\n"
        "                          local policy proxy (navigation gate only)\n"
        "  --no-https-first        do not upgrade top-level http:// to https://\n"
        "  --no-tracker-block      disable the built-in third-party tracker rules\n"
        "  --e2e-script <file>     run a scripted browsing session and exit\n"
        "  --version, --help\n"
        "Environment: LETHE_SANDBOX, LETHE_DNS_PROVIDER, LETHE_USER_AGENT_MODE,\n"
        "  LETHE_PRIVATE_NET_MODE, LETHE_PRIVATE_NET_ALLOW, LETHE_CERT_PINS,\n"
        "  LETHE_TRACKER_BLOCK, LETHE_HTTPS_FIRST, LETHE_DOH_SHARED_CACHE, LETHE_DOH_POOL\n";
}

bool envOff(const char* name) {
    const char* v = std::getenv(name);
    if (!v) return false;
    const std::string s(v);
    return s == "0" || s == "off" || s == "false" || s == "no";
}

} // namespace

int ShellBootstrap::init(int argc, char** argv, const std::string& engineName) {
    Config& cfg = ctx.cfg;
    cfg.sandboxEnabled = true;
    cfg.incognitoMode = true;
    applyEnvironmentOverrides(cfg);

    bool persistent = false;
    bool httpsFirst = true;
    bool trackerBlock = true;
    std::string e2eScript;
    if (std::getenv("LETHE_MAC_PROXY")) useProxy = !envOff("LETHE_MAC_PROXY");

    for (int i = 1; i < argc; i++) {
        const std::string a = argv[i];
        if (a == "--help" || a == "-h") { printHelp(); return 0; }
        if (a == "--list-plugins") {
            // Every feature as a plugin: id, apply-mode, default, name.
            PluginRegistry::instance().registerBuiltins();
            for (const PluginSpec& p : PluginRegistry::instance().plugins()) {
                std::cout << p.id << "\t"
                          << (p.requiresRestart ? "restart" : "live") << "\t"
                          << (p.defaultOn ? "default-on" : "default-off")
                          << "\t" << p.name << std::endl;
            }
            return 0;
        }
        if (a == "--version") {
            std::cout << "Lethe Browser v" LETHE_VERSION;
            if (!engineName.empty()) std::cout << " (" << engineName << ")";
            std::cout << "\n";
            return 0;
        }
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
        if (a.rfind("--", 0) == 0) continue;     // engine-level switches pass through
        if (!a.empty() && a[0] != '-') cfg.initialUrl = normalizeAddressInput(a);
    }

    std::cout << "Lethe Browser v" LETHE_VERSION;
    if (!engineName.empty()) std::cout << " (" << engineName << ")";
    std::cout << std::endl;

    if (engine.initialize(cfg) != 0) {
        std::cerr << "[lethe] Engine init failed" << std::endl;
        return 1;
    }

    ctx.tls.init_modern_tls_config(LETHE_MIN_TLS_VERSION, LETHE_MAX_TLS_VERSION);
    if (!cfg.caBundlePath.empty()) ctx.tls.setCaBundlePath(cfg.caBundlePath);

    ctx.engine = &engine;
    ctx.persistent = persistent;
    ctx.e2eScript = e2eScript;
    ctx.httpsFirst = httpsFirst;
    ctx.trackerBlocking = trackerBlock;
    if (trackerBlock && std::getenv("LETHE_TRACKER_BLOCK")) ctx.trackerBlocking = !envOff("LETHE_TRACKER_BLOCK");
    if (httpsFirst && std::getenv("LETHE_HTTPS_FIRST")) ctx.httpsFirst = !envOff("LETHE_HTTPS_FIRST");
    // Built-in VPN: defaults ON. LETHE_VPN=0 to disable entirely; the
    // fail-closed loopback tunnel keeps every byte on the policy path
    // until a real endpoint is set via LETHE_VPN_ENDPOINT=host:port.
    if (const char* v = std::getenv("LETHE_VPN")) {
        if (envOff("LETHE_VPN")) cfg.vpnEnabled = false;
        else cfg.vpnEnabled = true;
        (void)v;
    }
    if (const char* ep = std::getenv("LETHE_VPN_ENDPOINT")) {
        const std::string s = ep;
        const auto colon = s.find(':');
        if (colon != std::string::npos) {
            cfg.vpnConfig.endpointHost = s.substr(0, colon);
            cfg.vpnConfig.endpointPort = static_cast<uint16_t>(std::atoi(s.c_str() + colon + 1));
        } else {
            cfg.vpnConfig.endpointHost = s;
            cfg.vpnConfig.endpointPort = 51820;
        }
    }

    if (!envOff("LETHE_DOH_SHARED_CACHE")) ctx.dohCache = std::make_shared<SharedDohCache>();
    const bool usePool = !envOff("LETHE_DOH_POOL");
    if (!cfg.dnsProvider.empty() && usePool) {
        const TLSConfig rtls = ctx.tls;
        const std::string provider = cfg.dnsProvider;
        auto cache = ctx.dohCache;
        ctx.dohResolver = std::make_shared<SharedDohResolver>([rtls, provider, cache]() {
            auto c = std::make_unique<HttpClient>();
            c->initialize(rtls);
            c->setDohProvider(provider);
            if (cache) c->setSharedDohCache(cache);
            return c;
        });
    }

    if (useProxy) {
        PolicyProxyServer::Options po;
        po.tls = ctx.tls;
        po.dohProvider = cfg.dnsProvider;
        po.dohCache = ctx.dohCache;
        po.dohResolver = ctx.dohResolver;
        po.disableDohResolverPool = !usePool;
        po.privateNet.isolatePrivateNetworks = cfg.isolatePrivateNetworks;
        for (const auto& h : cfg.privateNetworkAllowedHosts) po.privateNet.allowedHosts.insert(h);
        // -- v0.1.1 perf: user-defined worker count ----------------------
        // Read from env var (set by the macOS shell from LethePreferences
        // before bootstrap runs). 0 = auto, otherwise literal pool size.
        // Changing this at runtime requires a relaunch; the Settings UI
        // surfaces that explicitly.
        if (const char* wt = std::getenv("LETHE_PROXY_WORKER_THREADS")) {
            const int n = std::atoi(wt);
            if (n > 0) po.workerThreads = static_cast<size_t>(n);
        }
        po.vpnTunnel = engine.vpnTunnel();
        po.udpTransport = engine.vpnTransport();
        po.relayHost = cfg.vpnConfig.endpointHost;
        po.relayPort = cfg.vpnConfig.endpointPort;
        po.authToken = PolicyProxyServer::generateAuthToken();
        if (po.authToken.empty()) {
            std::cerr << "[lethe] cannot generate proxy auth token (CSPRNG failure)" << std::endl;
            engine.shutdown();
            return 1;
        }
        if (proxy.start(po)) {
            ctx.proxyPort = proxy.port();
            ctx.proxyAuthToken = po.authToken;
            std::cout << "[lethe] policy proxy listening on 127.0.0.1:" << ctx.proxyPort
                      << " (per-launch auth token)" << std::endl;
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

    ctx.onTerminate = [this]() { shutdown(); };
    return -1;
}

void ShellBootstrap::shutdown() {
    if (shutDown_) return;
    shutDown_ = true;
    proxy.stop();
    engine.shutdown();
}

} // namespace lethe
