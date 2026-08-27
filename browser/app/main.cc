// main.cc - Lethe entry point on Linux (GTK3 shell, WebKitGTK engine)

#include <gtk/gtk.h>

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>

#include "browser/url_input.h"
#include "core/engine.h"
#include "network/policy_proxy.h"
#include "network/tls_config.h"
#include "ui/e2e_driver.h"
#include "ui/main_window.h"

namespace {

void printHelp() {
    std::cout <<
        "Lethe Browser v" LETHE_VERSION "\n"
        "usage: lethe [options] [url-or-search]\n"
        "  --persistent            keep cookies/site data between runs\n"
        "                          (default: ephemeral, incognito)\n"
        "  --disable-sandbox       do not apply the seccomp sandbox\n"
        "  --dns-provider <url>    DoH provider (default Cloudflare)\n"
        "  --no-https-first        do not upgrade top-level http:// to https://\n"
        "  --no-proxy              do not route WebKit traffic through the\n"
        "                          local policy proxy (navigation gate stays)\n"
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
    std::string e2eScript;
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
        if (a == "--dns-provider" && i + 1 < argc) { cfg.dnsProvider = argv[++i]; continue; }
        if (a == "--e2e-script" && i + 1 < argc) { e2eScript = argv[++i]; continue; }
        if (!a.empty() && a[0] != '-') cfg.initialUrl = lethe::normalizeAddressInput(a);
    }

    std::cout << "Lethe Browser v" LETHE_VERSION << std::endl;

    gtk_init(&argc, &argv);

#if defined(HAVE_FULLWEB)
    // Multi-process engine: a default-deny seccomp filter installed in this
    // process would be inherited by every WebKit helper (execve, bwrap,
    // GPU/network processes) and kill them at startup. Web content is
    // sandboxed by WebKitGTK's own bubblewrap + seccomp content sandbox
    // (enabled on the web context); the engine filter stays for the
    // reader-only build and the test suite.
    bool webkitSandbox = cfg.sandboxEnabled;
    if (const char* e = std::getenv("LETHE_WEBKIT_SANDBOX")) {
        const std::string v(e);
        webkitSandbox = !(v == "0" || v == "off" || v == "false" || v == "no");
    }
    if (cfg.sandboxEnabled) {
        std::cout << "[lethe] engine seccomp filter not applied to the GUI process "
                     "(multi-process WebKit); content sandbox: "
                  << (webkitSandbox ? "WebKitGTK bwrap+seccomp" : "OFF (LETHE_WEBKIT_SANDBOX)")
                  << std::endl;
    }
    cfg.sandboxEnabled = false;
#endif

    lethe::Engine engine;
    if (engine.initialize(cfg) != 0) {
        std::cerr << "[lethe] Engine init failed" << std::endl;
        return 1;
    }

    lethe::TLSConfig tls;
    tls.init_modern_tls_config(LETHE_MIN_TLS_VERSION, LETHE_MAX_TLS_VERSION);
    if (!cfg.caBundlePath.empty()) tls.setCaBundlePath(cfg.caBundlePath);

    lethe::ShellOptions shell;
    shell.tls = tls;
    shell.persistent = persistent;
    shell.httpsFirst = httpsFirst;
    if (const char* hf = std::getenv("LETHE_HTTPS_FIRST"); hf && httpsFirst)
        shell.httpsFirst = !(std::string(hf) == "0" || std::string(hf) == "off");
    // One DoH answer cache for the whole browser: gate, reader and every
    // proxied connection resolve a hostname once per TTL.
    // LETHE_DOH_SHARED_CACHE=0 disables it (per-connection resolution, as
    // in 0.1.0) so the effect can be measured with tools/bench.
    if (const char* sc = std::getenv("LETHE_DOH_SHARED_CACHE");
        !(sc && (std::string(sc) == "0" || std::string(sc) == "off")))
        shell.dohCache = std::make_shared<lethe::SharedDohCache>();
#if defined(HAVE_FULLWEB)
    shell.webkitSandbox = webkitSandbox;
#endif

    lethe::PolicyProxyServer proxy;
    if (useProxy) {
        lethe::PolicyProxyServer::Options po;
        po.tls = tls;
        po.dohProvider = cfg.dnsProvider;
        po.dohCache = shell.dohCache;
        po.authToken = lethe::PolicyProxyServer::generateAuthToken();
        if (po.authToken.empty()) {
            std::cerr << "[lethe] cannot generate proxy auth token (CSPRNG failure)" << std::endl;
            engine.shutdown();
            return 1;
        }
        po.privateNet.isolatePrivateNetworks = cfg.isolatePrivateNetworks;
        for (const auto& h : cfg.privateNetworkAllowedHosts) po.privateNet.allowedHosts.insert(h);
        po.vpnTunnel = engine.vpnTunnel();
        po.udpTransport = engine.vpnTransport();
        po.relayHost = cfg.vpnConfig.endpointHost;
        po.relayPort = cfg.vpnConfig.endpointPort;
        if (proxy.start(po)) {
            shell.proxyPort = proxy.port();
            shell.proxyAuthToken = po.authToken;
            std::cout << "[lethe] policy proxy listening on 127.0.0.1:" << shell.proxyPort
                      << " (per-launch auth token)" << std::endl;
        } else {
            // Fail closed: half-protected (navigation gate only) is not a
            // mode Lethe runs in by accident; --no-proxy is the explicit opt-out.
            std::cerr << "[lethe] policy proxy failed to start: " << proxy.lastError()
                      << "\n[lethe] refusing to run without transport enforcement "
                         "(pass --no-proxy to accept navigation-gate-only mode)" << std::endl;
            engine.shutdown();
            return 1;
        }
    }

    lethe::MainWindow window(&engine, shell);
    window.create();
    window.show();
    if (!cfg.initialUrl.empty()) window.loadAddress(window.currentTab(), cfg.initialUrl);

    std::unique_ptr<lethe::E2eDriver> driver;
    if (!e2eScript.empty()) {
        driver = std::make_unique<lethe::E2eDriver>(&window, e2eScript);
        driver->start();
    }

    gtk_main();

    proxy.stop();
    engine.shutdown();
    if (const char* code = std::getenv("LETHE_E2E_EXIT")) return std::atoi(code);
    return 0;
}
