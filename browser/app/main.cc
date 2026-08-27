#include <gtk/gtk.h>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include "core/engine.h"
#include "security/csp_policy.h"
#include "network/tls_config.h"
#include "network/policy_proxy.h"
#include "ui/fullweb.h"
#include "ui/main_window.h"
#include "ui/address_bar.h"
#include "ui/tab_bar.h"
#include "ui/viewport.h"

static void on_window_destroy(GtkWidget* widget, gpointer data) {
    (void)widget; (void)data;
    gtk_main_quit();
}

int main(int argc, char** argv) {
    std::cout << "Lethe Browser v" LETHE_VERSION << std::endl;
    
    gtk_init(&argc, &argv);
    
    // Configuration defaults, then LETHE_* environment overrides. Command
    // line arguments below win over both.
    lethe::Config cfg;
    cfg.sandboxEnabled = true;
    cfg.incognitoMode = true;
    lethe::applyEnvironmentOverrides(cfg);
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--incognito") == 0) {
            cfg.incognitoMode = true;
        } else if (strcmp(argv[i], "--disable-sandbox") == 0) {
            cfg.sandboxEnabled = false;
        } else if (strcmp(argv[i], "--disable-hardware-acceleration") == 0) {
            cfg.useHardwareAcceleration = false;
        } else if (strcmp(argv[i], "--dns-provider") == 0 && i + 1 < argc) {
            i++;
            cfg.dnsProvider = argv[i];
        } else if (argv[i][0] != '-') {
            cfg.initialUrl = argv[i];
        }
    }
    
    // Initialize engine
    lethe::Engine engine;
    int rc = engine.initialize(cfg);
    if (rc != 0) {
        std::cerr << "[lethe] Engine init failed: " << rc << std::endl;
        return 1;
    }
    
    // Initialize security policies
    lethe::CSPPolicy csp;
    csp.set_strict_policy();
    
    // Initialize TLS
    lethe::TLSConfig tls;
    tls.init_modern_tls_config(LETHE_MIN_TLS_VERSION, LETHE_MAX_TLS_VERSION);
    
    // Create main window
    lethe::MainWindow window(&engine);
    window.create();
    
    // --- Full-web mode: platform engine behind Lethe policy (Ctrl+Shift+W)
#if defined(HAVE_FULLWEB)
    lethe::FullWebConfig fw;
    fw.tls = tls;
    fw.dohProvider = cfg.dnsProvider;
    {
        lethe::PrivateNetworkPolicy pn;
        pn.isolatePrivateNetworks = cfg.isolatePrivateNetworks;
        for (const auto& h : cfg.privateNetworkAllowedHosts)
            pn.allowedHosts.insert(h);
        fw.privateNet = pn;
    }
    fw.vpnTunnel = engine.vpnTunnel();
    fw.udpTransport = engine.vpnTransport();
    fw.relayHost = cfg.vpnConfig.endpointHost;
    fw.relayPort = cfg.vpnConfig.endpointPort;

    static lethe::PolicyProxyServer webProxy;   // lives for the app loop
    {
        lethe::PolicyProxyServer::Options po;
        po.tls = tls;
        po.dohProvider = cfg.dnsProvider;
        po.privateNet = fw.privateNet;
        po.vpnTunnel = engine.vpnTunnel();
        po.udpTransport = engine.vpnTransport();
        po.relayHost = fw.relayHost;
        po.relayPort = fw.relayPort;
        if (webProxy.start(po)) fw.proxyPort = webProxy.port();
    }

    window.setFullWebCallback([&fw](const std::string& url) {
        if (url.empty()) return;
        static lethe::FullWebWindow win(fw);
        std::string err;
        if (!win.open(url, err))
            std::cerr << "[lethe-fullweb] " << err << std::endl;
    });
    // Smoke hook: LETHE_FULLWEB_TEST=<url> opens full-web mode at launch.
    const char* fwTest = std::getenv("LETHE_FULLWEB_TEST");
#endif
    
    // Create address bar
    lethe::AddressBar addressBar;
    addressBar.create();
    
    // Create tab bar
    lethe::TabBar tabBar(&engine);
    tabBar.create();
    
    // Create viewport
    lethe::Viewport viewport(&engine);
    viewport.create();
    
    // Connect window destroy signal
    g_signal_connect(window.getWidget(), "destroy", G_CALLBACK(on_window_destroy), nullptr);
    
    // Show window
    window.show();
#if defined(HAVE_FULLWEB)
    if (fwTest && *fwTest) {
        std::string err;
        static lethe::FullWebWindow smoke(fw);
        if (!smoke.open(fwTest, err))
            std::cerr << "[lethe-fullweb] " << err << std::endl;
    }
#endif
    
    // Load initial URL if specified
    if (!cfg.initialUrl.empty()) {
        addressBar.setText(cfg.initialUrl);
        viewport.loadURL(cfg.initialUrl);
    }
    
    // Start GTK main loop
    gtk_main();
    
    // Shutdown engine
    engine.shutdown();
    
    return 0;
}
