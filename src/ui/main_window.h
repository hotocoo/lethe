#ifndef LETHE_UI_MAIN_WINDOW_H
#define LETHE_UI_MAIN_WINDOW_H

// main_window.h - GTK3 browser shell (Linux)
//
// A real browser window: tab strip (GtkNotebook), address bar with search
// fallback, back/forward/reload/stop, progress, find bar, zoom, reader
// view, downloads. Each tab hosts a WebKitGTK view when the engine is
// available (HAVE_FULLWEB) - JavaScript, CSS, media - otherwise the Cairo
// reader Viewport. Every WebKit navigation is gated off the main loop by
// HttpClient::policyCheckUrl (DoH-only, private-network guard, VPN rule)
// and, when a PolicyProxyServer port is given, ALL engine traffic rides
// that proxy so subresources are enforced at the transport layer too.

#include <gtk/gtk.h>
#if defined(HAVE_FULLWEB)
#include <webkit2/webkit2.h>
#endif

#include <functional>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "core/engine.h"
#include "network/http_client.h"
#include "network/tls_config.h"

namespace lethe {

class Viewport;

struct ShellOptions {
    TLSConfig tls;
    int proxyPort = 0;         // local PolicyProxyServer (0 = none)
    std::shared_ptr<SharedDohCache> dohCache;  // shared by gate, reader, proxy
    std::string proxyAuthToken; // per-launch secret WebKit presents to the proxy
    bool httpsFirst = true;     // upgrade top-level http:// to https:// first
    bool trackerBlocking = true; // built-in third-party tracker rules (content filter)
    bool persistent = false;   // false = ephemeral (incognito) web context
    bool webkitSandbox = true; // WebKitGTK content-process sandbox (bwrap)
    std::string homeUrl;
};

class MainWindow {
public:
    MainWindow(Engine* engine, ShellOptions options);
    ~MainWindow();

    MainWindow(const MainWindow&) = delete;
    MainWindow& operator=(const MainWindow&) = delete;

    void create();
    void show();
    GtkWidget* getWidget() { return window_; }

    // --- Browsing API (menu, keyboard, e2e driver) ---
    struct Tab;
    Tab* currentTab();
    Tab* newTab(const std::string& addressText = "");
    void closeTab(Tab* tab);
    size_t tabCount() const { return tabs_.size(); }
    void loadAddress(Tab* tab, const std::string& text);   // URL or search
    void loadUrl(Tab* tab, const std::string& url);
    void goBack(Tab* tab);
    void goForward(Tab* tab);
    void reload(Tab* tab);
    void stop(Tab* tab);
    void toggleReader(Tab* tab);
    bool readerActive(Tab* tab) const;
    bool busy(Tab* tab) const;                 // loading or reader fetch
    std::string currentUrl(Tab* tab) const;
    std::string currentTitle(Tab* tab) const;
    std::string addressText() const;
    void focusAddressBar();
    void showFindBar();
    void hideFindBar();
    void zoom(Tab* tab, double factor);        // 0 = reset
    std::string securityStatusText() const;
#if defined(HAVE_FULLWEB)
    WebKitWebView* webView(Tab* tab) const;
#endif

    struct Tab {
        GtkWidget* container = nullptr;    // notebook page
        GtkWidget* labelBox = nullptr;
        GtkWidget* label = nullptr;
#if defined(HAVE_FULLWEB)
        WebKitWebView* web = nullptr;
#endif
        std::unique_ptr<Viewport> reader;  // fallback renderer (no WebKit)
        std::string url;                   // shown in the address bar
        std::string title;
        bool loading = false;              // tracked from load-changed
        bool readerActive = false;
        bool readerFetching = false;
        bool readerLoadPending = false;
        std::string readerSourceUrl;
        std::string internalPageUrl;       // block/error page for this URL
        std::string httpsUpgradedFrom;     // http URL being tried as https (HTTPS-first)
        MainWindow* owner = nullptr;
    };

private:
    friend struct MainWindowSignals;

    void buildChrome();
    void updateChrome();
    void setTabTitle(Tab* tab, const std::string& title);
    void showInternalPage(Tab* tab, const std::string& html, const std::string& url);
    void showBlockPage(Tab* tab, const std::string& url, const std::string& reason);
    void showErrorPage(Tab* tab, const std::string& url, const std::string& message,
                       const std::string& httpFallback = "");
    std::set<std::string> httpAllowedHosts_;   // HTTPS-first user exemptions
#if defined(HAVE_FULLWEB)
    void prepareTrackerProtection();           // compiles rules before the first view
    WebKitUserContentFilter* trackerFilter_ = nullptr;
#endif
    size_t trackerRuleCount_ = 0;
    void showNewTabPage(Tab* tab);
    Tab* tabForPage(GtkWidget* page);
    Tab* tabAt(int index);
    bool handleKey(GdkEventKey* event);

#if defined(HAVE_FULLWEB)
    WebKitWebContext* webContext();
    WebKitWebView* makeWebView(WebKitWebView* related);
    void attachWebSignals(Tab* tab);
    Tab* newTabWithView(WebKitWebView* view);
    void decidePolicy(Tab* tab, WebKitPolicyDecision* decision,
                      WebKitPolicyDecisionType type);
#endif

    Engine* engine_;
    ShellOptions options_;
    std::unique_ptr<HttpClient> policyChecker_;   // policy-gate thread only
    std::unique_ptr<HttpClient> readerClient_;    // reader-fetch thread only

    GtkWidget* window_ = nullptr;
    GtkWidget* headerBar_ = nullptr;
    GtkWidget* backButton_ = nullptr;
    GtkWidget* forwardButton_ = nullptr;
    GtkWidget* reloadButton_ = nullptr;
    GtkWidget* readerButton_ = nullptr;
    GtkWidget* entry_ = nullptr;
    GtkWidget* menuButton_ = nullptr;
    GtkWidget* notebook_ = nullptr;
    GtkWidget* findRevealer_ = nullptr;
    GtkWidget* findEntry_ = nullptr;
    GtkWidget* findStatus_ = nullptr;
    GtkWidget* box_ = nullptr;
#if defined(HAVE_FULLWEB)
    WebKitWebContext* context_ = nullptr;
#endif
    std::vector<std::unique_ptr<Tab>> tabs_;
    bool addressEditing_ = false;      // user typed since the last load
    bool settingEntryText_ = false;    // programmatic set_text in flight
    bool suppressSwitch_ = false;
};

} // namespace lethe

#endif // LETHE_UI_MAIN_WINDOW_H
