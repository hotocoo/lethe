// main_window.cc - GTK3 browser shell (see header)

#include "main_window.h"

#include <glib.h>
#include <gdk/gdkkeysyms.h>

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <thread>

#include "browser/url_input.h"
#include "config.h"
#include "renderer/html_view.h"
#include "renderer/page_templates.h"
#include "viewport.h"

namespace lethe {

namespace {

constexpr const char kTabKey[] = "lethe-tab";

std::unique_ptr<HttpClient> makeClient(Engine* engine, const ShellOptions& o) {
    auto c = std::make_unique<HttpClient>();
    c->initialize(o.tls);
    const Config& cfg = engine->config();
    if (!cfg.dnsProvider.empty()) c->setDohProvider(cfg.dnsProvider);
    PrivateNetworkPolicy pn;
    pn.isolatePrivateNetworks = cfg.isolatePrivateNetworks;
    for (const auto& h : cfg.privateNetworkAllowedHosts) pn.allowedHosts.insert(h);
    c->setPrivateNetworkPolicy(pn);
    if (engine->vpnTunnel()) {
        c->setVpnTunnel(std::shared_ptr<vpn::VpnTunnel>(engine->vpnTunnel(),
                                                        [](vpn::VpnTunnel*) {}));
    }
    return c;
}

bool debugLoads() {
    static const bool on = std::getenv("LETHE_DEBUG") != nullptr;
    return on;
}

bool isWebScheme(const std::string& url) {
    return url.rfind("http://", 0) == 0 || url.rfind("https://", 0) == 0;
}

std::string hostOf(const std::string& url) {
    const size_t s = url.find("://");
    if (s == std::string::npos) return "";
    const size_t b = s + 3;
    const size_t e = url.find_first_of("/?#", b);
    std::string h = url.substr(b, e == std::string::npos ? std::string::npos : e - b);
    const size_t at = h.rfind('@');
    if (at != std::string::npos) h = h.substr(at + 1);
    return h;
}

// Main-loop hop for results computed on worker threads.
template <typename F>
void onMainLoop(F fn) {
    auto* heap = new F(std::move(fn));
    g_idle_add([](gpointer data) -> gboolean {
        auto* f = static_cast<F*>(data);
        (*f)();
        delete f;
        return G_SOURCE_REMOVE;
    }, heap);
}

} // namespace

// All GTK callbacks live here; declared friend so they reach private state.
struct MainWindowSignals {
    static void onDestroy(GtkWidget*, gpointer) { gtk_main_quit(); }

    static void onEntryActivate(GtkEntry* entry, gpointer data) {
        auto* self = static_cast<MainWindow*>(data);
        self->addressEditing_ = false;
        MainWindow::Tab* tab = self->currentTab();
        if (!tab) tab = self->newTab();
        self->loadAddress(tab, gtk_entry_get_text(entry));
        gtk_widget_grab_focus(tab->container);
    }
    static void onEntryChanged(GtkEditable*, gpointer data) {
        auto* self = static_cast<MainWindow*>(data);
        // Only keystrokes count as editing; programmatic updates do not.
        if (!self->settingEntryText_ && gtk_widget_has_focus(self->entry_)) self->addressEditing_ = true;
    }
    static gboolean onEntryFocusOut(GtkWidget*, GdkEvent*, gpointer data) {
        auto* self = static_cast<MainWindow*>(data);
        self->addressEditing_ = false;
        self->updateChrome();
        return FALSE;
    }
    static void onBack(GtkButton*, gpointer d) { auto* s = static_cast<MainWindow*>(d); s->goBack(s->currentTab()); }
    static void onForward(GtkButton*, gpointer d) { auto* s = static_cast<MainWindow*>(d); s->goForward(s->currentTab()); }
    static void onReloadOrStop(GtkButton*, gpointer d) {
        auto* s = static_cast<MainWindow*>(d);
        MainWindow::Tab* t = s->currentTab();
        if (t && s->busy(t)) s->stop(t); else s->reload(t);
    }
    static void onReader(GtkButton*, gpointer d) { auto* s = static_cast<MainWindow*>(d); s->toggleReader(s->currentTab()); }
    static void onNewTab(GtkButton*, gpointer d) { static_cast<MainWindow*>(d)->newTab(); }
    static void onCloseTabClicked(GtkButton* b, gpointer d) {
        auto* self = static_cast<MainWindow*>(d);
        auto* tab = static_cast<MainWindow::Tab*>(g_object_get_data(G_OBJECT(b), kTabKey));
        if (tab) self->closeTab(tab);
    }
    static void onSwitchPage(GtkNotebook*, GtkWidget*, guint, gpointer d) {
        auto* self = static_cast<MainWindow*>(d);
        if (!self->suppressSwitch_) self->updateChrome();
    }
    static gboolean onKeyPress(GtkWidget*, GdkEventKey* e, gpointer d) {
        return static_cast<MainWindow*>(d)->handleKey(e) ? TRUE : FALSE;
    }
    static void onMenuNewTab(GtkMenuItem*, gpointer d) { static_cast<MainWindow*>(d)->newTab(); }
    static void onMenuCloseTab(GtkMenuItem*, gpointer d) { auto* s = static_cast<MainWindow*>(d); s->closeTab(s->currentTab()); }
    static void onMenuReader(GtkMenuItem*, gpointer d) { auto* s = static_cast<MainWindow*>(d); s->toggleReader(s->currentTab()); }
    static void onMenuFind(GtkMenuItem*, gpointer d) { static_cast<MainWindow*>(d)->showFindBar(); }
    static void onMenuZoomIn(GtkMenuItem*, gpointer d) { auto* s = static_cast<MainWindow*>(d); s->zoom(s->currentTab(), 1.1); }
    static void onMenuZoomOut(GtkMenuItem*, gpointer d) { auto* s = static_cast<MainWindow*>(d); s->zoom(s->currentTab(), 1 / 1.1); }
    static void onMenuZoomReset(GtkMenuItem*, gpointer d) { auto* s = static_cast<MainWindow*>(d); s->zoom(s->currentTab(), 0); }
    static void onMenuStatus(GtkMenuItem*, gpointer d) {
        auto* self = static_cast<MainWindow*>(d);
        GtkWidget* dlg = gtk_message_dialog_new(GTK_WINDOW(self->window_), GTK_DIALOG_MODAL,
            GTK_MESSAGE_INFO, GTK_BUTTONS_OK, "%s", self->securityStatusText().c_str());
        gtk_window_set_title(GTK_WINDOW(dlg), "Security status");
        gtk_dialog_run(GTK_DIALOG(dlg));
        gtk_widget_destroy(dlg);
    }
    static void onMenuAbout(GtkMenuItem*, gpointer d) {
        auto* self = static_cast<MainWindow*>(d);
        gtk_show_about_dialog(GTK_WINDOW(self->window_),
            "program-name", "Lethe", "version", LETHE_VERSION,
            "comments", "Private-by-default browser for Aletheia OS.",
            "website", "https://github.com/hotocoo/lethe", "license-type", GTK_LICENSE_APACHE_2_0,
            nullptr);
    }
    static void onMenuQuit(GtkMenuItem*, gpointer) { gtk_main_quit(); }
    static void onFindChanged(GtkSearchEntry* e, gpointer d) {
        auto* self = static_cast<MainWindow*>(d);
        (void)self; (void)e;
#if defined(HAVE_FULLWEB)
        MainWindow::Tab* tab = self->currentTab();
        if (!tab || !tab->web) return;
        const char* text = gtk_entry_get_text(GTK_ENTRY(e));
        WebKitFindController* fc = webkit_web_view_get_find_controller(tab->web);
        if (!text || !*text) { webkit_find_controller_search_finish(fc); return; }
        webkit_find_controller_search(fc, text,
            WEBKIT_FIND_OPTIONS_CASE_INSENSITIVE | WEBKIT_FIND_OPTIONS_WRAP_AROUND, G_MAXUINT);
#endif
    }
    static void onFindNext(GtkEntry*, gpointer d) {
#if defined(HAVE_FULLWEB)
        auto* self = static_cast<MainWindow*>(d);
        MainWindow::Tab* tab = self->currentTab();
        if (tab && tab->web) webkit_find_controller_search_next(webkit_web_view_get_find_controller(tab->web));
#else
        (void)d;
#endif
    }
    static void onFindStop(GtkSearchEntry*, gpointer d) { static_cast<MainWindow*>(d)->hideFindBar(); }

#if defined(HAVE_FULLWEB)
    static void onFoundText(WebKitFindController*, guint count, gpointer d) {
        auto* self = static_cast<MainWindow*>(d);
        gtk_label_set_text(GTK_LABEL(self->findStatus_), count ? "" : "");
    }
    static void onFailedToFind(WebKitFindController*, gpointer d) {
        auto* self = static_cast<MainWindow*>(d);
        gtk_label_set_text(GTK_LABEL(self->findStatus_), "Not found");
    }
    static void onLoadChanged(WebKitWebView* web, WebKitLoadEvent ev, gpointer d) {
        auto* tab = static_cast<MainWindow::Tab*>(d);
        MainWindow* self = tab->owner;
        const char* uri = webkit_web_view_get_uri(web);
        if (debugLoads()) {
            std::cout << "[lethe-debug] load-changed " << static_cast<int>(ev) << " "
                      << (uri ? uri : "") << " loading=" << webkit_web_view_is_loading(web) << std::endl;
        }
        // is-loading can stay TRUE after a history (page-cache) navigation
        // finishes; the load-changed sequence is the reliable signal.
        if (ev == WEBKIT_LOAD_STARTED) tab->loading = true;
        if (ev == WEBKIT_LOAD_FINISHED) tab->loading = false;
        if (ev == WEBKIT_LOAD_STARTED) {
            if (tab->readerLoadPending) {
                tab->readerLoadPending = false;
            } else {
                tab->readerActive = false;
                if (uri && strcmp(uri, "about:blank") != 0) tab->internalPageUrl.clear();
            }
        }
        if (uri && strcmp(uri, "about:blank") != 0 && tab->internalPageUrl.empty()) tab->url = uri;
        if (ev == WEBKIT_LOAD_FINISHED) {
            const char* title = webkit_web_view_get_title(web);
            self->setTabTitle(tab, title && *title ? title : hostOf(tab->url));
        }
        self->updateChrome();
    }
    static gboolean onLoadFailed(WebKitWebView*, WebKitLoadEvent, gchar* failingUri, GError* error, gpointer d) {
        auto* tab = static_cast<MainWindow::Tab*>(d);
        tab->loading = false;
        if (g_error_matches(error, WEBKIT_NETWORK_ERROR, WEBKIT_NETWORK_ERROR_CANCELLED)) return FALSE;
        if (g_error_matches(error, WEBKIT_POLICY_ERROR, WEBKIT_POLICY_ERROR_FRAME_LOAD_INTERRUPTED_BY_POLICY_CHANGE)) return FALSE;
        std::cerr << "[lethe] load failed " << (failingUri ? failingUri : "") << ": "
                  << (error ? error->message : "") << std::endl;
        tab->owner->showErrorPage(tab, failingUri ? failingUri : "", error ? error->message : "load failed");
        return TRUE;
    }
    static void onNotifyTitle(GObject* obj, GParamSpec*, gpointer d) {
        auto* tab = static_cast<MainWindow::Tab*>(d);
        const char* title = webkit_web_view_get_title(WEBKIT_WEB_VIEW(obj));
        if (title && *title) tab->owner->setTabTitle(tab, title);
    }
    static void onNotifyProgress(GObject*, GParamSpec*, gpointer d) {
        static_cast<MainWindow::Tab*>(d)->owner->updateChrome();
    }
    static gboolean onDecidePolicy(WebKitWebView*, WebKitPolicyDecision* decision,
                                   WebKitPolicyDecisionType type, gpointer d) {
        auto* tab = static_cast<MainWindow::Tab*>(d);
        tab->owner->decidePolicy(tab, decision, type);
        return TRUE;
    }
    static GtkWidget* onCreate(WebKitWebView* web, WebKitNavigationAction*, gpointer d) {
        auto* tab = static_cast<MainWindow::Tab*>(d);
        MainWindow* self = tab->owner;
        WebKitWebView* child = self->makeWebView(web);
        self->newTabWithView(child);
        return GTK_WIDGET(child);
    }
    static void onClose(WebKitWebView*, gpointer d) {
        auto* tab = static_cast<MainWindow::Tab*>(d);
        tab->owner->closeTab(tab);
    }
    static gboolean onWebProcessTerminated(WebKitWebView* web, WebKitWebProcessTerminationReason, gpointer) {
        std::cerr << "[lethe] web process terminated; reloading" << std::endl;
        webkit_web_view_reload(web);
        return TRUE;
    }
    static gboolean onDecideDestination(WebKitDownload* download, gchar* suggested, gpointer) {
        const char* dir = g_get_user_special_dir(G_USER_DIRECTORY_DOWNLOAD);
        std::string base = dir ? dir : (g_get_home_dir() ? g_get_home_dir() : "/tmp");
        std::string name = suggested && *suggested ? suggested : "download";
        for (char& c : name) if (c == '/') c = '_';
        std::string path = base + "/" + name;
        for (int i = 1; g_file_test(path.c_str(), G_FILE_TEST_EXISTS) && i < 1000; i++) {
            path = base + "/" + name + " (" + std::to_string(i) + ")";
        }
        gchar* uri = g_filename_to_uri(path.c_str(), nullptr, nullptr);
        webkit_download_set_destination(download, uri);
        std::cout << "[lethe] download -> " << path << std::endl;
        g_free(uri);
        return TRUE;
    }
    static void onDownloadFinished(WebKitDownload* download, gpointer) {
        std::cout << "[lethe] download finished: " << webkit_download_get_destination(download) << std::endl;
    }
    static void onDownloadFailed(WebKitDownload*, GError* error, gpointer) {
        std::cerr << "[lethe] download failed: " << (error ? error->message : "") << std::endl;
    }
    static void onDownloadStarted(WebKitWebContext*, WebKitDownload* download, gpointer d) {
        g_signal_connect(download, "decide-destination", G_CALLBACK(onDecideDestination), d);
        g_signal_connect(download, "finished", G_CALLBACK(onDownloadFinished), d);
        g_signal_connect(download, "failed", G_CALLBACK(onDownloadFailed), d);
    }
#endif
};

MainWindow::MainWindow(Engine* engine, ShellOptions options)
    : engine_(engine), options_(std::move(options)) {
    policyChecker_ = makeClient(engine_, options_);
    readerClient_ = makeClient(engine_, options_);
}

MainWindow::~MainWindow() = default;

void MainWindow::create() {
    window_ = gtk_window_new(GTK_WINDOW_TOPLEVEL);
    gtk_window_set_title(GTK_WINDOW(window_), "Lethe");
    gtk_window_set_default_size(GTK_WINDOW(window_), 1280, 860);
    g_signal_connect(window_, "destroy", G_CALLBACK(MainWindowSignals::onDestroy), nullptr);
    g_signal_connect(window_, "key-press-event", G_CALLBACK(MainWindowSignals::onKeyPress), this);
    buildChrome();
#if defined(HAVE_FULLWEB)
    g_signal_connect(webContext(), "download-started",
                     G_CALLBACK(MainWindowSignals::onDownloadStarted), this);
#endif
}

void MainWindow::buildChrome() {
    headerBar_ = gtk_header_bar_new();
    gtk_header_bar_set_show_close_button(GTK_HEADER_BAR(headerBar_), TRUE);
    gtk_window_set_titlebar(GTK_WINDOW(window_), headerBar_);

    auto iconButton = [](const char* icon, const char* tip) {
        GtkWidget* b = gtk_button_new_from_icon_name(icon, GTK_ICON_SIZE_BUTTON);
        gtk_widget_set_tooltip_text(b, tip);
        gtk_button_set_relief(GTK_BUTTON(b), GTK_RELIEF_NONE);
        return b;
    };
    backButton_ = iconButton("go-previous-symbolic", "Back (Alt+Left)");
    forwardButton_ = iconButton("go-next-symbolic", "Forward (Alt+Right)");
    reloadButton_ = iconButton("view-refresh-symbolic", "Reload (Ctrl+R)");
    readerButton_ = iconButton("format-justify-fill-symbolic", "Reader view (Ctrl+Shift+R)");
    GtkWidget* newTabButton = iconButton("tab-new-symbolic", "New tab (Ctrl+T)");
    g_signal_connect(backButton_, "clicked", G_CALLBACK(MainWindowSignals::onBack), this);
    g_signal_connect(forwardButton_, "clicked", G_CALLBACK(MainWindowSignals::onForward), this);
    g_signal_connect(reloadButton_, "clicked", G_CALLBACK(MainWindowSignals::onReloadOrStop), this);
    g_signal_connect(readerButton_, "clicked", G_CALLBACK(MainWindowSignals::onReader), this);
    g_signal_connect(newTabButton, "clicked", G_CALLBACK(MainWindowSignals::onNewTab), this);

    GtkWidget* navBox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_style_context_add_class(gtk_widget_get_style_context(navBox), "linked");
    gtk_box_pack_start(GTK_BOX(navBox), backButton_, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(navBox), forwardButton_, FALSE, FALSE, 0);
    gtk_header_bar_pack_start(GTK_HEADER_BAR(headerBar_), navBox);
    gtk_header_bar_pack_start(GTK_HEADER_BAR(headerBar_), reloadButton_);

    entry_ = gtk_entry_new();
    gtk_entry_set_placeholder_text(GTK_ENTRY(entry_), "Search or enter address");
    gtk_entry_set_icon_from_icon_name(GTK_ENTRY(entry_), GTK_ENTRY_ICON_PRIMARY, "web-browser-symbolic");
    gtk_widget_set_hexpand(entry_, TRUE);
    gtk_widget_set_size_request(entry_, 420, -1);
    g_signal_connect(entry_, "activate", G_CALLBACK(MainWindowSignals::onEntryActivate), this);
    g_signal_connect(entry_, "changed", G_CALLBACK(MainWindowSignals::onEntryChanged), this);
    g_signal_connect(entry_, "focus-out-event", G_CALLBACK(MainWindowSignals::onEntryFocusOut), this);
    gtk_header_bar_set_custom_title(GTK_HEADER_BAR(headerBar_), entry_);

    menuButton_ = gtk_menu_button_new();
    gtk_button_set_image(GTK_BUTTON(menuButton_),
        gtk_image_new_from_icon_name("open-menu-symbolic", GTK_ICON_SIZE_BUTTON));
    GtkWidget* menu = gtk_menu_new();
    auto item = [&](const char* label, GCallback cb) {
        GtkWidget* it = gtk_menu_item_new_with_label(label);
        g_signal_connect(it, "activate", cb, this);
        gtk_menu_shell_append(GTK_MENU_SHELL(menu), it);
    };
    item("New Tab                  Ctrl+T", G_CALLBACK(MainWindowSignals::onMenuNewTab));
    item("Close Tab                Ctrl+W", G_CALLBACK(MainWindowSignals::onMenuCloseTab));
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), gtk_separator_menu_item_new());
    item("Find in Page             Ctrl+F", G_CALLBACK(MainWindowSignals::onMenuFind));
    item("Reader View        Ctrl+Shift+R", G_CALLBACK(MainWindowSignals::onMenuReader));
    item("Zoom In                  Ctrl++", G_CALLBACK(MainWindowSignals::onMenuZoomIn));
    item("Zoom Out                 Ctrl+-", G_CALLBACK(MainWindowSignals::onMenuZoomOut));
    item("Actual Size              Ctrl+0", G_CALLBACK(MainWindowSignals::onMenuZoomReset));
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), gtk_separator_menu_item_new());
    item("Security Status…", G_CALLBACK(MainWindowSignals::onMenuStatus));
    item("About Lethe", G_CALLBACK(MainWindowSignals::onMenuAbout));
    gtk_menu_shell_append(GTK_MENU_SHELL(menu), gtk_separator_menu_item_new());
    item("Quit                     Ctrl+Q", G_CALLBACK(MainWindowSignals::onMenuQuit));
    gtk_widget_show_all(menu);
    gtk_menu_button_set_popup(GTK_MENU_BUTTON(menuButton_), menu);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(headerBar_), menuButton_);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(headerBar_), readerButton_);

    box_ = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_container_add(GTK_CONTAINER(window_), box_);

    notebook_ = gtk_notebook_new();
    gtk_notebook_set_scrollable(GTK_NOTEBOOK(notebook_), TRUE);
    gtk_notebook_set_show_border(GTK_NOTEBOOK(notebook_), FALSE);
    gtk_notebook_set_action_widget(GTK_NOTEBOOK(notebook_), newTabButton, GTK_PACK_END);
    gtk_widget_show(newTabButton);
    g_signal_connect(notebook_, "switch-page", G_CALLBACK(MainWindowSignals::onSwitchPage), this);
    gtk_box_pack_start(GTK_BOX(box_), notebook_, TRUE, TRUE, 0);

    findRevealer_ = gtk_revealer_new();
    GtkWidget* findBox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_container_set_border_width(GTK_CONTAINER(findBox), 6);
    findEntry_ = gtk_search_entry_new();
    gtk_widget_set_size_request(findEntry_, 320, -1);
    g_signal_connect(findEntry_, "search-changed", G_CALLBACK(MainWindowSignals::onFindChanged), this);
    g_signal_connect(findEntry_, "activate", G_CALLBACK(MainWindowSignals::onFindNext), this);
    g_signal_connect(findEntry_, "stop-search", G_CALLBACK(MainWindowSignals::onFindStop), this);
    findStatus_ = gtk_label_new("");
    GtkWidget* findDone = gtk_button_new_with_label("Done");
    g_signal_connect(findDone, "clicked", G_CALLBACK(MainWindowSignals::onFindStop), this);
    gtk_box_pack_start(GTK_BOX(findBox), findEntry_, FALSE, FALSE, 0);
    gtk_box_pack_start(GTK_BOX(findBox), findStatus_, FALSE, FALSE, 0);
    gtk_box_pack_end(GTK_BOX(findBox), findDone, FALSE, FALSE, 0);
    gtk_container_add(GTK_CONTAINER(findRevealer_), findBox);
    gtk_box_pack_end(GTK_BOX(box_), findRevealer_, FALSE, FALSE, 0);
}

void MainWindow::show() {
    gtk_widget_show_all(window_);
    if (tabs_.empty()) newTab();
    gtk_widget_grab_focus(entry_);
}

#if defined(HAVE_FULLWEB)
WebKitWebContext* MainWindow::webContext() {
    if (context_) return context_;
    context_ = options_.persistent ? webkit_web_context_get_default()
                                   : webkit_web_context_new_ephemeral();
    std::cout << "[lethe] web context: "
              << (options_.persistent ? "persistent" : "ephemeral (incognito)") << std::endl;
    if (options_.proxyPort > 0) {
        const std::string proxyUri = "http://127.0.0.1:" + std::to_string(options_.proxyPort);
        WebKitNetworkProxySettings* s = webkit_network_proxy_settings_new(proxyUri.c_str(), nullptr);
        webkit_web_context_set_network_proxy_settings(context_, WEBKIT_NETWORK_PROXY_MODE_CUSTOM, s);
        webkit_network_proxy_settings_free(s);
        std::cout << "[lethe] WebKit traffic routed through policy proxy " << proxyUri
                  << " (subresource enforcement on)" << std::endl;
    }
    webkit_web_context_set_sandbox_enabled(context_, options_.webkitSandbox ? TRUE : FALSE);
    return context_;
}

WebKitWebView* MainWindow::makeWebView(WebKitWebView* related) {
    WebKitWebView* web = related
        ? WEBKIT_WEB_VIEW(webkit_web_view_new_with_related_view(related))
        : WEBKIT_WEB_VIEW(webkit_web_view_new_with_context(webContext()));
    WebKitSettings* s = webkit_web_view_get_settings(web);
    webkit_settings_set_javascript_can_open_windows_automatically(s, FALSE);
    webkit_settings_set_enable_developer_extras(s, TRUE);
    webkit_settings_set_enable_fullscreen(s, TRUE);
    webkit_settings_set_enable_smooth_scrolling(s, TRUE);
    if (engine_->config().userAgentMode == "stealth") {
        webkit_settings_set_user_agent(s, stealthUserAgentString());
    }
    return web;
}

void MainWindow::attachWebSignals(Tab* tab) {
    WebKitWebView* w = tab->web;
    g_signal_connect(w, "load-changed", G_CALLBACK(MainWindowSignals::onLoadChanged), tab);
    g_signal_connect(w, "load-failed", G_CALLBACK(MainWindowSignals::onLoadFailed), tab);
    g_signal_connect(w, "notify::title", G_CALLBACK(MainWindowSignals::onNotifyTitle), tab);
    g_signal_connect(w, "notify::estimated-load-progress", G_CALLBACK(MainWindowSignals::onNotifyProgress), tab);
    g_signal_connect(w, "notify::is-loading", G_CALLBACK(MainWindowSignals::onNotifyProgress), tab);
    g_signal_connect(w, "notify::uri", G_CALLBACK(MainWindowSignals::onNotifyProgress), tab);
    g_signal_connect(w, "decide-policy", G_CALLBACK(MainWindowSignals::onDecidePolicy), tab);
    g_signal_connect(w, "create", G_CALLBACK(MainWindowSignals::onCreate), tab);
    g_signal_connect(w, "close", G_CALLBACK(MainWindowSignals::onClose), tab);
    g_signal_connect(w, "web-process-terminated", G_CALLBACK(MainWindowSignals::onWebProcessTerminated), tab);
    WebKitFindController* fc = webkit_web_view_get_find_controller(w);
    // Signal names vary across WebKitGTK releases; connect only what exists.
    if (g_signal_lookup("found-text", G_OBJECT_TYPE(fc)))
        g_signal_connect(fc, "found-text", G_CALLBACK(MainWindowSignals::onFoundText), this);
    if (g_signal_lookup("failed-to-find", G_OBJECT_TYPE(fc)))
        g_signal_connect(fc, "failed-to-find", G_CALLBACK(MainWindowSignals::onFailedToFind), this);
}

WebKitWebView* MainWindow::webView(Tab* tab) const { return tab ? tab->web : nullptr; }

void MainWindow::decidePolicy(Tab* tab, WebKitPolicyDecision* decision, WebKitPolicyDecisionType type) {
    if (type == WEBKIT_POLICY_DECISION_TYPE_RESPONSE) {
        auto* r = WEBKIT_RESPONSE_POLICY_DECISION(decision);
        if (webkit_response_policy_decision_is_mime_type_supported(r)) webkit_policy_decision_use(decision);
        else webkit_policy_decision_download(decision);
        return;
    }
    auto* nav = WEBKIT_NAVIGATION_POLICY_DECISION(decision);
    WebKitNavigationAction* action = webkit_navigation_policy_decision_get_navigation_action(nav);
    WebKitURIRequest* req = webkit_navigation_action_get_request(action);
    const char* uriC = webkit_uri_request_get_uri(req);
    const std::string uri = uriC ? uriC : "";
    const bool isMainFrame = type == WEBKIT_POLICY_DECISION_TYPE_NAVIGATION_ACTION &&
        webkit_navigation_policy_decision_get_frame_name(nav) == nullptr;
    if (debugLoads()) {
        std::cout << "[lethe-debug] decide-policy type=" << static_cast<int>(type)
                  << " main=" << isMainFrame << " " << uri << std::endl;
    }
    if (type == WEBKIT_POLICY_DECISION_TYPE_NEW_WINDOW_ACTION) {
        // target=_blank / window.open handled by "create"; refuse here to
        // avoid a duplicate top-level load in this tab.
        newTab(uri);
        webkit_policy_decision_ignore(decision);
        return;
    }
    if (uri.rfind("about:", 0) == 0 || uri.rfind("blob:", 0) == 0) { webkit_policy_decision_use(decision); return; }
    if (uri.rfind("data:", 0) == 0) {
        if (isMainFrame) webkit_policy_decision_ignore(decision); else webkit_policy_decision_use(decision);
        return;
    }
    if (!isWebScheme(uri)) {
        std::cerr << "[lethe] refused non-web scheme: " << uri << std::endl;
        webkit_policy_decision_ignore(decision);
        if (isMainFrame && webkit_navigation_action_get_navigation_type(action) == WEBKIT_NAVIGATION_TYPE_LINK_CLICKED) {
            showBlockPage(tab, uri, "scheme is not allowed");
        }
        return;
    }
    // Off the main loop: DoH resolution + policy. Decision stays alive via ref.
    g_object_ref(decision);
    HttpClient* checker = policyChecker_.get();
    std::thread([this, tab, decision, uri, isMainFrame, checker]() {
        static std::mutex gateMutex;   // HttpClient is single-threaded
        std::string reason;
        {
            std::lock_guard<std::mutex> lock(gateMutex);
            reason = checker->policyCheckUrl(uri);
        }
        onMainLoop([this, tab, decision, uri, isMainFrame, reason]() {
            if (debugLoads()) std::cout << "[lethe-debug] decision " << uri << " -> "
                                        << (reason.empty() ? "use" : reason) << std::endl;
            if (reason.empty()) {
                webkit_policy_decision_use(decision);
            } else {
                webkit_policy_decision_ignore(decision);
                std::cerr << "[lethe] policy refused " << uri << ": " << reason << std::endl;
                bool alive = false;
                for (auto& t : tabs_) if (t.get() == tab) alive = true;
                if (alive && isMainFrame) showBlockPage(tab, uri, reason);
            }
            g_object_unref(decision);
        });
    }).detach();
}

MainWindow::Tab* MainWindow::newTabWithView(WebKitWebView* view) {
    auto tab = std::make_unique<Tab>();
    tab->owner = this;
    tab->web = view;
    tab->container = GTK_WIDGET(view);
    Tab* raw = tab.get();
    attachWebSignals(raw);
    tabs_.push_back(std::move(tab));

    raw->labelBox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    raw->label = gtk_label_new("New Tab");
    gtk_label_set_ellipsize(GTK_LABEL(raw->label), PANGO_ELLIPSIZE_END);
    gtk_label_set_width_chars(GTK_LABEL(raw->label), 18);
    gtk_label_set_max_width_chars(GTK_LABEL(raw->label), 22);
    GtkWidget* close = gtk_button_new_from_icon_name("window-close-symbolic", GTK_ICON_SIZE_MENU);
    gtk_button_set_relief(GTK_BUTTON(close), GTK_RELIEF_NONE);
    g_object_set_data(G_OBJECT(close), kTabKey, raw);
    g_signal_connect(close, "clicked", G_CALLBACK(MainWindowSignals::onCloseTabClicked), this);
    gtk_box_pack_start(GTK_BOX(raw->labelBox), raw->label, TRUE, TRUE, 0);
    gtk_box_pack_end(GTK_BOX(raw->labelBox), close, FALSE, FALSE, 0);
    gtk_widget_show_all(raw->labelBox);

    g_object_set_data(G_OBJECT(raw->container), kTabKey, raw);
    const int page = gtk_notebook_append_page(GTK_NOTEBOOK(notebook_), raw->container, raw->labelBox);
    gtk_notebook_set_tab_reorderable(GTK_NOTEBOOK(notebook_), raw->container, TRUE);
    gtk_widget_show_all(raw->container);
    gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook_), page);
    gtk_notebook_set_show_tabs(GTK_NOTEBOOK(notebook_), TRUE);
    updateChrome();
    return raw;
}
#endif

MainWindow::Tab* MainWindow::newTab(const std::string& addressText) {
#if defined(HAVE_FULLWEB)
    Tab* tab = newTabWithView(makeWebView(nullptr));
#else
    auto owned = std::make_unique<Tab>();
    owned->owner = this;
    owned->reader = std::make_unique<Viewport>(engine_);
    GtkWidget* scroller = gtk_scrolled_window_new(nullptr, nullptr);
    gtk_container_add(GTK_CONTAINER(scroller), owned->reader->create());
    owned->container = scroller;
    Tab* tab = owned.get();
    tabs_.push_back(std::move(owned));
    tab->labelBox = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 4);
    tab->label = gtk_label_new("New Tab");
    GtkWidget* close = gtk_button_new_from_icon_name("window-close-symbolic", GTK_ICON_SIZE_MENU);
    gtk_button_set_relief(GTK_BUTTON(close), GTK_RELIEF_NONE);
    g_object_set_data(G_OBJECT(close), kTabKey, tab);
    g_signal_connect(close, "clicked", G_CALLBACK(MainWindowSignals::onCloseTabClicked), this);
    gtk_box_pack_start(GTK_BOX(tab->labelBox), tab->label, TRUE, TRUE, 0);
    gtk_box_pack_end(GTK_BOX(tab->labelBox), close, FALSE, FALSE, 0);
    gtk_widget_show_all(tab->labelBox);
    g_object_set_data(G_OBJECT(tab->container), kTabKey, tab);
    const int page = gtk_notebook_append_page(GTK_NOTEBOOK(notebook_), tab->container, tab->labelBox);
    gtk_widget_show_all(tab->container);
    gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook_), page);
#endif
    if (addressText.empty()) showNewTabPage(tab); else loadAddress(tab, addressText);
    return tab;
}

void MainWindow::closeTab(Tab* tab) {
    if (!tab) return;
    const int page = gtk_notebook_page_num(GTK_NOTEBOOK(notebook_), tab->container);
    if (page >= 0) gtk_notebook_remove_page(GTK_NOTEBOOK(notebook_), page);
    for (auto it = tabs_.begin(); it != tabs_.end(); ++it) {
        if (it->get() == tab) { tabs_.erase(it); break; }
    }
    if (tabs_.empty()) { gtk_widget_destroy(window_); return; }
    updateChrome();
}

MainWindow::Tab* MainWindow::tabForPage(GtkWidget* page) {
    return page ? static_cast<Tab*>(g_object_get_data(G_OBJECT(page), kTabKey)) : nullptr;
}

MainWindow::Tab* MainWindow::tabAt(int index) {
    return tabForPage(gtk_notebook_get_nth_page(GTK_NOTEBOOK(notebook_), index));
}

MainWindow::Tab* MainWindow::currentTab() {
    return tabAt(gtk_notebook_get_current_page(GTK_NOTEBOOK(notebook_)));
}

void MainWindow::setTabTitle(Tab* tab, const std::string& title) {
    tab->title = title.empty() ? "New Tab" : title;
    gtk_label_set_text(GTK_LABEL(tab->label), tab->title.c_str());
    if (tab == currentTab()) gtk_window_set_title(GTK_WINDOW(window_), tab->title.c_str());
}

void MainWindow::updateChrome() {
    Tab* tab = currentTab();
    if (!tab) return;
    if (!addressEditing_) {
        settingEntryText_ = true;
        gtk_entry_set_text(GTK_ENTRY(entry_), tab->url.c_str());
        settingEntryText_ = false;
    }
    gtk_window_set_title(GTK_WINDOW(window_), tab->title.empty() ? "Lethe" : tab->title.c_str());
    const bool https = tab->url.rfind("https://", 0) == 0;
    const bool http = tab->url.rfind("http://", 0) == 0;
    gtk_entry_set_icon_from_icon_name(GTK_ENTRY(entry_), GTK_ENTRY_ICON_PRIMARY,
        https ? "channel-secure-symbolic" : http ? "channel-insecure-symbolic" : "web-browser-symbolic");
    gtk_entry_set_icon_tooltip_text(GTK_ENTRY(entry_), GTK_ENTRY_ICON_PRIMARY,
        https ? "Secure connection (HTTPS)" : http ? "Not secure (plain HTTP)" : "Internal page");
#if defined(HAVE_FULLWEB)
    if (tab->web) {
        gtk_widget_set_sensitive(backButton_, webkit_web_view_can_go_back(tab->web));
        gtk_widget_set_sensitive(forwardButton_, webkit_web_view_can_go_forward(tab->web));
        const bool loading = tab->loading;
        gtk_button_set_image(GTK_BUTTON(reloadButton_), gtk_image_new_from_icon_name(
            loading ? "process-stop-symbolic" : "view-refresh-symbolic", GTK_ICON_SIZE_BUTTON));
        const double p = loading ? webkit_web_view_get_estimated_load_progress(tab->web) : 0.0;
        gtk_entry_set_progress_fraction(GTK_ENTRY(entry_), (loading && p < 1.0) ? p : 0.0);
    }
#else
    gtk_widget_set_sensitive(backButton_, FALSE);
    gtk_widget_set_sensitive(forwardButton_, FALSE);
#endif
}

void MainWindow::showInternalPage(Tab* tab, const std::string& html, const std::string& url) {
    addressEditing_ = false;
    tab->internalPageUrl = url;
    tab->url = url;
#if defined(HAVE_FULLWEB)
    if (tab->web) {
        tab->loading = true;
        webkit_web_view_load_alternate_html(tab->web, html.c_str(),
            url.empty() ? "about:blank" : url.c_str(), nullptr);
    }
#else
    if (tab->reader) tab->reader->showContent(html, "text/html");
#endif
    updateChrome();
}

void MainWindow::showBlockPage(Tab* tab, const std::string& url, const std::string& reason) {
    showInternalPage(tab, renderBlockPage(url, reason), url);
    setTabTitle(tab, "Blocked");
}

void MainWindow::showErrorPage(Tab* tab, const std::string& url, const std::string& message) {
    showInternalPage(tab, renderErrorPage(url, message), url);
    setTabTitle(tab, "Page failed to load");
}

void MainWindow::showNewTabPage(Tab* tab) {
    tab->readerActive = false;
    showInternalPage(tab, renderNewTabPage(), "");
    setTabTitle(tab, "New Tab");
}

void MainWindow::loadAddress(Tab* tab, const std::string& text) {
    if (!tab) return;
    const std::string url = normalizeAddressInput(text);
    if (url.empty() || url == "about:blank") { showNewTabPage(tab); return; }
    loadUrl(tab, url);
}

void MainWindow::loadUrl(Tab* tab, const std::string& url) {
    if (!tab) return;
    addressEditing_ = false;
    tab->internalPageUrl.clear();
    tab->readerActive = false;
    tab->readerLoadPending = false;
    tab->url = url;
#if defined(HAVE_FULLWEB)
    if (tab->web) { tab->loading = true; webkit_web_view_load_uri(tab->web, url.c_str()); }
#else
    if (tab->reader) {
        tab->reader->loadURL(url);
        setTabTitle(tab, hostOf(url));
    }
#endif
    updateChrome();
}

void MainWindow::goBack(Tab* tab) {
#if defined(HAVE_FULLWEB)
    if (tab && tab->web) webkit_web_view_go_back(tab->web);
#else
    (void)tab;
#endif
}

void MainWindow::goForward(Tab* tab) {
#if defined(HAVE_FULLWEB)
    if (tab && tab->web) webkit_web_view_go_forward(tab->web);
#else
    (void)tab;
#endif
}

void MainWindow::reload(Tab* tab) {
    if (!tab) return;
    if (tab->readerActive && !tab->readerSourceUrl.empty()) { loadUrl(tab, tab->readerSourceUrl); return; }
    if (!tab->internalPageUrl.empty()) { loadUrl(tab, tab->internalPageUrl); return; }
#if defined(HAVE_FULLWEB)
    if (tab->web) webkit_web_view_reload(tab->web);
#else
    if (tab->reader) tab->reader->reload();
#endif
}

void MainWindow::stop(Tab* tab) {
    if (tab) tab->loading = false;
#if defined(HAVE_FULLWEB)
    if (tab && tab->web) webkit_web_view_stop_loading(tab->web);
#else
    if (tab && tab->reader) tab->reader->stop();
#endif
}

bool MainWindow::readerActive(Tab* tab) const { return tab && tab->readerActive; }

bool MainWindow::busy(Tab* tab) const {
    if (!tab) return false;
    if (tab->readerFetching) return true;
    return tab->loading;
}

std::string MainWindow::currentUrl(Tab* tab) const { return tab ? tab->url : ""; }
std::string MainWindow::currentTitle(Tab* tab) const { return tab ? tab->title : ""; }
std::string MainWindow::addressText() const { return gtk_entry_get_text(GTK_ENTRY(entry_)); }

void MainWindow::focusAddressBar() {
    gtk_widget_grab_focus(entry_);
    gtk_editable_select_region(GTK_EDITABLE(entry_), 0, -1);
}

void MainWindow::showFindBar() {
    gtk_revealer_set_reveal_child(GTK_REVEALER(findRevealer_), TRUE);
    gtk_widget_grab_focus(findEntry_);
}

void MainWindow::hideFindBar() {
    gtk_revealer_set_reveal_child(GTK_REVEALER(findRevealer_), FALSE);
    gtk_label_set_text(GTK_LABEL(findStatus_), "");
#if defined(HAVE_FULLWEB)
    Tab* tab = currentTab();
    if (tab && tab->web) webkit_find_controller_search_finish(webkit_web_view_get_find_controller(tab->web));
#endif
    Tab* t = currentTab();
    if (t) gtk_widget_grab_focus(t->container);
}

void MainWindow::zoom(Tab* tab, double factor) {
#if defined(HAVE_FULLWEB)
    if (!tab || !tab->web) return;
    if (factor == 0) { webkit_web_view_set_zoom_level(tab->web, 1.0); return; }
    double z = webkit_web_view_get_zoom_level(tab->web) * factor;
    if (z < 0.25) z = 0.25;
    if (z > 5.0) z = 5.0;
    webkit_web_view_set_zoom_level(tab->web, z);
#else
    (void)tab; (void)factor;
#endif
}

void MainWindow::toggleReader(Tab* tab) {
    if (!tab) return;
    if (tab->readerActive) {
        if (!tab->readerSourceUrl.empty()) loadUrl(tab, tab->readerSourceUrl);
        return;
    }
    if (tab->readerFetching || !isWebScheme(tab->url)) return;
    const std::string source = tab->url;
    tab->readerFetching = true;
    HttpClient* client = readerClient_.get();
    std::thread([this, tab, source, client]() {
        static std::mutex readerMutex;
        HttpRequest req;
        req.url = source;
        req.method = HttpMethod::GET;
        req.navigationRequest = true;
        HttpResponse resp;
        {
            std::lock_guard<std::mutex> lock(readerMutex);
            resp = client->sendRequest(req);
        }
        std::string html, finalUrl, error;
        if (resp.success && resp.statusCode >= 200 && resp.statusCode < 300) {
            const std::string body(resp.body.begin(), resp.body.end());
            finalUrl = resp.finalUrl.empty() ? source : resp.finalUrl;
            html = renderReaderPage(finalUrl, HtmlView::extractBlocks(body));
        } else if (resp.success) {
            error = "HTTP " + std::to_string(resp.statusCode);
        } else {
            error = resp.error.empty() ? "request failed" : resp.error;
        }
        onMainLoop([this, tab, source, html, finalUrl, error]() {
            bool alive = false;
            for (auto& t : tabs_) if (t.get() == tab) alive = true;
            if (!alive) return;
            tab->readerFetching = false;
            std::cout << "[lethe] reader fetch " << source << ": "
                      << (error.empty() ? "ok" : error) << std::endl;
            if (!error.empty()) {
                showErrorPage(tab, source, "Reader view unavailable: " + error);
                return;
            }
            tab->readerActive = true;
            tab->readerLoadPending = true;
            tab->readerSourceUrl = source;
            tab->internalPageUrl = finalUrl;
            tab->url = finalUrl;
#if defined(HAVE_FULLWEB)
            if (tab->web) { tab->loading = true; webkit_web_view_load_alternate_html(tab->web, html.c_str(), finalUrl.c_str(), finalUrl.c_str()); }
#else
            if (tab->reader) tab->reader->showContent(html, "text/html");
#endif
            updateChrome();
        });
    }).detach();
}

std::string MainWindow::securityStatusText() const {
    const Config& cfg = engine_->config();
    std::string s = "Lethe v" LETHE_VERSION "\n\n";
    s += "Secure DNS (DoH): " + (cfg.dnsProvider.empty() ? std::string("OFF") : cfg.dnsProvider) + "\n";
    s += std::string("Private-network isolation: ") + (cfg.isolatePrivateNetworks ? "on (SSRF guard)" : "OFF") + "\n";
    s += options_.proxyPort > 0
        ? "Transport enforcement: policy proxy 127.0.0.1:" + std::to_string(options_.proxyPort) + " (every WebKit request)\n"
        : "Transport enforcement: navigation gate only\n";
    s += std::string("Built-in VPN: ") + (engine_->isVpnConnected() ? "connected"
        : cfg.vpnConfig.endpointHost.empty() ? "not configured" : "disconnected") + "\n";
    s += std::string("Site data: ") + (options_.persistent ? "persistent" : "ephemeral (cleared on quit)") + "\n";
#if defined(HAVE_FULLWEB)
    s += std::string("Content sandbox: ") + (options_.webkitSandbox ? "WebKitGTK bwrap + seccomp per web process" : "OFF") + "\n";
#else
    s += std::string("Process sandbox: ") + (cfg.sandboxEnabled ? "seccomp-bpf allowlist" : "OFF") + "\n";
#endif
    s += std::string("User agent: ") + (cfg.userAgentMode == "stealth" ? "stealth (fixed profile)" : "WebKit default") + "\n";
    s += "\nInside https, TLS is WebKit's own; Lethe's TLS 1.3 floor, pins and HSTS cover reader-mode and proxy hops.";
    return s;
}

bool MainWindow::handleKey(GdkEventKey* e) {
    const bool ctrl = e->state & GDK_CONTROL_MASK;
    const bool shift = e->state & GDK_SHIFT_MASK;
    const bool alt = e->state & GDK_MOD1_MASK;
    const guint key = gdk_keyval_to_lower(e->keyval);
    Tab* tab = currentTab();
    if (ctrl && !shift) {
        switch (key) {
            case GDK_KEY_t: newTab(); return true;
            case GDK_KEY_w: closeTab(tab); return true;
            case GDK_KEY_l: focusAddressBar(); return true;
            case GDK_KEY_r: reload(tab); return true;
            case GDK_KEY_f: showFindBar(); return true;
            case GDK_KEY_q: gtk_main_quit(); return true;
            case GDK_KEY_plus: case GDK_KEY_equal: zoom(tab, 1.1); return true;
            case GDK_KEY_minus: zoom(tab, 1 / 1.1); return true;
            case GDK_KEY_0: zoom(tab, 0); return true;
            case GDK_KEY_Tab: case GDK_KEY_Page_Down: gtk_notebook_next_page(GTK_NOTEBOOK(notebook_)); return true;
            case GDK_KEY_Page_Up: gtk_notebook_prev_page(GTK_NOTEBOOK(notebook_)); return true;
            default: break;
        }
        if (key >= GDK_KEY_1 && key <= GDK_KEY_8) {
            gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook_), static_cast<int>(key - GDK_KEY_1));
            return true;
        }
        if (key == GDK_KEY_9) { gtk_notebook_set_current_page(GTK_NOTEBOOK(notebook_), -1); return true; }
    }
    if (ctrl && shift) {
        switch (key) {
            case GDK_KEY_r: toggleReader(tab); return true;
            case GDK_KEY_Tab: case GDK_KEY_ISO_Left_Tab: gtk_notebook_prev_page(GTK_NOTEBOOK(notebook_)); return true;
            default: break;
        }
    }
    if (alt && !ctrl) {
        if (key == GDK_KEY_Left) { goBack(tab); return true; }
        if (key == GDK_KEY_Right) { goForward(tab); return true; }
        if (key == GDK_KEY_Home) { if (options_.homeUrl.empty()) showNewTabPage(tab); else loadAddress(tab, options_.homeUrl); return true; }
    }
    if (key == GDK_KEY_F5) { reload(tab); return true; }
    if (key == GDK_KEY_F11) {
        GdkWindow* gw = gtk_widget_get_window(window_);
        if (gw && (gdk_window_get_state(gw) & GDK_WINDOW_STATE_FULLSCREEN)) gtk_window_unfullscreen(GTK_WINDOW(window_));
        else gtk_window_fullscreen(GTK_WINDOW(window_));
        return true;
    }
    if (key == GDK_KEY_Escape) {
        if (gtk_revealer_get_reveal_child(GTK_REVEALER(findRevealer_))) { hideFindBar(); return true; }
        if (gtk_widget_has_focus(entry_)) { addressEditing_ = false; updateChrome(); if (tab) gtk_widget_grab_focus(tab->container); return true; }
        if (busy(tab)) { stop(tab); return true; }
    }
    return false;
}

} // namespace lethe
