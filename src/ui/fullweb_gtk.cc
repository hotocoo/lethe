// fullweb_gtk.cc - WebKitGTK backend of Lethe full-web mode (Linux).
//
// WebKitGTK renders real pages (JavaScriptCore + GStreamer media). Deep
// enforcement: when a proxyPort is provided, the DEFAULT WebKit context is
// pointed at Lethe\'s local PolicyProxyServer with
// WEBKIT_NETWORK_PROXY_MODE_CUSTOM, so every request of every subresource
// is DoH-resolved, private-net-checked and tunnel-routed by lethe_core.
//
// Honest note: WebKitGTK exposes no rasterization-scale hook today, so the
// FSR/DLAA-style scale control is a logged no-op here (it applies on macOS
// contentsScale and Windows WebView2 RasterizationScale).

#include <gio/gio.h>
#include <gtk/gtk.h>
#include <webkit2/webkit2.h>

#include <iostream>

#include "ui/fullweb.h"

namespace lethe {

struct FullWebWindow::Impl {
    GtkWidget* window = nullptr;
    GtkWidget* web = nullptr;
};

FullWebWindow::FullWebWindow(FullWebConfig cfg) : cfg_(cfg) {}

FullWebWindow::~FullWebWindow() = default;

static void ensureProxyHook(int proxyPort) {
    if (proxyPort <= 0) return;
    static bool configured = false;
    if (configured) return;
    configured = true;
    std::string proxyUri = "http://127.0.0.1:" + std::to_string(proxyPort);
    WebKitNetworkProxySettings* settings =
        webkit_network_proxy_settings_new(proxyUri.c_str(), nullptr);
    webkit_web_context_set_network_proxy_settings(
        webkit_web_context_get_default(),
        WEBKIT_NETWORK_PROXY_MODE_CUSTOM, settings);
    webkit_network_proxy_settings_free(settings);
    std::cout << "[lethe-fullweb] engine traffic routed through local "
              << "policy proxy " << proxyUri << std::endl;
}

bool FullWebWindow::open(const std::string& url, std::string& error) {
    if (!impl_) impl_ = std::make_unique<Impl>();
    if (!impl_->window) {
        ensureProxyHook(cfg_.proxyPort);
        impl_->window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
        gtk_window_set_title(GTK_WINDOW(impl_->window), "Lethe - Full Web");
        gtk_window_set_default_size(GTK_WINDOW(impl_->window), 1180, 800);
        impl_->web = webkit_web_view_new();
        WebKitSettings* s =
            webkit_web_view_get_settings(WEBKIT_WEB_VIEW(impl_->web));
        webkit_settings_set_javascript_can_open_windows_automatically(s, FALSE);
        gtk_container_add(GTK_CONTAINER(impl_->window), impl_->web);
        gtk_widget_show_all(impl_->window);
    }
    if (!impl_->web) {
        error = "WebKitGTK view unavailable";
        return false;
    }
    webkit_web_view_load_uri(WEBKIT_WEB_VIEW(impl_->web), url.c_str());
    return true;
}

void FullWebWindow::setRasterScale(double scale) {
    cfg_.rasterScale = scale;
    if (scale != 1.0) {
        std::cout << "[lethe-fullweb] rasterization scale " << scale
                  << " unsupported on WebKitGTK (no public hook); ignored"
                  << std::endl;
    }
}

} // namespace lethe
