#ifndef LETHE_UI_FULLWEB_H
#define LETHE_UI_FULLWEB_H

// fullweb.h - Embedded full-web mode (JS / CSS / media) behind Lethe policy.
//
// Reader mode stays the hardened default; this window embeds the PLATFORM
// web engine so real pages - YouTube included - actually render:
//   macOS  : WKWebView (system WebKit; JavaScriptCore)
//            - every navigation gated by HttpClient::policyCheckUrl()
//              through a dedicated checker client (DoH-only resolution,
//              private-network guard, VPN fail-closed decision)
//   Linux  : WebKitGTK (JSC + GStreamer media)
//            - engine-wide custom network proxy pointed at Lethe's local
//              PolicyProxyServer, so EVERY subresource request is enforced
//              at the transport layer
//   Windows: WebView2 host (see src/win/) - Chromium with its own
//            navigation gate and native RasterizationScale support.
//
// Honest limits (documented, not hidden): inside https CONNECT tunnels TLS
// stays end-to-end between the platform engine and the origin, so cert
// pinning/HSTS inspection do not apply there; the platform cookie store is
// used (incognito-only data store on macOS), not Lethe's memory jar.

#include <memory>
#include <string>

#include "core/engine.h"

namespace lethe {

struct FullWebConfig {
    TLSConfig tls;
    std::string dohProvider;
    PrivateNetworkPolicy privateNet;
    vpn::VpnTunnel* vpnTunnel = nullptr;  // non-owning; engine owns it

    // Relay plumbing for covered destinations (mirrors PolicyDialConfig).
    void* udpTransport = nullptr;
    std::string relayHost;
    int relayPort = 0;

    // Local PolicyProxyServer port (Linux deep path). 0 = no proxy hook.
    int proxyPort = 0;

    bool incognito = true;

    // Rasterization scale of the embedded view:
    //   <1.0  render fewer pixels, upscale (FSR-style performance mode)
    //   >1.0  supersample up to 2.0x, downscale (DLAA-style AA crispness)
    // Applied where the engine exposes raster control (macOS contentsScale,
    // Windows WebView2 RasterizationScale). Logged as unsupported elsewhere.
    double rasterScale = 1.0;
};

class FullWebWindow {
public:
    explicit FullWebWindow(FullWebConfig cfg);
    ~FullWebWindow();

    FullWebWindow(const FullWebWindow&) = delete;
    FullWebWindow& operator=(const FullWebWindow&) = delete;

    // Create/show the window and navigate to \p url. False with reason on
    // immediate failure (engine missing, navigation refused pre-flight).
    bool open(const std::string& url, std::string& error);

    // Live raster-scale change (see FullWebConfig::rasterScale).
    void setRasterScale(double scale);

private:
    FullWebConfig cfg_;
    std::unique_ptr<HttpClient> policyChecker_;
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace lethe

#endif // LETHE_UI_FULLWEB_H
