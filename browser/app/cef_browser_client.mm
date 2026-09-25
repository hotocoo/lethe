// cef_browser_client.cc - see cef_browser_client.h

#include "app/cef_browser_client.h"

#import "ui/mac/LetheMediaEnhancer.h"
#import <Foundation/Foundation.h>

#include <cctype>
#include <iostream>
#include <sstream>
#include <string_view>
#include <unordered_set>
#include <utility>

#include "include/cef_browser.h"
#include "include/cef_command_line.h"
#include "include/cef_process_message.h"
#include "include/cef_task.h"
#include "include/cef_values.h"

#import <Cocoa/Cocoa.h>

#import "ui/mac/LetheGuard.h"
#import "ui/mac/LethePreferences.h"

#include "app/cef_automation.h"
#include "app/cef_chrome.h"
#include "plugins/plugin_registry.h"
#include "network/policy_proxy.h"
#include "security/private_network_guard.h"
#include "security/tracker_blocklist.h"
#include "browser/url_input.h"
#include "renderer/page_templates.h"

namespace {
// URLs in logs are for orientation, not archival: an internal data: document
// is thousands of characters and makes every other line unreadable.
std::string ShortUrlForLog(const std::string& url) {
    if (url.rfind("data:", 0) == 0) return "data:<internal page>";
    if (url.size() <= 120) return url;
    return url.substr(0, 117) + "...";
}
}  // namespace


namespace {

std::string blockPageUrl(const std::string& target, const std::string& reason) {
    // This page is intentionally tiny and script-free. It is only used for
    // top-level destinations that CEF can classify locally before Chromium
    // gets a chance to open a socket (notably IP-literal SSRF targets).
    auto encode = [](const std::string& in) {
        std::string out;
        const char hex[] = "0123456789ABCDEF";
        for (unsigned char c : in) {
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '-' || c == '_' ||
                c == '.' || c == '~') {
                out += static_cast<char>(c);
            } else {
                out += '%';
                out += hex[c >> 4];
                out += hex[c & 0x0f];
            }
        }
        return out;
    };
    const std::string html = lethe::renderBlockPage(target, reason);
    return "data:text/html;charset=utf-8," + encode(html);
}

std::string errorPageUrl(const std::string& target,
                         const std::string& reason,
                         const std::string& httpFallback) {
    auto encode = [](const std::string& in) {
        std::string out;
        const char hex[] = "0123456789ABCDEF";
        for (unsigned char c : in) {
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '-' || c == '_' ||
                c == '.' || c == '~') {
                out += static_cast<char>(c);
            } else {
                out += '%';
                out += hex[c >> 4];
                out += hex[c & 0x0f];
            }
        }
        return out;
    };
    const std::string html = lethe::renderErrorPage(target, reason, httpFallback);
    return "data:text/html;charset=utf-8," + encode(html);
}

bool hasSuffixInsensitive(std::string value, const std::string& suffix) {
    for (char& c : value)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (value.size() < suffix.size()) return false;
    return value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string_view urlHostView(std::string_view url) {
    const size_t schemeEnd = url.find("://");
    if (schemeEnd == std::string_view::npos) return {};
    size_t start = schemeEnd + 3;
    size_t end = url.find_first_of("/?#", start);
    if (end == std::string_view::npos) end = url.size();
    std::string_view authority = url.substr(start, end - start);
    const size_t at = authority.rfind('@');
    if (at != std::string_view::npos) authority.remove_prefix(at + 1);
    if (!authority.empty() && authority.front() == '[') {
        const size_t close = authority.find(']');
        if (close == std::string_view::npos) return {};
        authority = authority.substr(1, close - 1);
    } else {
        const size_t colon = authority.rfind(':');
        if (colon != std::string_view::npos && authority.find(':') == colon)
            authority = authority.substr(0, colon);
    }
    return authority;
}

bool domainMatches(std::string_view host, std::string_view domain) {
    if (host == domain) return true;
    return host.size() > domain.size() &&
           host.compare(host.size() - domain.size(), domain.size(), domain) == 0 &&
           host[host.size() - domain.size() - 1] == '.';
}

bool isAllowedResourceScheme(std::string_view url) {
    const size_t colon = url.find(':');
    if (colon == std::string_view::npos || colon == 0) return false;
    // CEF resource loading is broader than top-level navigation. Keep the
    // renderer's resource surface deliberately small so a page cannot use a
    // non-web handler (file:, ftp:, custom OS schemes, etc.) as an alternate
    // path around Lethe's authenticated HTTP/CONNECT policy boundary.
    const std::string_view scheme = url.substr(0, colon);
    auto equalInsensitive = [](std::string_view a, std::string_view b) {
        if (a.size() != b.size()) return false;
        for (size_t i = 0; i < a.size(); ++i) {
            if (std::tolower(static_cast<unsigned char>(a[i])) !=
                std::tolower(static_cast<unsigned char>(b[i]))) return false;
        }
        return true;
    };
    return equalInsensitive(scheme, "http") || equalInsensitive(scheme, "https") ||
           equalInsensitive(scheme, "ws") || equalInsensitive(scheme, "wss") ||
           equalInsensitive(scheme, "data") || equalInsensitive(scheme, "blob") ||
           equalInsensitive(scheme, "about");
}

struct TrackerHash {
    using is_transparent = void;
    size_t operator()(std::string_view value) const noexcept {
        // Hash directly from the URL view and fold ASCII case while hashing.
        // The old path first allocated a host string and lowercased it, then
        // hashed that second representation. Tracker matching is case
        // insensitive by URL semantics, so doing both operations in one pass
        // removes an allocation and a full host traversal on every resource.
        size_t hash = sizeof(size_t) == 8 ? 1469598103934665603ULL
                                          : 2166136261U;
        for (unsigned char c : value) {
            if (c >= 'A' && c <= 'Z') c = static_cast<unsigned char>(c + ('a' - 'A'));
            hash ^= c;
            hash *= sizeof(size_t) == 8 ? 1099511628211ULL : 16777619U;
        }
        return hash;
    }
    size_t operator()(const std::string& value) const noexcept {
        return (*this)(std::string_view(value));
    }
};

struct TrackerEqual {
    using is_transparent = void;
    bool operator()(std::string_view a, std::string_view b) const noexcept {
        if (a.size() != b.size()) return false;
        for (size_t i = 0; i < a.size(); ++i) {
            unsigned char ac = static_cast<unsigned char>(a[i]);
            unsigned char bc = static_cast<unsigned char>(b[i]);
            if (ac >= 'A' && ac <= 'Z') ac = static_cast<unsigned char>(ac + ('a' - 'A'));
            if (bc >= 'A' && bc <= 'Z') bc = static_cast<unsigned char>(bc + ('a' - 'A'));
            if (ac != bc) return false;
        }
        return true;
    }
    bool operator()(const std::string& a, const std::string& b) const noexcept {
        return (*this)(std::string_view(a), std::string_view(b));
    }
};

using TrackerDomainSet = std::unordered_set<std::string, TrackerHash, TrackerEqual>;

const TrackerDomainSet& trackerDomains() {
    static const TrackerDomainSet domains = [] {
        TrackerDomainSet out;
        const auto& list = lethe::builtinTrackerBlocklist();
        out.reserve(list.domains.size() * 2 + 1);
        for (const auto& domain : list.domains) out.insert(domain);
        return out;
    }();
    return domains;
}

bool trackerHost(std::string_view host) {
    // Avoid repeatedly allocating/erasing strings on the IO hot path. The
    // blocklist is immutable for the lifetime of the process, so walk suffix
    // views and use the transparent hash/equality overloads directly.
    const auto& domains = trackerDomains();
    while (!host.empty()) {
        if (domains.find(host) != domains.end()) return true;
        const size_t dot = host.find('.');
        if (dot == std::string_view::npos) break;
        host.remove_prefix(dot + 1);
    }
    return false;
}

class DeferredFrameLoadTask : public CefTask {
 public:
    DeferredFrameLoadTask(CefRefPtr<CefFrame> frame, std::string url)
        : frame_(std::move(frame)), url_(std::move(url)) {}
    void Execute() override {
        if (frame_) frame_->LoadURL(url_);
    }
 private:
    CefRefPtr<CefFrame> frame_;
    std::string url_;
    IMPLEMENT_REFCOUNTING(DeferredFrameLoadTask);
};

void LoadBlockPageDeferred(CefRefPtr<CefFrame> frame,
                           const std::string& url,
                           const std::string& reason) {
    if (!frame) return;
    CefPostTask(TID_UI, new DeferredFrameLoadTask(
        frame, blockPageUrl(url, reason)));
}

}  // namespace

void CefBrowserClient::AppBrowserProcessHandler::OnContextInitialized() {
    std::cout << "[lethe-cef] OnContextInitialized (browser process)" << std::endl;
    std::cout.flush();
}

void CefBrowserClient::AppBrowserProcessHandler::OnBeforeChildProcessLaunch(
    CefRefPtr<CefCommandLine> command_line) {
    // Renderers inject the media enhancer at context creation and cannot
    // read Settings themselves; hand them the mode as "<mode>,<hdr>".
    command_line->AppendSwitchWithValue(
        "lethe-media",
        std::to_string(static_cast<long>(LetheMediaEnhancerMode())) + "," +
            (LetheMediaEnhancerHDR() ? "1" : "0"));
}

void CefBrowserClient::App::OnBeforeCommandLineProcessing(
    const CefString& process_type,
    CefRefPtr<CefCommandLine> command_line) {
    // We only need to inject switches in the browser process; the renderer
    // and GPU subprocesses inherit Chromium's defaults.
    if (!process_type.empty()) return;
    if (!ctx_) return;
#if !defined(NDEBUG)
    // Debug-only bisect escape hatch. Release builds must never allow an
    // environment variable to bypass the browser's mandatory security
    // switches.
    if (getenv("LETHE_CEF_MIN_SWITCHES")) {
        command_line->AppendSwitch("use-mock-keychain");
        return;
    }
#endif
    // Keep the browser policy boundary authoritative even when launchers or
    // stale preferences carry Chromium switches from another environment.
    // In particular, never permit an argv switch to disable the renderer
    // sandbox, weaken same-origin isolation, or bypass the authenticated
    // policy proxy.
    static constexpr const char* kForbiddenSwitches[] = {
        "no-sandbox", "disable-setuid-sandbox", "disable-web-security",
        "allow-file-access-from-files", "disable-site-isolation-trials",
        "no-proxy-server", "proxy-server", "proxy-bypass-list",
        "host-resolver-rules",
    };
    for (const char* name : kForbiddenSwitches)
        command_line->RemoveSwitch(name);
    if (ctx_->proxyPort > 0) {
        const int proxyPort = ctx_->httpsProxyPort > 0
            ? ctx_->httpsProxyPort : ctx_->proxyPort;
        const std::string scheme = ctx_->httpsProxyPort > 0 ? "https" : "http";
        const std::string url = scheme + "://127.0.0.1:" + std::to_string(proxyPort);
        command_line->AppendSwitchWithValue("proxy-server", url);
        // Chromium applies an implicit proxy bypass to loopback destinations.
        // That would let http://127.0.0.1 and http://localhost escape the
        // authenticated policy proxy entirely, defeating transport-level
        // private-network enforcement for local origins. Explicitly remove
        // that implicit exception; the proxy itself remains loopback-only
        // and its private-network policy decides which local destinations
        // are allowed.
        command_line->AppendSwitchWithValue("proxy-bypass-list", "<-loopback>");
        // DoH-only: prevent Chromium's own host resolver from opening a
        // direct DNS socket. All web destinations must remain names at the
        // authenticated proxy boundary, where Lethe performs DoH resolution
        // and the private-network/VPN policy check. Loopback is excluded
        // because the proxy itself is intentionally bound to 127.0.0.1.
        command_line->AppendSwitchWithValue(
            "host-resolver-rules", "MAP * ~NOTFOUND, EXCLUDE 127.0.0.1");

        if (ctx_->httpsProxyPort > 0 && !ctx_->httpsProxySpkiSha256.empty() &&
            !command_line->HasSwitch("ignore-certificate-errors-spki-list")) {
            // Pin only the ephemeral loopback proxy certificate. This does
            // not disable normal origin certificate validation.
            command_line->AppendSwitchWithValue(
                "ignore-certificate-errors-spki-list",
                ctx_->httpsProxySpkiSha256);
        }

    }

    // The Lethe proxy is an HTTP/CONNECT boundary and deliberately has no
    // QUIC/UDP forwarding path. Disable Chromium's direct QUIC transport so
    // an origin cannot opportunistically escape the authenticated proxy via
    // HTTP/3. This is a security invariant, not a benchmark/debug switch.
    command_line->AppendSwitch("disable-quic");
    // WebRTC has its own UDP candidate path and can otherwise bypass an HTTP
    // proxy. Keep the browser's network boundary equivalent to the proxy-only
    // design without disabling WebRTC itself.
    command_line->AppendSwitchWithValue(
        "force-webrtc-ip-handling-policy", "disable_non_proxied_udp");

    // Keep Chromium's Network Service out-of-process by default. The local
    // policy proxy is still the mandatory network boundary, but moving the
    // Network Service into the browser process removes a Chromium process
    // isolation boundary and increases the blast radius of a network-service
    // compromise. The faster in-process path remains available only as an
    // explicit benchmark/debug opt-in; production browsing keeps the safer
    // Chromium-style process model.
#if !defined(NDEBUG)
    if (getenv("LETHE_CEF_NETWORK_SERVICE_INPROCESS")) {
        const std::string existingFeatures =
            command_line->GetSwitchValue("enable-features").ToString();
        if (existingFeatures.empty()) {
            command_line->AppendSwitchWithValue("enable-features", "NetworkServiceInProcess");
        } else if (existingFeatures.find("NetworkServiceInProcess") == std::string::npos) {
            command_line->AppendSwitchWithValue(
                "enable-features", existingFeatures + ",NetworkServiceInProcess");
        }
    }
#endif

    // Security baseline for the Blink engine: force Chromium's full site
    // isolation instead of inheriting whatever process-model default the
    // embedded CEF release happens to ship. This keeps cross-site documents
    // out of the same renderer and materially reduces the blast radius of a
    // renderer compromise. It is intentionally a hard default, not a
    // performance/debug toggle: memory cost is measured by the benchmark
    // suite rather than traded away silently for a smaller process count.
    command_line->AppendSwitch("site-per-process");

    // Keep origin isolation explicit as well. Site-per-process handles the
    // common web-site boundary; strict origin isolation tightens the process
    // boundary for origins that would otherwise share a site instance.
    command_line->AppendSwitch("strict-origin-isolation");
    // Delegate every login / proxy-auth challenge to the embedder's
    // CefRequestHandler::GetAuthCredentials. Without this CEF falls back to
    // Chrome's own login-prompt UI, which does not exist in an embedded
    // app: the 407 challenge from the policy proxy then hangs forever and
    // every https navigation dies as ERR_INVALID_AUTH_CREDENTIALS.
    // LETHE_CEF_NO_LOGIN_PROMPT_SWITCH=1 to bisect.
    if (!getenv("LETHE_CEF_NO_LOGIN_PROMPT_SWITCH"))
        command_line->AppendSwitch("disable-chrome-login-prompt");
    // CEF 151/Chromium 151 can legitimately deliver the renderer's browser
    // info acknowledgement after the default timeout on macOS when the
    // native sandbox + helper bundle are cold-starting.  The default timeout
    // then invalidates the RFH: navigation is silently dropped and every
    // subresource (images, video, downloads, attachment fetches) appears
    // broken even though the renderer is alive.  Let CEF keep the handshake
    // pending instead of turning a slow, valid startup into ERR_ABORTED.
    if (!getenv("LETHE_CEF_BROWSER_INFO_TIMEOUT_DEFAULT"))
        command_line->AppendSwitch("disable-new-browser-info-timeout");
    // Privacy: turn off everything Chromium does in the background that
    // would phone home. These are all default-off in --no-first-run, but
    // we set them explicitly so a config drift in upstream CEF cannot
    // silently re-enable them. NOTE: disable-component-update must stay
    // OFF this list - the network service's builtin cert verifier waits
    // for the Chrome root-store data that pipeline delivers, and with the
    // updater disabled every TLS handshake times out (ERR_TIMED_OUT after
    // a fully established tunnel).
    command_line->AppendSwitch("disable-background-networking");
    command_line->AppendSwitch("disable-default-apps");
    command_line->AppendSwitch("disable-domain-reliability");
    command_line->AppendSwitch("disable-sync");
    command_line->AppendSwitch("disable-translate");
    command_line->AppendSwitch("no-pings");
    command_line->AppendSwitch("no-first-run");
    // No process singleton: Lethe launches are independent and the
    // macOS Seatbelt sandbox does not allow writing the singleton
    // lock into ~/Library/Application Support/.
    command_line->AppendSwitch("disable-process-singleton");
    // Ephemeral browser: never touch the login keychain. The Safe Storage
    // prompt blocks the browser UI thread in securityd and starves CEF's
    // browser-info handshake (see the delegate's global-command-line note).
    command_line->AppendSwitch("use-mock-keychain");
    // Merge, don't clobber: a --disable-features passed on our own argv
    // (diagnostics, upstream-bug workarounds) must survive alongside the
    // privacy set below - Chromium keeps the LAST value of a repeated
    // switch, which would otherwise silently drop the user's list.
    {
        static const char* kOurs =
            "InterestFeedContentSuggestions,LookalikeUrlNavigationThrottle,"
            "PrivacySandboxAdsAPIs,PrivacySandboxAttributionReporting,"
            "Translate,TranslateUI";
        std::string theirs =
            command_line->GetSwitchValue("disable-features").ToString();
        command_line->AppendSwitchWithValue(
            "disable-features",
            theirs.empty() ? kOurs : theirs + "," + kOurs);
    }
    // --user-data-dir: without an explicit value the chromium process
    // singleton tries to read DIR_USER_DATA before any settings have
    // registered it, and crashes in chrome_main_delegate.cc:1566. The
    // CefSettings.root_cache_path field is a CEF-level setting; Chromium
    // also needs the command-line flag.
    {
        NSString* path = nil;
        if (const char* override = getenv("LETHE_CEF_USER_DATA_DIR")) {
            if (*override) path = [NSString stringWithUTF8String:override];
        }
        if (!path) {
            NSArray* dirs = NSSearchPathForDirectoriesInDomains(
                NSApplicationSupportDirectory, NSUserDomainMask, YES);
            path = [dirs.firstObject
                stringByAppendingPathComponent:@"Lethe CEF"];
        }
        [[NSFileManager defaultManager] createDirectoryAtPath:path
            withIntermediateDirectories:YES attributes:nil error:nil];
        command_line->AppendSwitchWithValue("user-data-dir",
            CefString([path UTF8String]));
    }
    // Stealth UA when prefs ask for it.
    if (ctx_->cfg.userAgentMode == "stealth") {
        command_line->AppendSwitchWithValue("user-agent",
            lethe::stealthUserAgentString());
    }
    // The "hardware-accel" plugin: off = software compositing (the
    // documented debugging mode with a large performance cost).
    if (!ctx_->cfg.useHardwareAcceleration) {
        command_line->AppendSwitch("disable-gpu");
        command_line->AppendSwitch("disable-gpu-compositing");
    } else {
        // Keep Chromium's GPU path explicit rather than depending on the
        // CEF/Chromium defaults drifting between embedded releases. These
        // switches keep raster work on the GPU, allow texture ownership to
        // move without an extra CPU copy, and move raster tasks off the
        // renderer main thread. They are only enabled for the normal
        // hardware-accelerated profile; the software/debug profile above is
        // deliberately unchanged.
        command_line->AppendSwitch("enable-gpu-rasterization");
        command_line->AppendSwitch("enable-zero-copy");
        command_line->AppendSwitch("enable-oop-rasterization");
    }
}

bool CefBrowserClient::OnBeforeBrowse(CefRefPtr<CefBrowser> browser,
                                      CefRefPtr<CefFrame> frame,
                                      CefRefPtr<CefRequest> request,
                                      bool user_gesture,
                                      bool is_redirect) {
    (void)user_gesture; (void)is_redirect;
    if (!frame || !frame->IsMain()) return false;
    if (!ctx_) return false;
    if (request) {
        const std::string url = request->GetURL().ToString();
        // Built-in site guard, identical to the WebKit shell: a local
        // structural assessment, a modal the user can override once per
        // host, and no lookup service anywhere in the path.
        if ([[LethePreferences shared] siteGuard] &&
            (url.rfind("https://", 0) == 0 || url.rfind("http://", 0) == 0)) {
            NSString* target = [NSString stringWithUTF8String:url.c_str()];
            LetheScanResult* verdict = [LetheGuard assessURL:target];
            NSString* host = [NSURL URLWithString:target].host ?: @"";
            if (verdict.blocked && ![LetheGuard isHostAllowed:host]) {
                if ([LetheGuard presentNavigationWarning:verdict
                                                  forURL:target
                                                  window:nil]) {
                    // The user overrode the warning: reload the same URL now
                    // that the host is on the session allow-list.
                    CefPostTask(TID_UI, new DeferredFrameLoadTask(frame, url));
                }
                return true;
            }
        }
        if (browser && IsOblivion(browser) &&
            (url.rfind("http://", 0) == 0 || url.rfind("ws://", 0) == 0)) {
            LetheCefChromeSetAddress(browser, url);
            // Defer the replacement document until OnBeforeBrowse returns.
            // Loading a data: block page synchronously from the cancellation
            // callback can cause CEF to abort both the blocked request and
            // the replacement document, leaving the generic error page.
            LoadBlockPageDeferred(
                frame, url,
                "Oblivion windows are https-only: unencrypted (http://) pages are never loaded");
            return true;
        }
        // The error page exposes a private, browser-generated continuation
        // URL rather than a raw javascript/link escape. Accept it only when
        // it exactly matches the pending HTTPS-first URL for this tab.
        if (url.rfind(std::string(lethe::kHttpFallbackScheme) + "://allow-http?u=", 0) == 0) {
            const std::string fallback = lethe::parseHttpFallbackActionUrl(url);
            auto it = http_fallback_allowed_.find(browser ? browser->GetIdentifier() : -1);
            if (!fallback.empty() && it != http_fallback_allowed_.end() && fallback == it->second &&
                fallback.rfind("http://", 0) == 0) {
                http_fallback_allowed_.erase(it);
                http_fallback_active_[browser->GetIdentifier()] = fallback;
                frame->LoadURL(fallback);
            } else {
                frame->LoadURL(blockPageUrl(url, "invalid or expired HTTP fallback"));
            }
            return true;
        }

        const size_t schemeEnd = url.find(':');
        if (schemeEnd != std::string::npos) {
            std::string scheme = url.substr(0, schemeEnd);
            for (char& c : scheme)
                c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            // The top-level browser surface has a deliberately tiny scheme
            // allowlist. Anything else can hand navigation to an OS protocol
            // handler or bypass the authenticated HTTP policy boundary.
            // data: is retained for Lethe-owned internal pages and
            // about:blank is required by normal popup/document flows.
            const bool allowedWebScheme = scheme == "http" || scheme == "https";
            const bool allowedInternalScheme = scheme == "data" ||
                                                (scheme == "about" &&
                                                 url == "about:blank");
            if (!allowedWebScheme && !allowedInternalScheme) {
                const std::string reason =
                    "this navigation scheme is not allowed by Lethe";
                if (const char* debug = std::getenv("LETHE_DEBUG");
                    debug && *debug && std::string(debug) != "0") {
                    std::cout << "[lethe-cef] blocked non-web navigation "
                              << url << std::endl;
                }
                if (browser && frame->IsMain())
                    policy_blocked_urls_[browser->GetIdentifier()] = url;
                LetheCefChromeSetAddress(browser, url);
                frame->LoadURL(blockPageUrl(url, reason));
                return true;
            }
        }
    }
    if (ctx_->cfg.isolatePrivateNetworks && request) {
        const std::string url = request->GetURL().ToString();
        // CEF can resolve IP literals itself before the policy proxy sees the
        // request. Re-apply Lethe's destination classifier here so link-local,
        // RFC1918, CGNAT, reserved and multicast literals cannot escape via a
        // browser-network path that never reaches HttpClient.
        std::string host;
        const size_t schemeEnd = url.find("://");
        if (schemeEnd != std::string::npos) {
            const size_t authorityStart = schemeEnd + 3;
            size_t authorityEnd = url.find_first_of("/?#", authorityStart);
            if (authorityEnd == std::string::npos) authorityEnd = url.size();
            host = url.substr(authorityStart, authorityEnd - authorityStart);
            const size_t at = host.rfind('@');
            if (at != std::string::npos) host.erase(0, at + 1);
            if (!host.empty() && host.front() == '[') {
                const size_t close = host.find(']');
                if (close != std::string::npos) host = host.substr(1, close - 1);
            } else {
                const size_t colon = host.rfind(':');
                if (colon != std::string::npos && host.find(':') == colon)
                host.resize(colon);
            }
        }
        // RFC 2606 reserves .invalid specifically for names that must not
        // resolve. Reject it locally instead of waiting for a DNS/proxy
        // timeout; the e2e policy contract requires an immediate fail-closed
        // block page for this class of destination.
        if (hasSuffixInsensitive(host, ".invalid")) {
            const std::string reason =
                "the .invalid special-use domain is reserved and must not resolve";
            std::cout << "[lethe-cef] blocked special-use navigation "
                      << url << " : " << reason << std::endl;
            if (browser && frame->IsMain())
                policy_blocked_urls_[browser->GetIdentifier()] = url;
            LetheCefChromeSetAddress(browser, url);
            frame->LoadURL(blockPageUrl(url, reason));
            return true;
        }
        const std::string canonical = lethe::HttpClient::canonicalNumericAddress(host);
        if (!canonical.empty()) {
            lethe::PrivateNetworkPolicy policy;
            policy.isolatePrivateNetworks = ctx_->cfg.isolatePrivateNetworks;
            policy.allowLoopback = true;
            for (const auto& allowed : ctx_->cfg.privateNetworkAllowedHosts)
                policy.allowedHosts.insert(allowed);
            const std::string reason =
                lethe::PrivateNetworkGuard(std::move(policy)).check(host, canonical);
            if (!reason.empty()) {
                if (const char* debug = std::getenv("LETHE_DEBUG");
                    debug && *debug && std::string(debug) != "0") {
                    std::cout << "[lethe-cef] blocked private navigation "
                              << url << " : " << reason << std::endl;
                }
                if (browser && frame->IsMain())
                    policy_blocked_urls_[browser->GetIdentifier()] = url;
                LetheCefChromeSetAddress(browser, url);
                frame->LoadURL(blockPageUrl(url, reason));
                return true;
            }
        }
    }
    // The local policy proxy already enforces everything at transport time
    // (HTTPS-first, HSTS, private-network, SSRF, VPN), so a refused URL
    // comes back as a 403 from 127.0.0.1:<port> with the named reason in
    // the body. Letting Chromium handle the failure in OnLoadError keeps
    // the UI consistent with the WebKit shell's "Blocked by Lethe policy".
    (void)browser; (void)request;
    return false;
}

CefRefPtr<CefResourceRequestHandler> CefBrowserClient::GetResourceRequestHandler(
    CefRefPtr<CefBrowser> browser,
    CefRefPtr<CefFrame> frame,
    CefRefPtr<CefRequest> request,
    bool is_navigation,
    bool is_download,
    const CefString& request_initiator,
    bool& disable_default_handling) {
    (void)frame;
    (void)is_navigation;
    (void)is_download;
    disable_default_handling = false;
    if (browser && IsOblivion(browser)) return this;
    if (!request || !ctx_ || !ctx_->trackerBlocking) return nullptr;

    // CEF 151 uses UTF-16 CefString by default. Converting both URL and
    // initiator to std::string on every resource request allocates twice
    // before we even know whether the host is in the immutable tracker set.
    // Convert the URL once, then defer the second conversion until the URL
    // host is actually a tracker candidate. This keeps ordinary resources on
    // the cheapest possible negative path while preserving exact matching.
    const std::string url = request->GetURL().ToString();
    // Resource-handler installation is also the earliest CEF hook that lets
    // us reject unsupported schemes before Chromium's network stack creates
    // a loader. Route those requests through this handler and let
    // OnBeforeResourceLoad cancel them. Keeping the classification here means
    // the hot callback below never has to parse/allocate the URL again.
    if (!isAllowedResourceScheme(url)) return this;
    const std::string_view host = urlHostView(url);
    if (host.empty() || !trackerHost(host)) return nullptr;

    const std::string initiator = request_initiator.ToString();
    const std::string_view initiatorHost = urlHostView(initiator);
    if (initiatorHost.empty() || domainMatches(host, initiatorHost)) return nullptr;
    return this;
}

CefBrowserClient::ReturnValue CefBrowserClient::OnBeforeResourceLoad(
    CefRefPtr<CefBrowser> browser,
    CefRefPtr<CefFrame> frame,
    CefRefPtr<CefRequest> request,
    CefRefPtr<CefCallback> callback) {
    (void)callback;
    if (!request) return RV_CONTINUE;
    if (browser && IsOblivion(browser)) {
        const std::string url = request->GetURL().ToString();
        if (url.rfind("http://", 0) == 0 || url.rfind("ws://", 0) == 0)
            return RV_CANCEL;
        return RV_CONTINUE;
    }
    if (!ctx_ || !ctx_->trackerBlocking) return RV_CONTINUE;

    // GetResourceRequestHandler already performed the complete tracker
    // classification before installing this handler. Repeating URL parsing,
    // host extraction, and the blocklist lookup here doubled the CEF IO-path
    // work for every blocked resource. At this point the handler exists
    // specifically because the request was classified as a tracker.
    if (const char* debug = std::getenv("LETHE_DEBUG");
        debug && *debug && std::string(debug) != "0") {
        std::cout << "[lethe-cef] tracker blocked" << std::endl;
    }
    return RV_CANCEL;
}

bool CefBrowserClient::IsThirdPartyTrackerRequest(const std::string& url,
                                                  const std::string& initiator) {
    // Keep host parsing view-only. This callback is reached on CEF's IO path
    // for resource loads, so two temporary host strings per request are pure
    // allocator pressure before the immutable tracker set is consulted.
    const std::string_view host = urlHostView(url);
    const std::string_view initiatorHost = urlHostView(initiator);
    if (host.empty() || initiatorHost.empty() || domainMatches(host, initiatorHost))
        return false;
    return trackerHost(host);
}

bool CefBrowserClient::OnOpenURLFromTab(
    CefRefPtr<CefBrowser> browser,
    CefRefPtr<CefFrame> frame,
    const CefString& target_url,
    WindowOpenDisposition target_disposition,
    bool user_gesture) {
    (void)target_disposition;
    (void)user_gesture;
    if (!browser || !frame || !frame->IsMain()) return false;
    const std::string action = target_url.ToString();
    if (action.rfind(std::string(lethe::kHttpFallbackScheme) + "://allow-http?u=", 0) != 0)
        return false;

    const std::string fallback = lethe::parseHttpFallbackActionUrl(action);
    const int id = browser->GetIdentifier();
    auto it = http_fallback_allowed_.find(id);
    if (fallback.empty() || it == http_fallback_allowed_.end() ||
        fallback != it->second || fallback.rfind("http://", 0) != 0) {
        frame->LoadURL(blockPageUrl(action, "invalid or expired HTTP fallback"));
        return true;
    }

    http_fallback_allowed_.erase(it);
    http_fallback_active_[id] = fallback;
    frame->LoadURL(fallback);
    return true;
}

bool CefBrowserClient::OnBeforePopup(
    CefRefPtr<CefBrowser> browser,
    CefRefPtr<CefFrame> frame,
    int popup_id,
    const CefString& target_url,
    const CefString& target_frame_name,
    WindowOpenDisposition target_disposition,
    bool user_gesture,
    const CefPopupFeatures& popupFeatures,
    CefWindowInfo& windowInfo,
    CefRefPtr<CefClient>& client,
    CefBrowserSettings& settings,
    CefRefPtr<CefDictionaryValue>& extra_info,
    bool* no_javascript_access) {
    (void)browser; (void)frame; (void)popup_id; (void)target_frame_name;
    (void)target_disposition; (void)popupFeatures;
    (void)extra_info; (void)no_javascript_access;
    // Popup creation is a normal browser operation. Avoid unconditional
    // stdout I/O on this callback: terminal locking becomes measurable when
    // a page creates several user-initiated windows in quick succession.
    if (const char* debug = std::getenv("LETHE_DEBUG");
        debug && *debug && std::string(debug) != "0") {
        std::cout << "[lethe-cef] popup " << ShortUrlForLog(target_url.ToString()) << std::endl;
    }
    // Match modern browser popup blocking at the embedder boundary: a page
    // cannot create arbitrary native windows after an unrelated timer,
    // redirect, or hidden iframe fires. A direct user activation is still
    // allowed and continues through the normal CEF navigation/policy path.
    if (!user_gesture) {
        std::cout << "[lethe-cef] blocked popup without user gesture"
                  << std::endl;
        return true;
    }
    // Use a normal native window and the same client so popup browsers enter
    // the automation browser set and remain behind the same policy handlers.
    windowInfo.bounds = CefRect(0, 0, 1280, 860);
    windowInfo.runtime_style = LetheCefRuntimeStyle();
    client = this;
    settings = CefBrowserSettings();
    return false;
}

bool CefBrowserClient::OnPreKeyEvent(CefRefPtr<CefBrowser> browser,
                                     const CefKeyEvent& event,
                                     CefEventHandle os_event,
                                     bool* is_keyboard_shortcut) {
    (void)os_event;
    if (is_keyboard_shortcut) *is_keyboard_shortcut = false;

    // OnPreKeyEvent receives both key-down and key-up notifications. Native
    // browser actions must run exactly once, on the raw key-down event.
    if (event.type != KEYEVENT_RAWKEYDOWN) return false;

    const bool command = (event.modifiers & EVENTFLAG_COMMAND_DOWN) != 0;
    const bool shift = (event.modifiers & EVENTFLAG_SHIFT_DOWN) != 0;
    if (!browser || !command) return false;

    // CEF reports macOS Command as EVENTFLAG_COMMAND_DOWN. Use the physical
    // Windows key code rather than character output so this remains reliable
    // with non-US keyboard layouts and while an input field has focus.
    if (!shift && (event.windows_key_code == ',' || event.windows_key_code == 188)) {
        // Keep CEF's keyboard surface aligned with the native WebKit shell:
        // Cmd+, must open the same authoritative Settings window instead of
        // being swallowed by the renderer or depending on an AppKit menu
        // responder that Alloy does not always expose.
        LetheCefChromeShowSettings();
        if (is_keyboard_shortcut) *is_keyboard_shortcut = true;
        return true;
    }

    if (!shift && event.windows_key_code == 'T') {
        CefWindowInfo windowInfo;
        windowInfo.bounds = CefRect(0, 0, 1280, 860);
        windowInfo.runtime_style = LetheCefRuntimeStyle();
        CefBrowserSettings settings;
        settings.background_color = 0xFFFFFFFFu;
        if (!lethe::PluginRegistry::instance().enabled("javascript"))
            settings.javascript = STATE_DISABLED;
        const std::string startUrl = LetheCefNewTabDataUrl();
        if (!CefBrowserHost::CreateBrowser(
                windowInfo, this, startUrl, settings, nullptr, nullptr)) {
            std::cerr << "[lethe-cef] Cmd+T CreateBrowser failed" << std::endl;
        } else {
            std::cout << "[lethe-cef] Cmd+T -> new tab" << std::endl;
        }
        if (is_keyboard_shortcut) *is_keyboard_shortcut = true;
        return true;
    }

    if (!shift && event.windows_key_code == 'L') {
        LetheCefChromeFocusAddress(browser);
        if (is_keyboard_shortcut) *is_keyboard_shortcut = true;
        return true;
    }

    if (!shift && event.windows_key_code == 'R') {
        browser->Reload();
        if (is_keyboard_shortcut) *is_keyboard_shortcut = true;
        return true;
    }

    if (shift && event.windows_key_code == 'R') {
        browser->ReloadIgnoreCache();
        if (is_keyboard_shortcut) *is_keyboard_shortcut = true;
        return true;
    }

    if (!shift && event.windows_key_code == '[') {
        if (browser->CanGoBack()) browser->GoBack();
        if (is_keyboard_shortcut) *is_keyboard_shortcut = true;
        return true;
    }

    if (!shift && event.windows_key_code == ']') {
        if (browser->CanGoForward()) browser->GoForward();
        if (is_keyboard_shortcut) *is_keyboard_shortcut = true;
        return true;
    }

    if (!shift && event.windows_key_code == 'W') {
        // CEF owns the top-level browser window. CloseBrowser(false) enters
        // its normal macOS close negotiation and ultimately reaches
        // OnBeforeClose, where Lethe releases the browser/chrome references.
        LetheCefChromeDetach(browser);
        browser->GetHost()->CloseBrowser(false);
        if (is_keyboard_shortcut) *is_keyboard_shortcut = true;
        return true;
    }

    return false;
}

bool CefBrowserClient::GetAuthCredentials(CefRefPtr<CefBrowser> browser,
                                          const CefString& origin_url,
                                          bool isProxy,
                                          const CefString& host,
                                          int port,
                                          const CefString& realm,
                                          const CefString& scheme,
                                          CefRefPtr<CefAuthCallback> callback) {
    // Proxy authentication is on the network hot path. Do not synchronously
    // write/flush stdout for every Chromium 407 challenge; keep the
    // diagnostic available only when explicitly requested.
    if (const char* debug = std::getenv("LETHE_DEBUG");
        debug && *debug && std::string(debug) != "0") {
        std::cout << "[lethe-cef] GetAuthCredentials proxy=" << isProxy
                  << " host=" << host.ToString() << " port=" << port
                  << " scheme=" << scheme.ToString()
                  << " browser=" << (browser ? browser->GetIdentifier() : -1)
                  << std::endl;
        std::cout.flush();
    }
    (void)origin_url; (void)realm; (void)scheme;
    if (!ctx_ || !isProxy) return false;
    // Only ever answer the loopback policy proxy we started ourselves -
    // never volunteer the per-launch token to any other host.
    const int expectedPort = ctx_->httpsProxyPort > 0
        ? ctx_->httpsProxyPort : ctx_->proxyPort;
    if (host.ToString() != "127.0.0.1" || port != expectedPort) return false;
    if (ctx_->proxyAuthToken.empty()) return false;
    callback->Continue("lethe", ctx_->proxyAuthToken);
    return true;
}

bool CefBrowserClient::OnSelectClientCertificate(
    CefRefPtr<CefBrowser> browser,
    bool isProxy,
    const CefString& host,
    int port,
    const X509CertificateList& certificates,
    CefRefPtr<CefSelectClientCertificateCallback> callback) {
    // Never select a client identity for an origin server. The only mTLS
    // peer in Lethe's HTTPS-proxy mode is our own loopback frontend.
    if (!isProxy || !ctx_ || ctx_->httpsProxyPort <= 0 ||
        host.ToString() != "127.0.0.1" || port != ctx_->httpsProxyPort ||
        !callback) {
        return false;
    }

    if (const char* debug = std::getenv("LETHE_DEBUG");
        debug && *debug && std::string(debug) != "0") {
        std::cout << "[lethe-cef] proxy client-certificate request host="
                  << host.ToString() << " port=" << port
                  << " candidates=" << certificates.size() << std::endl;
    }

    // The provisioning path installs an identity with this exact subject.
    // Do not blindly select the first platform certificate: that could
    // disclose an unrelated user identity if this callback is reached for a
    // different proxy request.
    constexpr std::string_view kClientSubject = "Lethe CEF Proxy Client";
    for (const auto& cert : certificates) {
        if (!cert) continue;
        auto subject = cert->GetSubject();
        if (!subject) continue;
        if (subject->GetCommonName().ToString() == kClientSubject) {
            if (const char* debug = std::getenv("LETHE_DEBUG");
                debug && *debug && std::string(debug) != "0") {
                std::cout << "[lethe-cef] selected Lethe proxy client certificate"
                          << " browser=" << (browser ? browser->GetIdentifier() : -1)
                          << std::endl;
            }
            callback->Select(cert);
            return true;
        }
    }

    // Fail closed: do not let Chromium silently choose another identity or
    // display a certificate-selection dialog.
    callback->Select(nullptr);
    return true;
}

bool CefBrowserClient::IsOblivion(CefRefPtr<CefBrowser> browser) const {
    return browser && oblivion_browser_ids_.find(browser->GetIdentifier()) !=
        oblivion_browser_ids_.end();
}

void CefBrowserClient::OnAfterCreated(CefRefPtr<CefBrowser> browser) {
    const bool first_browser = browsers_.empty();
    browsers_.push_back(browser);
    if (next_browser_oblivion_) {
        oblivion_browser_ids_.insert(browser->GetIdentifier());
        next_browser_oblivion_ = false;
    }
    if (first_browser || !browser_) browser_ = browser;
    browser_count_++;
    LetheCefAutomation::shared()->OnBrowserCreated(browser);
    LetheCefChromeAttach(browser);
    if (!first_browser) {
        // browser_ is the current surviving tab, not necessarily the browser
        // that was created first. This matters after the active/first tab is
        // closed: CEF can still have another browser alive, and a later Cmd+T
        // must join that surviving native tab group rather than create a
        // detached AppKit window.
        CefRefPtr<CefBrowser> parentBrowser = browser_;
        if (!parentBrowser) parentBrowser = browsers_.front();
        CefWindowHandle parentHandle = parentBrowser
            ? parentBrowser->GetHost()->GetWindowHandle() : nullptr;
        CefWindowHandle childHandle = browser->GetHost()->GetWindowHandle();
        NSWindow* parentWindow = parentHandle
            ? [(__bridge NSView*)parentHandle window] : nil;
        NSWindow* childWindow = childHandle
            ? [(__bridge NSView*)childHandle window] : nil;
        if (parentWindow && childWindow && parentWindow != childWindow) {
            // Alloy CEF creates each top-level browser in its own NSWindow.
            // Convert Cmd+T's new window into a native macOS window-tab so
            // the browser remains a single tabbed window from the user's
            // perspective while CEF retains one browser object per tab.
            [parentWindow addTabbedWindow:childWindow
                                  ordered:NSWindowAbove];
        if (parentWindow.tabGroup && !parentWindow.tabGroup.tabBarVisible) {
                [parentWindow toggleTabBar:nil];
        }
            // AppKit now owns the visible tab strip. Remove the single-tab
            // compatibility accessory from the grouped windows so the user
            // sees exactly one tab UI rather than a duplicate native/custom
            // pair.
            LetheCefChromeUpdate(browser);
            std::cout << "[lethe-cef] native tab group windows="
                      << (parentWindow.tabbedWindows
                              ? [parentWindow.tabbedWindows count] : 1)
                      << " tabbar="
                      << (parentWindow.tabGroup && parentWindow.tabGroup.tabBarVisible ? 1 : 0)
                      << std::endl;
        }
    }
    std::cout << "[lethe-cef] browser created ("
              << browser->GetIdentifier() << ") windows=" << browser_count_
              << " runtime=" << static_cast<int>(browser->GetHost()->GetRuntimeStyle())
              << std::endl;
}

void CefBrowserClient::OnTitleChange(CefRefPtr<CefBrowser> browser,
                                     const CefString& title) {
    LetheCefChromeSetTitle(browser, title.ToString());
}

void CefBrowserClient::OnLoadingProgressChange(CefRefPtr<CefBrowser> browser,
                                               double progress) {
    // Progress is presentation-only state. Keep it out of navigation policy
    // and update only the tiny native progress layer in the toolbar.
    LetheCefChromeSetLoadingProgress(browser, progress);
}

bool CefBrowserClient::DoClose(CefRefPtr<CefBrowser> browser) {
    if (!browser) return false;

    std::cout << "[lethe-cef] DoClose browser=" << browser->GetIdentifier()
              << " ready=" << browser->GetHost()->IsReadyToBeClosed()
              << std::endl;
    std::cout.flush();
    // Let CEF's native macOS Alloy window delegate receive the standard
    // performClose: notification and complete the browser destruction path.
    // Browser creation is deliberately deferred until after the message loop
    // starts; that is required for reliable native-window teardown on macOS.
    return false;
}

void CefBrowserClient::OnBeforeClose(CefRefPtr<CefBrowser> browser) {
    // Do not retain a CefBrowser reference past OnBeforeClose. CEF's
    // shutdown checker requires all browser references to be released before
    // CefShutdown; the client itself otherwise keeps the last closed popup
    // alive even though browser_count_ has reached zero.
    LetheCefChromeDetach(browser);
    const int closingId = browser ? browser->GetIdentifier() : -1;
    oblivion_browser_ids_.erase(closingId);
    http_fallback_allowed_.erase(closingId);
    http_fallback_active_.erase(closingId);
    policy_blocked_urls_.erase(closingId);
    if (browser_ && browser &&
        browser_->GetIdentifier() == browser->GetIdentifier()) {
        browser_ = nullptr;
    }
    browsers_.erase(std::remove_if(browsers_.begin(), browsers_.end(),
        [id = browser ? browser->GetIdentifier() : -1](const auto& b) {
            return !b || b->GetIdentifier() == id;
        }), browsers_.end());
    if (!browser_ && !browsers_.empty()) browser_ = browsers_.back();
    browser_count_--;
    LetheCefAutomation::shared()->OnBrowserClosed(browser);
    if (browser_count_ == 0) {
        std::cout << "[lethe-cef] last browser closed; quitting message loop"
                  << std::endl;
        CefQuitMessageLoop();
    }
}

bool CefBrowserClient::OnProcessMessageReceived(
    CefRefPtr<CefBrowser> browser,
    CefRefPtr<CefFrame> frame,
    CefProcessId source_process,
    CefRefPtr<CefProcessMessage> message) {
    (void)frame; (void)source_process;
    if (!message) return false;
    const std::string& name = message->GetName();
    if (name == "lethe:eval-result") {
        CefRefPtr<CefListValue> args = message->GetArgumentList();
        if (args && args->GetSize() >= 2) {
            const std::string text = args->GetString(0).ToString();
            const std::string id   = args->GetString(1).ToString();
            ParkEvalResult(id, text);
            LetheCefAutomation::shared()->OnResult(id, text);
        }
        return true;
    }
    (void)browser;
    return false;
}

void CefBrowserClient::OnLoadStart(CefRefPtr<CefBrowser> browser,
                                   CefRefPtr<CefFrame> frame,
                                   TransitionType transition_type) {
    (void)transition_type;
    if (frame && frame->IsMain()) {
        LetheCefChromeSetLoading(browser, true);
        LetheCefChromeUpdate(browser);
        main_loading_ = true;
        std::cout << "[e2e] nav " << ShortUrlForLog(browser->GetMainFrame()->GetURL().ToString())
                  << std::endl;
        std::cout.flush();
    }
}

void CefBrowserClient::OnLoadEnd(CefRefPtr<CefBrowser> browser,
                                 CefRefPtr<CefFrame> frame,
                                 int httpStatusCode) {
    (void)browser;
    if (frame && frame->IsMain()) {
        LetheCefChromeSetLoading(browser, false);
        LetheCefChromeUpdate(browser);
        main_loading_ = false;
        first_load_done_ = true;
        LetheCefAutomation::shared()->ClearPendingNavigation();
        // A renderer keeps the mode it was launched with; bring the document
        // up to the current Settings (no-op when the enhancer is absent).
        frame->ExecuteJavaScript(LetheMediaEnhancerApplyJS().UTF8String, "<lethe-media>", 0);
        std::cout << "[e2e] nav-end " << ShortUrlForLog(frame->GetURL().ToString())
                  << " status=" << httpStatusCode << std::endl;
        std::cout.flush();
        if (quit_when_loaded_) {
            quit_when_loaded_ = false;
            CefQuitMessageLoop();
        }
    }
}

void CefBrowserClient::OnLoadError(CefRefPtr<CefBrowser> browser,
                                   CefRefPtr<CefFrame> frame,
                                   ErrorCode errorCode,
                                   const CefString& errorText,
                                   const CefString& failedUrl) {
    if (frame && frame->IsMain()) {
        const int browserId = browser ? browser->GetIdentifier() : -1;
        auto blocked = policy_blocked_urls_.find(browserId);
        if (blocked != policy_blocked_urls_.end() &&
            blocked->second == failedUrl.ToString()) {
            const std::string blockedUrl = blocked->second;
            policy_blocked_urls_.erase(blocked);
            LetheCefChromeSetLoading(browser, false);
            LetheCefChromeUpdate(browser);
            main_loading_ = false;
            first_load_done_ = true;
            LetheCefAutomation::shared()->ClearPendingNavigation();
            frame->LoadURL(blockPageUrl(
                blockedUrl, "destination rejected by Lethe's network policy"));
            std::cout << "[lethe-cef] restored policy block page for "
                      << blockedUrl << " after ERR_ABORTED" << std::endl;
            std::cout.flush();
            return;
        }
        std::string fallback;
        if (browser) {
            const int id = browser->GetIdentifier();
            const std::string failed = failedUrl.ToString();
            if (IsOblivion(browser) &&
                (failed.rfind("http://", 0) == 0 ||
                 failed.rfind("ws://", 0) == 0)) {
                http_fallback_allowed_.erase(id);
                http_fallback_active_.erase(id);
                frame->LoadURL(blockPageUrl(
                    failed,
                    "Oblivion windows are https-only: unencrypted (http://) pages are never loaded"));
                LetheCefChromeSetLoading(browser, false);
                LetheCefChromeUpdate(browser);
                main_loading_ = false;
                std::cout << "[lethe-cef] Oblivion blocked plaintext navigation "
                          << failed << std::endl;
                std::cout.flush();
                return;
            }
            auto active = http_fallback_active_.find(id);
            if (active != http_fallback_active_.end()) {
                // The user already explicitly accepted the downgrade. Do not
                // turn an ordinary origin failure into a Lethe data: page;
                // keeping the failed URL lets Chromium present its native
                // error surface and preserves normal browser navigation state.
                if (failed == active->second) {
                    http_fallback_active_.erase(active);
                    // This is a terminal load outcome, not a successful
                    // navigation. Clear the browser's loading state before
                    // returning so the omnibox spinner does not remain stuck
                    // and the next user navigation is not mistaken for the
                    // previous fallback request. The URL itself is left
                    // untouched, preserving Chromium's native error surface.
                    LetheCefChromeSetLoading(browser, false);
                    LetheCefChromeUpdate(browser);
                    main_loading_ = false;
                    first_load_done_ = true;
                    LetheCefAutomation::shared()->ClearPendingNavigation();
                    std::cout << "[lethe-cef] explicit HTTP fallback failed; "
                              << "preserving URL " << failed << std::endl;
                    std::cout << "[e2e] nav-error " << errorCode << " "
                              << errorText.ToString() << " " << failed
                              << std::endl;
                    std::cout.flush();
                    return;
                }
            }
            // HTTPS-first is enforced by the shared policy proxy. CEF can
            // report the original http URL when the proxy's https attempt
            // fails, so use that authoritative failed navigation as the
            // candidate for the explicit, one-shot fallback action.
            if (ctx_ && ctx_->httpsFirst && failed.rfind("http://", 0) == 0) {
                fallback = failed;
                http_fallback_allowed_[id] = fallback;
            }
        }
        LetheCefChromeSetLoading(browser, false);
        LetheCefChromeUpdate(browser);
        main_loading_ = false;
        LetheCefAutomation::shared()->ClearPendingNavigation();
        // The policy proxy reports a DoH fail-closed decision by terminating
        // the CONNECT, which Chromium surfaces as ERR_TUNNEL_CONNECTION_FAILED
        // rather than as an HTTP 403 response. Keep the browser-level policy
        // contract intact by turning that transport-only failure into the
        // same script-free block page used for locally classified private
        // destinations. Other network/TLS errors remain native CEF errors.
        if (ctx_ && !fallback.empty()) {
            frame->LoadURL(errorPageUrl(failedUrl.ToString(),
                                         errorText.ToString(), fallback));
        } else if (errorCode == ERR_TUNNEL_CONNECTION_FAILED &&
                   ctx_ && ctx_->cfg.isolatePrivateNetworks) {
            const std::string url = failedUrl.ToString();
            const std::string reason =
                "secure DNS or policy-proxy resolution failed; Lethe "
                "refused the destination before opening an origin connection";
            frame->LoadURL(blockPageUrl(url, reason));
        }
        std::cout << "[e2e] nav-error " << errorCode << " "
                  << errorText.ToString() << " " << failedUrl.ToString()
                  << std::endl;
        std::cout.flush();
    }
}

bool CefBrowserClient::CanDownload(CefRefPtr<CefBrowser> browser,
                                   const CefString& url,
                                   const CefString& request_method) {
    (void)browser;
    (void)request_method;
    std::cout << "[lethe-cef] download request " << ShortUrlForLog(url.ToString()) << std::endl;
    return true;
}

bool CefBrowserClient::OnBeforeDownload(
    CefRefPtr<CefBrowser> browser,
    CefRefPtr<CefDownloadItem> download_item,
    const CefString& suggested_name,
    CefRefPtr<CefBeforeDownloadCallback> callback) {
    (void)browser;
    (void)download_item;
    if (!callback) return true;

    NSString* downloads = [NSSearchPathForDirectoriesInDomains(
        NSDownloadsDirectory, NSUserDomainMask, YES) firstObject];
    if (!downloads) {
        callback->Continue(CefString(), false);
        return true;
    }

    // Treat the server-provided filename as untrusted data. Strip path
    // separators and control characters so downloads cannot escape the
    // Downloads directory through traversal or malformed names.
    std::string name = suggested_name.ToString();
    for (char& c : name) {
        if (c == '/' || c == '\\' || static_cast<unsigned char>(c) < 0x20)
            c = '_';
    }
    if (name.empty() || name == "." || name == "..") name = "download";

    NSString* path = [downloads stringByAppendingPathComponent:
        [NSString stringWithUTF8String:name.c_str()]];
    callback->Continue(CefString([path UTF8String]), false);
    std::cout << "[lethe-cef] download -> " << [path UTF8String] << std::endl;
    return true;
}

void CefBrowserClient::OnDownloadUpdated(
    CefRefPtr<CefBrowser> browser,
    CefRefPtr<CefDownloadItem> download_item,
    CefRefPtr<CefDownloadItemCallback> callback) {
    (void)browser;
    if (!download_item) return;
    constexpr int64_t kMaxDownloadBytes = 512LL * 1024 * 1024;
    const int64_t total = download_item->GetTotalBytes();
    const int64_t received = download_item->GetReceivedBytes();
    if (received > kMaxDownloadBytes || (total > kMaxDownloadBytes)) {
        if (callback) callback->Cancel();
        std::cerr << "[lethe-cef] download canceled: size limit exceeded" << std::endl;
        return;
    }
    if (download_item->IsComplete() || download_item->IsCanceled() ||
        download_item->IsInterrupted()) {
        const std::string path = download_item->GetFullPath().ToString();
        std::cout << "[lethe-cef] download finished path=" << path
                  << " bytes=" << received << std::endl;
        if (download_item->IsComplete() && !path.empty()) {
            const std::string source = download_item->GetURL().ToString();
            NSString* file = [NSString stringWithUTF8String:path.c_str()];
            NSString* origin = [NSString stringWithUTF8String:source.c_str()];
            LetheScanResult* verdict =
                [LetheGuard handleFinishedDownloadAtPath:file source:origin window:nil];
            if (verdict && verdict.level > LetheThreatLevelNotice) {
                std::cout << "[lethe-cef] download scan: "
                          << verdict.headline.UTF8String << " score="
                          << verdict.score << std::endl;
            }
        }
    }
}

bool CefBrowserClient::OnRequestMediaAccessPermission(
    CefRefPtr<CefBrowser> browser,
    CefRefPtr<CefFrame> frame,
    const CefString& requesting_origin,
    uint32_t requested_permissions,
    CefRefPtr<CefMediaAccessCallback> callback) {
    (void)browser;
    (void)frame;
    std::cout << "[lethe-cef] denied media permission origin="
              << requesting_origin.ToString() << " mask="
              << requested_permissions << std::endl;
    if (callback) callback->Cancel();
    return true;
}

bool CefBrowserClient::OnShowPermissionPrompt(
    CefRefPtr<CefBrowser> browser,
    uint64_t prompt_id,
    const CefString& requesting_origin,
    uint32_t requested_permissions,
    CefRefPtr<CefPermissionPromptCallback> callback) {
    (void)browser;
    std::cout << "[lethe-cef] denied permission prompt id=" << prompt_id
              << " origin=" << requesting_origin.ToString()
              << " mask=" << requested_permissions << std::endl;
    if (callback) callback->Continue(CEF_PERMISSION_RESULT_DENY);
    return true;
}

void CefBrowserClient::ParkEvalResult(const std::string& reqId,
                                      const std::string& result) {
    std::lock_guard<std::mutex> lk(evals_mtx_);
    evals_[reqId] = result;
}

bool CefBrowserClient::TryTakeEvalResult(const std::string& reqId,
                                         std::string* out) {
    std::lock_guard<std::mutex> lk(evals_mtx_);
    auto it = evals_.find(reqId);
    if (it == evals_.end()) return false;
    if (out) *out = it->second;
    evals_.erase(it);
    return true;
}

std::string CefBrowserClient::NextEvalId() {
    const uint64_t n = eval_seq_.fetch_add(1);
    std::ostringstream o; o << "e" << n;
    return o.str();
}
