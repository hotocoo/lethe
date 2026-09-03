// cef_browser_client.cc - see cef_browser_client.h

#include "app/cef_browser_client.h"

#import <Foundation/Foundation.h>

#include <cctype>
#include <iostream>
#include <sstream>
#include <utility>

#include "include/cef_browser.h"
#include "include/cef_command_line.h"
#include "include/cef_process_message.h"
#include "include/cef_values.h"

#include "app/cef_automation.h"
#include "app/cef_chrome.h"
#include "plugins/plugin_registry.h"
#include "network/policy_proxy.h"
#include "security/private_network_guard.h"
#include "renderer/page_templates.h"

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

bool hasSuffixInsensitive(std::string value, const std::string& suffix) {
    for (char& c : value)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (value.size() < suffix.size()) return false;
    return value.compare(value.size() - suffix.size(), suffix.size(), suffix) == 0;
}

}  // namespace

CefBrowserClient::ReturnValue CefBrowserClient::OnBeforeResourceLoad(
    CefRefPtr<CefBrowser> browser,
    CefRefPtr<CefFrame> frame,
    CefRefPtr<CefRequest> request,
    CefRefPtr<CefCallback> callback) {
    (void)browser; (void)frame; (void)callback;
    if (!ctx_ || ctx_->proxyPort <= 0 || ctx_->proxyAuthToken.empty()) {
        return RV_CONTINUE;
    }
    // Proxy-Authorization is Chromium-owned and injecting it here produces
    // ERR_INVALID_ARGUMENT. Do not use a custom header as a substitute:
    // HTTPS requests are tunneled end-to-end, so such a header would reach
    // the origin and disclose the per-launch proxy capability.
    return RV_CONTINUE;
}

void CefBrowserClient::AppBrowserProcessHandler::OnContextInitialized() {
    std::cout << "[lethe-cef] OnContextInitialized (browser process)" << std::endl;
    std::cout.flush();
}

void CefBrowserClient::AppBrowserProcessHandler::OnBeforeChildProcessLaunch(
    CefRefPtr<CefCommandLine> command_line) {
    (void)command_line;
}

void CefBrowserClient::App::OnBeforeCommandLineProcessing(
    const CefString& process_type,
    CefRefPtr<CefCommandLine> command_line) {
    // We only need to inject switches in the browser process; the renderer
    // and GPU subprocesses inherit Chromium's defaults.
    if (!process_type.empty()) return;
    if (!ctx_) return;
    // LETHE_CEF_MIN_SWITCHES=1 (bisect): skip every switch except the mock
    // keychain (the securityd startup block is fatal without it).
    if (getenv("LETHE_CEF_MIN_SWITCHES")) {
        command_line->AppendSwitch("use-mock-keychain");
        return;
    }
    if (ctx_->proxyPort > 0) {
        const std::string url = "http://127.0.0.1:" + std::to_string(ctx_->proxyPort);
        command_line->AppendSwitchWithValue("proxy-server", url);
        // DoH-only: tell Chromium not to bypass the proxy's resolver. The
        // proxy itself is the only thing allowed to open DNS sockets; the
        // browser subprocess's resolver would defeat that gate.
        // (Temporarily disabled to bisect the network-service crash.)
        // command_line->AppendSwitch("host-resolver-rules");
    }
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
                std::cout << "[lethe-cef] blocked private navigation "
                          << url << " : " << reason << std::endl;
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
    (void)target_disposition; (void)user_gesture; (void)popupFeatures;
    (void)extra_info; (void)no_javascript_access;
    std::cout << "[lethe-cef] popup " << target_url.ToString() << std::endl;
    // Use a normal native window and the same client so popup browsers enter
    // the automation browser set and remain behind the same policy handlers.
    windowInfo.bounds = CefRect(0, 0, 1280, 860);
    windowInfo.runtime_style = CEF_RUNTIME_STYLE_ALLOY;
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
    if (!shift && event.windows_key_code == 'T') {
        CefWindowInfo windowInfo;
        windowInfo.bounds = CefRect(0, 0, 1280, 860);
        windowInfo.runtime_style = CEF_RUNTIME_STYLE_ALLOY;
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
    std::cout << "[lethe-cef] GetAuthCredentials proxy=" << isProxy
              << " host=" << host.ToString() << " port=" << port
              << " scheme=" << scheme.ToString()
              << " browser=" << (browser ? browser->GetIdentifier() : -1)
              << std::endl;
    std::cout.flush();
    (void)origin_url; (void)realm; (void)scheme;
    if (!ctx_ || !isProxy) return false;
    // Only ever answer the loopback policy proxy we started ourselves -
    // never volunteer the per-launch token to any other host.
    if (host.ToString() != "127.0.0.1" || port != ctx_->proxyPort) return false;
    if (ctx_->proxyAuthToken.empty()) return false;
    callback->Continue("lethe", ctx_->proxyAuthToken);
    return true;
}

void CefBrowserClient::OnAfterCreated(CefRefPtr<CefBrowser> browser) {
    const bool first_browser = browsers_.empty();
    browsers_.push_back(browser);
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
        }
    }
    std::cout << "[lethe-cef] browser created ("
              << browser->GetIdentifier() << ") windows=" << browser_count_
              << " runtime=" << static_cast<int>(browser->GetHost()->GetRuntimeStyle())
              << std::endl;
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
        LetheCefChromeUpdate(browser);
        main_loading_ = true;
        std::cout << "[e2e] nav " << browser->GetMainFrame()->GetURL().ToString()
                  << std::endl;
        std::cout.flush();
    }
}

void CefBrowserClient::OnLoadEnd(CefRefPtr<CefBrowser> browser,
                                 CefRefPtr<CefFrame> frame,
                                 int httpStatusCode) {
    (void)browser;
    if (frame && frame->IsMain()) {
        LetheCefChromeUpdate(browser);
        main_loading_ = false;
        first_load_done_ = true;
        LetheCefAutomation::shared()->ClearPendingNavigation();
        std::cout << "[e2e] nav-end " << frame->GetURL().ToString()
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
    (void)browser;
    if (frame && frame->IsMain()) {
        LetheCefChromeUpdate(browser);
        main_loading_ = false;
        LetheCefAutomation::shared()->ClearPendingNavigation();
        // The policy proxy reports a DoH fail-closed decision by terminating
        // the CONNECT, which Chromium surfaces as ERR_TUNNEL_CONNECTION_FAILED
        // rather than as an HTTP 403 response. Keep the browser-level policy
        // contract intact by turning that transport-only failure into the
        // same script-free block page used for locally classified private
        // destinations. Other network/TLS errors remain native CEF errors.
        if (errorCode == ERR_TUNNEL_CONNECTION_FAILED &&
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
    std::cout << "[lethe-cef] download request " << url.ToString() << std::endl;
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
        std::cout << "[lethe-cef] download finished path="
                  << download_item->GetFullPath().ToString()
                  << " bytes=" << received << std::endl;
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
