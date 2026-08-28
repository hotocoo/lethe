// cef_browser_client.cc - see cef_browser_client.h

#include "app/cef_browser_client.h"

#import <Foundation/Foundation.h>

#include <iostream>
#include <sstream>
#include <utility>

#include "include/cef_browser.h"
#include "include/cef_command_line.h"
#include "include/cef_process_message.h"
#include "include/cef_values.h"

#include "network/policy_proxy.h"

CefBrowserClient::ReturnValue CefBrowserClient::OnBeforeResourceLoad(
    CefRefPtr<CefBrowser> browser,
    CefRefPtr<CefFrame> frame,
    CefRefPtr<CefRequest> request,
    CefRefPtr<CefCallback> callback) {
    (void)browser; (void)frame; (void)callback;
    if (!ctx_ || ctx_->proxyPort <= 0 || ctx_->proxyAuthToken.empty()) {
        return RV_CONTINUE;
    }
    if (proxy_auth_header_.empty()) {
        proxy_auth_header_ = lethe::PolicyProxyServer::basicCredentialFor(
            ctx_->proxyAuthToken);
    }
    // Pre-emptive proxy auth: Chromium uses a request-level
    // Proxy-Authorization header directly on the CONNECT tunnel, so the
    // policy proxy authenticates on first contact. GetAuthCredentials
    // stays as the fallback for the 407 dance. The header terminates at
    // the proxy: tunnels end there and plain HTTP is re-fetched
    // internally, so the token never leaves loopback.
    request->SetHeaderByName("Proxy-Authorization", proxy_auth_header_, true);
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
    if (ctx_->proxyPort > 0) {
        const std::string url = "http://127.0.0.1:" + std::to_string(ctx_->proxyPort);
        command_line->AppendSwitchWithValue("proxy-server", url);
        if (!ctx_->proxyAuthToken.empty()) {
            // The proxy is HTTP, not HTTPS, so this is "lethe:<token>" sent
            // in plain over loopback. The token is per-launch, never leaves
            // the machine, and is the same secret the WebKit shell uses.
            const std::string cred = lethe::PolicyProxyServer::basicCredentialFor(
                ctx_->proxyAuthToken);
            command_line->AppendSwitchWithValue("proxy-auth", cred);
        }
        // DoH-only: tell Chromium not to bypass the proxy's resolver. The
        // proxy itself is the only thing allowed to open DNS sockets; the
        // browser subprocess's resolver would defeat that gate.
        command_line->AppendSwitch("host-resolver-rules");
    }
    // Delegate every login / proxy-auth challenge to the embedder's
    // CefRequestHandler::GetAuthCredentials. Without this CEF falls back to
    // Chrome's own login-prompt UI, which does not exist in an embedded
    // app: the 407 challenge from the policy proxy then hangs forever and
    // every https navigation dies as ERR_INVALID_AUTH_CREDENTIALS.
    command_line->AppendSwitch("disable-chrome-login-prompt");
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
    command_line->AppendSwitch("disable-default-apps");
    command_line->AppendSwitchWithValue("disable-features",
        "InterestFeedContentSuggestions,LookalikeUrlNavigationThrottle,"
        "PrivacySandboxAdsAPIs,PrivacySandboxAttributionReporting,"
        "Translate,TranslateUI");
    // --user-data-dir: without an explicit value the chromium process
    // singleton tries to read DIR_USER_DATA before any settings have
    // registered it, and crashes in chrome_main_delegate.cc:1566. The
    // CefSettings.root_cache_path field is a CEF-level setting; Chromium
    // also needs the command-line flag.
    {
        NSArray* dirs = NSSearchPathForDirectoriesInDomains(
            NSApplicationSupportDirectory, NSUserDomainMask, YES);
        NSString* path = [dirs.firstObject
            stringByAppendingPathComponent:@"Lethe CEF"];
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
}

bool CefBrowserClient::OnBeforeBrowse(CefRefPtr<CefBrowser> browser,
                                      CefRefPtr<CefFrame> frame,
                                      CefRefPtr<CefRequest> request,
                                      bool user_gesture,
                                      bool is_redirect) {
    (void)user_gesture; (void)is_redirect;
    if (!frame || !frame->IsMain()) return false;
    if (!ctx_) return false;
    // The local policy proxy already enforces everything at transport time
    // (HTTPS-first, HSTS, private-network, SSRF, VPN), so a refused URL
    // comes back as a 403 from 127.0.0.1:<port> with the named reason in
    // the body. Letting Chromium handle the failure in OnLoadError keeps
    // the UI consistent with the WebKit shell's "Blocked by Lethe policy".
    (void)browser; (void)request;
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
    (void)browser; (void)origin_url; (void)realm; (void)scheme;
    if (!ctx_ || !isProxy) return false;
    // Only ever answer the loopback policy proxy we started ourselves -
    // never volunteer the per-launch token to any other host.
    if (host.ToString() != "127.0.0.1" || port != ctx_->proxyPort) return false;
    if (ctx_->proxyAuthToken.empty()) return false;
    callback->Continue("lethe", ctx_->proxyAuthToken);
    return true;
}

void CefBrowserClient::OnAfterCreated(CefRefPtr<CefBrowser> browser) {
    if (!browser_) browser_ = browser;
    browser_count_++;
    std::cout << "[lethe-cef] browser created ("
              << browser->GetIdentifier() << ") windows=" << browser_count_
              << std::endl;
}

void CefBrowserClient::OnBeforeClose(CefRefPtr<CefBrowser> browser) {
    (void)browser;
    browser_count_--;
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
        main_loading_ = false;
        first_load_done_ = true;
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
        main_loading_ = false;
        std::cout << "[e2e] nav-error " << errorCode << " "
                  << errorText.ToString() << " " << failedUrl.ToString()
                  << std::endl;
        std::cout.flush();
    }
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
