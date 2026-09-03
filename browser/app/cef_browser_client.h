// cef_browser_client.h - CEF browser process client (BrowserClient).
//
// Owns the CefBrowser instances and the load callbacks. Routes navigation
// through the shared lethe_core policy gate the same way the WebKit shell
// does (CefRequestHandler::OnBeforeBrowse -> LethePolicyGate::checkURL).
//
// Engine-agnostic: the same CefClient is reused if a new tab is opened
// (window.open) because CEF keys new browsers by the CefClient set on
// CefWindowInfo; multiple CefBrowser objects can share one client.
#ifndef LETHE_BROWSER_APP_CEF_BROWSER_CLIENT_H
#define LETHE_BROWSER_APP_CEF_BROWSER_CLIENT_H

#include <atomic>
#include <string>
#include <unordered_map>
#include <mutex>
#include <vector>

#include "include/cef_client.h"
#include "include/cef_request_handler.h"
#include "include/cef_life_span_handler.h"
#include "include/cef_load_handler.h"
#include "include/cef_download_handler.h"
#include "include/cef_permission_handler.h"
#include "include/cef_keyboard_handler.h"
#include "include/cef_command_line.h"
#include "include/cef_process_message.h"

#include "app/shell_bootstrap.h"
#include "app/cef_render_handler.h"

class CefBrowserClient : public CefClient,
                         public CefRequestHandler,
                         public CefResourceRequestHandler,
                         public CefLifeSpanHandler,
                         public CefLoadHandler,
                         public CefDownloadHandler,
                         public CefPermissionHandler,
                         public CefKeyboardHandler {
 public:
    // CefBrowserProcessHandler: CEF used to run with a null handler here,
    // which silently disabled OnContextInitialized / OnBeforeChildProcessLaunch.
    // OnBeforeChildProcessLaunch is the last browser-side hook before the
    // child exec - logging the child command line there is how we can tell
    // "renderer launch attempted, exec failed" apart from "never attempted".
    class AppBrowserProcessHandler : public CefBrowserProcessHandler {
     public:
        explicit AppBrowserProcessHandler(const lethe::ShellContext* ctx)
            : ctx_(ctx) {}
        void OnContextInitialized() override;
        void OnBeforeChildProcessLaunch(
            CefRefPtr<CefCommandLine> command_line) override;
     private:
        const lethe::ShellContext* ctx_ = nullptr;
        IMPLEMENT_REFCOUNTING(AppBrowserProcessHandler);
    };

    // CefApp implementation that injects the policy proxy into Chromium's
    // net stack before any process starts. This is what binds CEF to the
    // shared ShellBootstrap (and therefore to the same DoH, HSTS, private-
    // network policy, VPN tunnel that the WebKit shell uses).
    class App : public CefApp {
     public:
        App() = default;
        void SetShellContext(const lethe::ShellContext* ctx) { ctx_ = ctx; }
        void OnBeforeCommandLineProcessing(
            const CefString& process_type,
            CefRefPtr<CefCommandLine> command_line) override;
        CefRefPtr<CefBrowserProcessHandler> GetBrowserProcessHandler() override {
            if (!browser_process_handler_) {
                browser_process_handler_ = new AppBrowserProcessHandler(ctx_);
            }
            return browser_process_handler_;
        }
        CefRefPtr<CefRenderProcessHandler> GetRenderProcessHandler() override {
            if (!render_process_handler_) {
                render_process_handler_ = new LetheCefRenderHandler();
            }
            return render_process_handler_;
        }
     private:
        CefRefPtr<CefBrowserProcessHandler> browser_process_handler_;
        CefRefPtr<CefRenderProcessHandler> render_process_handler_;
        const lethe::ShellContext* ctx_ = nullptr;
        IMPLEMENT_REFCOUNTING(App);
    };

    CefBrowserClient() = default;
    void SetShellContext(const lethe::ShellContext* ctx) { ctx_ = ctx; }

    // CefClient
    CefRefPtr<CefRequestHandler> GetRequestHandler() override { return this; }
    CefRefPtr<CefResourceRequestHandler> GetResourceRequestHandler(
        CefRefPtr<CefBrowser> browser,
        CefRefPtr<CefFrame> frame,
        CefRefPtr<CefRequest> request,
        bool is_navigation,
        bool is_download,
        const CefString& request_initiator,
        bool& disable_default_handling) override {
        (void)browser; (void)frame; (void)request; (void)is_navigation;
        (void)is_download; (void)request_initiator;
        disable_default_handling = false;
        return this;
    }

    // CefResourceRequestHandler - stamp the per-launch proxy token onto
    // every request. Chromium strips Proxy-Authorization out of CONNECT
    // tunnel requests (it belongs to the auth system, whose CEF routing
    // never fires for the tunnel in this build), but it forwards custom
    // X- headers onto the tunnel, so the policy proxy accepts
    // X-Lethe-Proxy-Auth as the credential. The header terminates at the
    // proxy: CONNECT tunnels end there and plain-HTTP requests are
    // re-fetched internally, so the token never leaves loopback.
    ReturnValue OnBeforeResourceLoad(CefRefPtr<CefBrowser> browser,
                                     CefRefPtr<CefFrame> frame,
                                     CefRefPtr<CefRequest> request,
                                     CefRefPtr<CefCallback> callback) override;
    CefRefPtr<CefLifeSpanHandler> GetLifeSpanHandler() override { return this; }
    CefRefPtr<CefLoadHandler> GetLoadHandler() override { return this; }
    CefRefPtr<CefDownloadHandler> GetDownloadHandler() override { return this; }
    CefRefPtr<CefPermissionHandler> GetPermissionHandler() override { return this; }
    CefRefPtr<CefKeyboardHandler> GetKeyboardHandler() override { return this; }

    // CefRequestHandler - route every navigation through lethe_core policy.
    bool OnBeforeBrowse(CefRefPtr<CefBrowser> browser,
                        CefRefPtr<CefFrame> frame,
                        CefRefPtr<CefRequest> request,
                        bool user_gesture,
                        bool is_redirect) override;

    bool OnBeforePopup(CefRefPtr<CefBrowser> browser,
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
                       bool* no_javascript_access) override;

    // CefKeyboardHandler - native browser shortcuts must work even when the
    // renderer has focus. Cmd+T creates a real CEF browser and lets the macOS
    // chrome layer place its native window into the current tab group.
    bool OnPreKeyEvent(CefRefPtr<CefBrowser> browser,
                       const CefKeyEvent& event,
                       CefEventHandle os_event,
                       bool* is_keyboard_shortcut) override;

    // CefRequestHandler - answer the policy proxy's 407 challenge with the
    // per-launch token. The proxy is the only network path Chromium has, so
    // without this every real page fails with ERR_INVALID_AUTH_CREDENTIALS.
    bool GetAuthCredentials(CefRefPtr<CefBrowser> browser,
                            const CefString& origin_url,
                            bool isProxy,
                            const CefString& host,
                            int port,
                            const CefString& realm,
                            const CefString& scheme,
                            CefRefPtr<CefAuthCallback> callback) override;

    // CefLifeSpanHandler - one NSWindow per top-level browser, single
    // process model: subsequent windows also reuse this client.
    void OnAfterCreated(CefRefPtr<CefBrowser> browser) override;
    bool DoClose(CefRefPtr<CefBrowser> browser) override;
    void OnBeforeClose(CefRefPtr<CefBrowser> browser) override;
    bool OnProcessMessageReceived(CefRefPtr<CefBrowser> browser,
                                  CefRefPtr<CefFrame> frame,
                                  CefProcessId source_process,
                                  CefRefPtr<CefProcessMessage> message) override;

    // CefLoadHandler - bridge state into the e2e driver / mark events.
    void OnLoadStart(CefRefPtr<CefBrowser> browser,
                     CefRefPtr<CefFrame> frame,
                     TransitionType transition_type) override;
    void OnLoadEnd(CefRefPtr<CefBrowser> browser,
                   CefRefPtr<CefFrame> frame,
                   int httpStatusCode) override;
    void OnLoadError(CefRefPtr<CefBrowser> browser,
                     CefRefPtr<CefFrame> frame,
                     ErrorCode errorCode,
                     const CefString& errorText,
                     const CefString& failedUrl) override;

    // Downloads: save into the user's Downloads directory, never execute or
    // hand off to another application. Cap each transfer at 512 MiB to stop
    // drive-fill attacks from hostile pages.
    bool CanDownload(CefRefPtr<CefBrowser> browser,
                     const CefString& url,
                     const CefString& request_method) override;
    bool OnBeforeDownload(CefRefPtr<CefBrowser> browser,
                          CefRefPtr<CefDownloadItem> download_item,
                          const CefString& suggested_name,
                          CefRefPtr<CefBeforeDownloadCallback> callback) override;
    void OnDownloadUpdated(CefRefPtr<CefBrowser> browser,
                           CefRefPtr<CefDownloadItem> download_item,
                           CefRefPtr<CefDownloadItemCallback> callback) override;

    // Secure default: deny camera, microphone, notifications, geolocation,
    // MIDI, and other privileged permission prompts until explicit UI exists.
    bool OnRequestMediaAccessPermission(
        CefRefPtr<CefBrowser> browser,
        CefRefPtr<CefFrame> frame,
        const CefString& requesting_origin,
        uint32_t requested_permissions,
        CefRefPtr<CefMediaAccessCallback> callback) override;
    bool OnShowPermissionPrompt(
        CefRefPtr<CefBrowser> browser,
        uint64_t prompt_id,
        const CefString& requesting_origin,
        uint32_t requested_permissions,
        CefRefPtr<CefPermissionPromptCallback> callback) override;

    // The e2e driver pushes an eval request, the renderer replies; the
    // reply lands in OnProcessMessageReceived and gets parked here for the
    // driver to read.
    void ParkEvalResult(const std::string& reqId, const std::string& result);
    bool TryTakeEvalResult(const std::string& reqId, std::string* out);
    // Stable request id generator.
    std::string NextEvalId();

    bool IsMainLoading() const { return main_loading_; }
    // True once any main-frame navigation has committed (OnLoadEnd). CEF
    // silently drops CefFrame::LoadURL issued before the renderer's first
    // frame commit, so the e2e driver waits for this before the first load.
    bool IsFirstLoadDone() const { return first_load_done_; }
    CefRefPtr<CefBrowser> GetBrowser() const { return browser_; }
    void SetPendingQuit(bool q) { quit_when_loaded_ = q; }

 private:
    const lethe::ShellContext* ctx_ = nullptr;
    CefRefPtr<CefBrowser> browser_;
    std::vector<CefRefPtr<CefBrowser>> browsers_;
    std::atomic<bool> main_loading_{false};
    std::atomic<bool> first_load_done_{false};
    std::string proxy_auth_header_;
    bool quit_when_loaded_ = false;
    int browser_count_ = 0;

    std::mutex evals_mtx_;
    std::unordered_map<std::string, std::string> evals_;
    std::atomic<uint64_t> eval_seq_{0};

    IMPLEMENT_REFCOUNTING(CefBrowserClient);
};

#endif  // LETHE_BROWSER_APP_CEF_BROWSER_CLIENT_H
