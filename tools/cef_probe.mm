// cef_probe.mm - minimal CEF diagnosis probe (no Lethe code, no AppKit).
//
// Windowless (OSR) browser that navigates example.com and prints the page
// title on load end, driven by the canonical CefRunMessageLoop() straight
// from main() - no NSApplication, no engine, no policy proxy, no sandbox.
// Purpose: separate "CEF/Chromium on this machine" from "the lethe-cef
// integration" when the browser-info handshake stalls.
//
// Build (see tools/build_cef_probe.sh): links the same CEF dist the
// lethe-cef target uses.
//
// Run: LETHE_CEF_USER_DATA_DIR is NOT used here; pass --user-data-dir or
// nothing (uses the CEF default). Print: [probe] lines on stdout.

#include <cstdio>
#include <climits>
#include <cstdlib>
#define PROBE_TRACE(msg) fprintf(stderr, "[probe] %s\n", msg)
#include <iostream>
#include <deque>
#include <string>

#include "include/cef_app.h"
#include "include/cef_browser.h"
#include "include/cef_client.h"
#include "include/cef_render_handler.h"
#include "include/wrapper/cef_helpers.h"
#import <Cocoa/Cocoa.h>

// LETHE_PROBE_BOOTSTRAP=1: run the lethe ShellBootstrap (engine, VPN
// tunnel, DoH pool) before CefInitialize, exactly like the lethe-cef host.
#if defined(LETHE_PROBE_WITH_BOOTSTRAP)
#include "app/shell_bootstrap.h"
#endif

namespace {

class ProbeRenderHandler : public CefRenderHandler {
 public:
    ProbeRenderHandler() = default;
    void GetViewRect(CefRefPtr<CefBrowser>, CefRect& rect) override {
        rect = CefRect(0, 0, 1280, 720);
    }
    void OnPaint(CefRefPtr<CefBrowser>, PaintElementType, const RectList&,
                 const void*, int, int) override {}
 private:
    IMPLEMENT_REFCOUNTING(ProbeRenderHandler);
};

class ProbeClient : public CefClient, public CefLifeSpanHandler,
                    public CefLoadHandler {
 public:
    explicit ProbeClient(std::string url) : url_(std::move(url)) {
        urls_ = {"https://www.iana.org/domains/reserved",
                 "https://en.wikipedia.org/wiki/Web_browser",
                 "https://httpforever.com/"};
    }
    CefRefPtr<CefLifeSpanHandler> GetLifeSpanHandler() override { return this; }
    CefRefPtr<CefLoadHandler> GetLoadHandler() override { return this; }
    CefRefPtr<CefRenderHandler> GetRenderHandler() override { return render_; }

    void OnAfterCreated(CefRefPtr<CefBrowser> browser) override {
        PROBE_TRACE("after-created");
        browser_ = browser;
    }
    void OnLoadingStateChange(CefRefPtr<CefBrowser>, bool isLoading, bool canGoBack,
                              bool canGoForward) override {
        fprintf(stderr, "[probe] loading-state isLoading=%d\n", isLoading ? 1 : 0);
    }
    void OnLoadStart(CefRefPtr<CefBrowser>, CefRefPtr<CefFrame> frame,
                     TransitionType) override {
        fprintf(stderr, "[probe] load-start url=%s\n", frame->GetURL().ToString().c_str());
    }
    void OnLoadEnd(CefRefPtr<CefBrowser>, CefRefPtr<CefFrame> frame,
                   int httpStatusCode) override {
        std::cout << "[probe] load-end status=" << httpStatusCode
                  << " url=" << frame->GetURL().ToString() << std::endl;
        // Second direct cross-origin navigation: exercises the browser-info
        // handshake for a NEW speculative RFH (round-4 suspicion).
        if (urls_.empty()) { Quit(0); return; }
        std::string next = urls_.front();
        urls_.pop_front();
        fprintf(stderr, "[probe] navigate -> %s\n", next.c_str());
        browser_->GetMainFrame()->LoadURL(next);
    }
    void OnLoadError(CefRefPtr<CefBrowser>, CefRefPtr<CefFrame> frame,
                     ErrorCode code, const CefString& text,
                     const CefString&) override {
        std::cout << "[probe] load-error " << code << " " << text.ToString()
                  << " url=" << frame->GetURL().ToString() << std::endl;
        Quit(1);
    }
    void Quit(int code) {
        // OnLoadEnd/OnLoadError run on the UI thread: quit directly.
        if (browser_) browser_->GetHost()->CloseBrowser(true);
        CefQuitMessageLoop();
    }

 private:
    std::string url_;
    std::deque<std::string> urls_;
    CefRefPtr<CefBrowser> browser_;
    CefRefPtr<ProbeRenderHandler> render_ = new ProbeRenderHandler();
    int exitCode_ = 0;
    IMPLEMENT_REFCOUNTING(ProbeClient);
};

class ProbeApp : public CefApp, public CefBrowserProcessHandler {
 public:
    ProbeApp() = default;
    CefRefPtr<CefBrowserProcessHandler> GetBrowserProcessHandler() override {
        return this;
    }
    // Lethe's round-4 lesson applies here too: without the mock keychain
    // Chromium reads the "Chromium Safe Storage" item and blocks the
    // browser UI thread in securityd/Security framework decrypt.
    void OnBeforeCommandLineProcessing(const CefString& process_type,
                                       CefRefPtr<CefCommandLine> cl) override {
        if (cl && !cl->HasSwitch("use-mock-keychain"))
            cl->AppendSwitch("use-mock-keychain");
        // LETHE_PROBE_SWITCHES=1: replicate lethe-cef's browser-process
        // switch set (minus the proxy lines, which need a live proxy).
        if (std::getenv("LETHE_PROBE_SWITCHES") && process_type.empty() && cl) {
            cl->AppendSwitch("disable-chrome-login-prompt");
            cl->AppendSwitch("disable-background-networking");
            cl->AppendSwitch("disable-default-apps");
            cl->AppendSwitch("disable-domain-reliability");
            cl->AppendSwitch("disable-sync");
            cl->AppendSwitch("disable-translate");
            cl->AppendSwitch("no-pings");
            cl->AppendSwitch("no-first-run");
            cl->AppendSwitch("disable-process-singleton");
            cl->AppendSwitch("disable-features");
            cl->AppendSwitchWithValue("disable-features",
                "InterestFeedContentSuggestions,LookalikeUrlNavigationThrottle,"
                "PrivacySandboxAdsAPIs,PrivacySandboxAttributionReporting,"
                "Translate,TranslateUI");
            // lethe-cef appends this with NO value:
            cl->AppendSwitch("host-resolver-rules");
            cl->AppendSwitchWithValue("user-data-dir", udd_);
        }
    }
    void SetUdd(const std::string& udd) { udd_ = udd; }
 private:
    std::string udd_;
    void OnContextInitialized() override {
        PROBE_TRACE("context-initialized");
    }
 private:
    IMPLEMENT_REFCOUNTING(ProbeApp);
};


}  // namespace

// --- NSApp-nested variant (replicates the lethe-cef host structure) -----
@interface ProbeNSAppDelegate : NSObject <NSApplicationDelegate> {
@public
    CefRefPtr<ProbeApp> cefApp;
    std::string url;
    std::string udd;
}
@end
@implementation ProbeNSAppDelegate
- (void)applicationDidFinishLaunching:(NSNotification*)note {
    (void)note;
    PROBE_TRACE("nsapp: didFinishLaunching");
    CefMainArgs args(0, nullptr);
    CefSettings settings;
    settings.windowless_rendering_enabled = true;
    settings.no_sandbox = true;
    settings.log_severity = LOGSEVERITY_WARNING;
    std::string helper = std::getenv("LETHE_CEF_HELPER")
        ? std::getenv("LETHE_CEF_HELPER")
        : "build-cef/lethe-cef.app/Contents/Frameworks/"
          "Lethe CEF Helper.app/Contents/MacOS/lethe_cef_helper";
    if (!helper.empty() && helper[0] != '/') {
        char buf[PATH_MAX];
        if (realpath(helper.c_str(), buf)) helper = buf;
    }
    CefString(&settings.browser_subprocess_path).FromString(helper);
    PROBE_TRACE("nsapp: CefInitialize");
    CefInitialize(args, settings, cefApp, nullptr);
    PROBE_TRACE("nsapp: initialized");
    CefWindowInfo info;
    info.SetAsWindowless(0);
    CefBrowserSettings bsettings;
    CefRefPtr<ProbeClient> client = new ProbeClient(url);
    PROBE_TRACE("nsapp: create-browser");
    CefRefPtr<CefBrowser> b = CefBrowserHost::CreateBrowserSync(
        info, client, url.empty() ? "about:blank" : url,
        bsettings, nullptr, nullptr);
    PROBE_TRACE(b ? "nsapp: create-browser-ok" : "nsapp: create-browser-NULL");
    PROBE_TRACE("nsapp: CefRunMessageLoop (nested inside NSApp run)");
    CefRunMessageLoop();
    PROBE_TRACE("nsapp: loop returned");
    CefShutdown();
    [[NSApplication sharedApplication] terminate:nil];
}
@end


int main(int argc, char* argv[]) {
    PROBE_TRACE("main");
    CefMainArgs args(argc, argv);
    CefRefPtr<ProbeApp> app = new ProbeApp();
    CefRefPtr<ProbeApp> app2 = new ProbeApp();
    PROBE_TRACE("execute-process");
    const int rc = CefExecuteProcess(args, app, nullptr);
    PROBE_TRACE("execute-process-done");
    if (rc >= 0) return rc;

    std::string url = argc > 1 ? argv[1] : "https://example.com/";
    // LETHE_PROBE_NSAPP=1: replicate the lethe-cef host structure exactly
    // (NSApp run loop with CefInitialize + CreateBrowserSync + nested
    // CefRunMessageLoop inside applicationDidFinishLaunching) to bisect the
    // host-integration suspects.
    if (std::getenv("LETHE_PROBE_NSAPP")) {
        @autoreleasepool {
            NSApplication* app = [NSApplication sharedApplication];
            [app setActivationPolicy:NSApplicationActivationPolicyAccessory];
            ProbeNSAppDelegate* del = [ProbeNSAppDelegate new];
            del->cefApp = app2;
            del->url = url;
            app.delegate = del;
            [app run];
        }
        return 0;
    }
    CefSettings settings;
    settings.windowless_rendering_enabled = true;
    settings.no_sandbox = true;
    settings.log_severity = LOGSEVERITY_WARNING;
    settings.multi_threaded_message_loop = false;
    // Renderer subprocess: reuse the lethe-cef app's helper (a plain
    // CefExecuteProcess binary, host-agnostic). CEF requires an absolute
    // path. Overridable via LETHE_CEF_HELPER for other layouts.
    std::string helper = std::getenv("LETHE_CEF_HELPER")
        ? std::getenv("LETHE_CEF_HELPER")
        : "build-cef/lethe-cef.app/Contents/Frameworks/"
          "Lethe CEF Helper.app/Contents/MacOS/lethe_cef_helper";
    if (!helper.empty() && helper[0] != '/') {
        char buf[PATH_MAX];
        if (realpath(helper.c_str(), buf)) helper = buf;
    }
    CefString(&settings.browser_subprocess_path).FromString(helper);
    std::cout << "[probe] initializing (helper=" << helper << ")" << std::endl;
    CefInitialize(args, settings, app, nullptr);
    PROBE_TRACE("initialized");

    CefWindowInfo info;
    CefRefPtr<ProbeClient> client = new ProbeClient(url);
    if (std::getenv("LETHE_PROBE_WINDOWED")) {
        PROBE_TRACE("windowed variant");
        NSRect frame = NSMakeRect(100, 100, 1280, 720);
        NSWindow* win = [[NSWindow alloc]
            initWithContentRect:frame
                      styleMask:NSWindowStyleMaskTitled |
                                NSWindowStyleMaskClosable |
                                NSWindowStyleMaskMiniaturizable |
                                NSWindowStyleMaskResizable
                        backing:NSBackingStoreBuffered
                          defer:NO];
        [win setTitle:@"cef_probe"];
        NSView* view = [[NSView alloc] initWithFrame:frame];
        [win setContentView:view];
        [win makeFirstResponder:view];
        [win orderFrontRegardless];
        [win makeKeyWindow];
        info.SetAsChild((__bridge void*)view, CefRect(0, 0, 1280, 720));
    } else {
        info.SetAsWindowless(0);
    }
    CefBrowserSettings bsettings;
    PROBE_TRACE("create-browser");
    // Start directly on the requested URL: the first main frame is then
    // created inside the initial renderer, avoiding the dropped-LoadURL
    // race with the browser-info handshake.
    CefRefPtr<CefBrowser> b = CefBrowserHost::CreateBrowserSync(info, client, url,
                                      bsettings, nullptr, nullptr);
    PROBE_TRACE(b ? "create-browser-ok" : "create-browser-NULL");
    CefRunMessageLoop();
    CefShutdown();
    return 0;
}
