// cef_app_delegate.mm - NSApplication delegate for the CEF shell.
//
// Owns the CefBrowserClient (one CefApp + CefClient + browser window). The
// CefApp subclass injects the policy proxy into Chromium's net stack via
// OnBeforeCommandLineProcessing, so the same ShellBootstrap proxy that the
// WebKit shell uses is also the only path CEF can reach the network on.
//
// Engine init order: ShellBootstrap first (engine, DoH, proxy), then
// CefInitialize, then the CefBrowserHost::CreateBrowser that opens the
// first window. The CEF message-loop owner in main_cef.mm performs the
// single, final CefShutdown + ShellBootstrap::shutdown after the loop
// returns. AppKit termination notifications must not tear the bootstrap
// down while a CEF browser callback is still executing.

#include "app/cef_app_delegate.h"

#import <Cocoa/Cocoa.h>

#include <cstring>
#include <iostream>

#include "include/cef_browser.h"
#include "include/internal/cef_string.h"
#include "include/cef_command_line.h"
#include "include/cef_process_message.h"
#include "include/cef_values.h"
#include "include/wrapper/cef_helpers.h"

#include "app/cef_automation.h"
#include "app/cef_chrome.h"

#include "network/policy_proxy.h"
#include "plugins/plugin_registry.h"

@implementation LetheCefAppDelegate {
    lethe::ShellContext* _ctx;
    CefRefPtr<CefBrowserClient::App> _cefApp;
    CefRefPtr<CefBrowserClient> _client;
    int _argc;
    char** _argv;
}

- (void)createInitialBrowser {
    // CEF on macOS has a long-standing lifecycle edge case when a native
    // browser is created synchronously before CefRunMessageLoop() starts:
    // CloseBrowser() can reach DoClose() but the top-level window never
    // completes destruction. Defer creation onto the main/UI event queue so
    // the browser is created from inside the running CEF/AppKit loop.
    CefWindowInfo windowInfo;
    CefRect rect(0, 0, 1280, 860);
    windowInfo.bounds = rect;
    windowInfo.runtime_style = CEF_RUNTIME_STYLE_ALLOY;

    CefBrowserSettings browserSettings;
    browserSettings.background_color = 0xFFFFFFFFu;
    if (!lethe::PluginRegistry::instance().enabled("javascript")) {
        browserSettings.javascript = STATE_DISABLED;
    }

    std::string startUrl = LetheCefNewTabDataUrl();
    if (_ctx && !_ctx->cfg.initialUrl.empty()) startUrl = _ctx->cfg.initialUrl;

    if (!CefBrowserHost::CreateBrowser(
            windowInfo, _client, startUrl, browserSettings, nullptr, nullptr)) {
        std::cerr << "[lethe-cef] CreateBrowser failed" << std::endl;
        CefQuitMessageLoop();
        return;
    }

    // Honour --e2e-script only after the browser creation request has been
    // submitted to the running UI loop. OnAfterCreated will register the
    // actual browser with the automation driver before its first 600 ms tick.
    NSString* scriptPath = [[NSUserDefaults standardUserDefaults]
        stringForKey:@"e2e-script"];
    if (scriptPath.length) {
        LetheCefAutomation::shared()->Start(self, [scriptPath UTF8String]);
    } else if (_ctx && !_ctx->e2eScript.empty()) {
        LetheCefAutomation::shared()->Start(self, _ctx->e2eScript);
    }
}

- (void)newTabFromMenu:(id)sender {
    (void)sender;
    // AppKit menu key equivalents are the native macOS command path. Keep
    // this separate from CEF's OnPreKeyEvent handler: when a renderer or
    // NSTextField has focus, AppKit may consume Cmd+T before CEF sees the
    // raw key event. Both paths create the same CEF browser, and OnAfterCreated
    // folds the resulting native window into the existing tab group.
    if (!_client) return;

    CefWindowInfo windowInfo;
    windowInfo.bounds = CefRect(0, 0, 1280, 860);
    windowInfo.runtime_style = CEF_RUNTIME_STYLE_ALLOY;
    CefBrowserSettings settings;
    settings.background_color = 0xFFFFFFFFu;
    if (!lethe::PluginRegistry::instance().enabled("javascript"))
        settings.javascript = STATE_DISABLED;

    const std::string startUrl = LetheCefNewTabDataUrl();
    if (!CefBrowserHost::CreateBrowser(
            windowInfo, _client, startUrl, settings, nullptr, nullptr)) {
        std::cerr << "[lethe-cef] native Cmd+T CreateBrowser failed" << std::endl;
        return;
    }
    std::cout << "[lethe-cef] native Cmd+T -> new tab" << std::endl;
}

- (void)installNativeMenu {
    NSMenu* bar = [[NSMenu alloc] initWithTitle:@"Main Menu"];
    NSMenuItem* fileHolder = [[NSMenuItem alloc] initWithTitle:@"File"
                                                       action:nil
                                                keyEquivalent:@""];
    NSMenu* file = [[NSMenu alloc] initWithTitle:@"File"];
    fileHolder.submenu = file;
    NSMenuItem* newTab = [[NSMenuItem alloc]
        initWithTitle:@"New Tab"
               action:@selector(newTabFromMenu:)
        keyEquivalent:@"t"];
    newTab.keyEquivalentModifierMask = NSEventModifierFlagCommand;
    newTab.target = self;
    [file addItem:newTab];
    [bar addItem:fileHolder];
    [NSApp setMainMenu:bar];
}

@synthesize context = _ctx;
@synthesize client = _client;

- (instancetype)initWithContext:(lethe::ShellContext*)ctx
                           app:(CefRefPtr<CefBrowserClient::App>)cefApp
                        client:(CefRefPtr<CefBrowserClient>)client
                          argc:(int)argc
                          argv:(char**)argv {
    if ((self = [super init])) {
        _ctx = ctx;
        _cefApp = cefApp;
        _client = client;
        _argc = argc;
        _argv = argv;
    }
    return self;
}

- (void)initializeCEF {
    [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];

    CefMainArgs args(_argc, _argv);  // plumbed from main(); carries --disable-process-singleton etc.
    CefSettings settings;
    // macOS ignores CefMainArgs argc/argv (CEF reads the process args from
    // NSProcessInfo). Force the singleton off on the global command line
    // before Chromium boots. Chromium's own subprocess sandbox remains on;
    // Lethe's Seatbelt is an additional host-level boundary.
    CefRefPtr<CefCommandLine> global = CefCommandLine::GetGlobalCommandLine();
    // LETHE_CEF_MIN_SWITCHES=1 (bisect): skip the global-command-line block
    // entirely (mock keychain still applied by App::OnBeforeCommandLineProcessing).
    const bool minSwitches = getenv("LETHE_CEF_MIN_SWITCHES") != nullptr;
    if (global && !minSwitches) {
        // Lethe is ephemeral by default: there is no stored password or
        // cookie blob to decrypt. Chromium's OSCrypt would still read the
        // "Chromium Safe Storage" keychain item at startup - a modal
        // keychain prompt on every launch that blocks the browser UI
        // thread in securityd and (through CEF's 15 s browser-info
        // handshake timeout) kills the first navigation. The mock keychain
        // skips the prompt and the keychain entirely.
        if (!global->HasSwitch("use-mock-keychain"))
            global->AppendSwitch("use-mock-keychain");
        if (!global->HasSwitch("disable-process-singleton"))
            global->AppendSwitch("disable-process-singleton");
        if (!global->HasSwitch("disable-default-apps"))
            global->AppendSwitch("disable-default-apps");
        if (!global->HasSwitch("disable-dev-shm-usage"))
            global->AppendSwitch("disable-dev-shm-usage");
        // Belt and suspenders for the net stack: OnBeforeCommandLineProcessing
        // also appends proxy-server, but Chromium consumes --proxy-server and
        // strips it from the command line handed to child processes. The
        // network service runs as its own utility process in this build, so
        // re-asserting on the global command line before CefInitialize is the
        // reliable path (the same path that carries --no-sandbox). Without it
        // the network service dials targets directly and every navigation
        // hangs past OnBeforeBrowse with no OnLoadStart and no OnLoadError.
        if (_ctx && _ctx->proxyPort > 0) {
            const std::string proxyUrl =
                "http://127.0.0.1:" + std::to_string(_ctx->proxyPort);
            if (!global->HasSwitch("proxy-server"))
                global->AppendSwitchWithValue("proxy-server", proxyUrl);
            if (!_ctx->proxyAuthToken.empty() && !global->HasSwitch("proxy-auth"))
                global->AppendSwitchWithValue(
                    "proxy-auth",
                    lethe::PolicyProxyServer::basicCredentialFor(
                        _ctx->proxyAuthToken));
            // Never bypass the proxy for loopback targets: the policy proxy
            // itself is loopback, and Chromium's default bypass list would
            // otherwise let loopback destinations escape the policy gate.
            if (!global->HasSwitch("proxy-bypass-list"))
                global->AppendSwitchWithValue("proxy-bypass-list", "<-loopback>");
        }
        // Diagnostics: LETHE_CEF_NETLOG=<path> dumps the Chromium net log
        // (proxy config, socket errors) for offline inspection.
        if (const char* netlog = getenv("LETHE_CEF_NETLOG")) {
            if (!global->HasSwitch("log-net-log"))
                global->AppendSwitchWithValue("log-net-log", netlog);
        }
    }
    // Keep Chromium's renderer/GPU sandbox enabled by default. If the user
    // explicitly disables native CEF sandboxing, the shared Lethe Seatbelt
    // can be used instead.
    const char* nativeSandbox = getenv("LETHE_CEF_NATIVE_SANDBOX");
    settings.no_sandbox = nativeSandbox && std::string(nativeSandbox) == "0";
    // Crash forensics: Chromium CHECK aborts print only through CEF's
    // logging sink. Route it somewhere we can read after a SIGTRAP.
    {
        const char* src = "/tmp/lethe-cef-debug.log";
        cef_string_from_utf8(src, strlen(src), &settings.log_file);
        settings.log_severity = LOGSEVERITY_INFO;
    }
    // No persistent cache by default: every launch is a fresh profile.
    // The Settings UI can flip this in a follow-up.
    settings.multi_threaded_message_loop = false;  // we run our own run loop
    settings.command_line_args_disabled = false;
    // Bypass the GPU process if the system has no GPU; CEF still works
    // through software compositing. (Same default as upstream cefclient.)
    settings.uncaught_exception_stack_size = 8;
    // Chromium needs a writable user data dir; the warning otherwise is
    // an actual path_service::DIR_USER_DATA failure at startup on macOS.
    NSArray* dirs = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory,
                                                        NSUserDomainMask, YES);
    NSString* root = [dirs.firstObject stringByAppendingPathComponent:@"Lethe CEF"];
    // Same override main_cef.mm honored: one profile per run on request
    // (bench + interactive, or two sessions sharing one checkout).
    if (const char* override = getenv("LETHE_CEF_USER_DATA_DIR")) {
        if (*override) root = [NSString stringWithUTF8String:override];
    }
    [[NSFileManager defaultManager] createDirectoryAtPath:root
        withIntermediateDirectories:YES attributes:nil error:nil];
    // CefSettings exposes the underlying cef_settings_t fields directly;
    // root_cache_path is a raw cef_string_t (UTF-16 on macOS). Convert
    // the NSString path with cef_string_from_utf8.
    {
        const char* src = [root UTF8String] ?: "";
        cef_string_from_utf8(src, strlen(src), &settings.root_cache_path);
    }
    // Chromium's path_service also resolves DIR_USER_DATA from a few
    // platform-specific env vars. The current macOS build reads
    // CHROME_USER_DATA_DIR at first touch, before any settings kick in.
    // Set it as a belt-and-suspenders alongside --user-data-dir so the
    // helper processes find the same directory.
    setenv("CHROME_USER_DATA_DIR", [root UTF8String] ?: "", 1);
    // The browser subprocess path. CEF spawns a Helper binary for every
    // renderer / GPU / network / utility process; we point it at the
    // helper.app we copied into the bundle.
    {
        NSString* helperPath = [[NSBundle mainBundle].bundlePath
            stringByAppendingPathComponent:
                @"Contents/Frameworks/Lethe CEF Helper.app/Contents/MacOS/lethe_cef_helper"];
        const char* src = [helperPath UTF8String] ?: "";
        cef_string_from_utf8(src, strlen(src), &settings.browser_subprocess_path);
    }

    // CefInitialize auto-locates the CEF framework from the executable path,
    // so no manual main_bundle_path / framework_dir_path plumbing is needed
    // for the standard layout (the framework is a sibling of the .app).

    std::cout << "[lethe-cef] CefInitialize..." << std::endl;
    if (!CefInitialize(args, settings, _cefApp, nullptr)) {
        std::cerr << "[lethe-cef] CefInitialize failed" << std::endl;
        std::exit(1);
    }

    // Install an AppKit command-key equivalent in addition to the CEF raw
    // key handler. This is the authoritative OS-level Cmd+T route on macOS:
    // it remains reachable when CEF's renderer/input view consumes the
    // physical key event before OnPreKeyEvent is invoked.
    [self installNativeMenu];

    // Defer browser creation until the CEF/AppKit message loop is running.
    // dispatch_async cannot execute this block until initializeCEF returns,
    // which avoids the macOS pre-run-loop browser destruction bug.
    dispatch_async(dispatch_get_main_queue(), ^{
        [self createInitialBrowser];
    });

}

- (void)applicationWillTerminate:(NSNotification*)notification {
    (void)notification;
    // Do not call ShellBootstrap::shutdown here. AppKit can deliver
    // applicationWillTerminate synchronously while CEF is unwinding a
    // browser close (including OnBeforeClose). Shutting down the policy
    // proxy/engine from that callback races CEF's own browser destruction
    // and was the source of the SIGTRAP seen in the 2026-09-02 diagnostic
    // report. main_cef.mm is the sole owner of final shutdown and runs it
    // only after CefRunMessageLoop returns.
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication*)app {
    (void)app;
    // CEF owns the message-loop shutdown. A CEF browser close can make its
    // native NSWindow disappear while OnBeforeClose is still executing; if
    // AppKit terminates NSApplication at that point it synchronously delivers
    // applicationWillTerminate from inside the CEF callback. That re-enters
    // the AppKit/CEF teardown stack and produces the SIGTRAP seen in the
    // macOS crash report. CefQuitMessageLoop() is the sole termination path;
    // main_cef.mm exits after CefShutdown completes.
    return NO;
}

@end
