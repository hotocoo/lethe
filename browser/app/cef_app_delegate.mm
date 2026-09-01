// cef_app_delegate.mm - NSApplication delegate for the CEF shell.
//
// Owns the CefBrowserClient (one CefApp + CefClient + browser window). The
// CefApp subclass injects the policy proxy into Chromium's net stack via
// OnBeforeCommandLineProcessing, so the same ShellBootstrap proxy that the
// WebKit shell uses is also the only path CEF can reach the network on.
//
// Engine init order: ShellBootstrap first (engine, DoH, proxy), then
// CefInitialize, then the CefBrowserHost::CreateBrowser that opens the
// first window. applicationWillTerminate shuts the proxy + engine down
// via ShellBootstrap::shutdown, which is idempotent.

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

#include "network/policy_proxy.h"
#include "plugins/plugin_registry.h"

@implementation LetheCefAppDelegate {
    lethe::ShellContext* _ctx;
    CefRefPtr<CefBrowserClient::App> _cefApp;
    CefRefPtr<CefBrowserClient> _client;
    int _argc;
    char** _argv;
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

- (void)applicationDidFinishLaunching:(NSNotification*)notification {
    (void)notification;
    [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];

    CefMainArgs args(_argc, _argv);  // plumbed from main(); carries --disable-process-singleton etc.
    CefSettings settings;
    // macOS ignores CefMainArgs argc/argv (CEF reads the process args from
    // NSProcessInfo). Force the singleton off + sandbox off on the global
    // CefCommandLine so CefInitialize picks them up before Chromium boots.
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
        if (!global->HasSwitch("no-sandbox"))
            global->AppendSwitch("no-sandbox");
        if (!global->HasSwitch("disable-dev-shm-usage"))
            global->AppendSwitch("disable-dev-shm-usage");
        if (!global->HasSwitch("disable-gpu-sandbox"))
            global->AppendSwitch("disable-gpu-sandbox");
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
    // The CEF sandbox needs a fully-Apple-signed Helper.app that has been
    // blessed by codesign --entitlements. Without that, Chromium's
    // InitProcessSingleton path fails to find DIR_USER_DATA and aborts at
    // chrome_main_delegate.cc:1566 (NOTREACHED) before CefInitialize even
    // returns. We disable the sandbox and let our own macOS Seatbelt
    // profile (cfg.sandboxEnabled in the engine config) carry the policy
    // load. Turning the CEF sandbox back on requires a proper codesign
    // pass on the Helper, which is part of the v1.0 packaging work.
    settings.no_sandbox = true;
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

    // Open the first window. CefBrowserHost::CreateBrowser is async: the
    // browser object will arrive in CefBrowserClient::OnAfterCreated.
    CefWindowInfo windowInfo;
    CefRect rect(0, 0, 1280, 860);
    windowInfo.bounds = rect;

    CefBrowserSettings browserSettings;
    // Background colour matches the WebKit shell's new-tab page so a brief
    // white flash doesn't appear between window-show and first paint.
    // (0x00000000 = fully transparent. We use opaque white instead.)
    browserSettings.background_color = 0xFFFFFFFFu;
    // The "javascript" plugin: settings toggles reach this engine through
    // the shared preferences store (see main_cef.mm). Off breaks most
    // modern sites - that is the plugin's documented trade-off.
    if (!lethe::PluginRegistry::instance().enabled("javascript")) {
        browserSettings.javascript = STATE_DISABLED;
    }

    CefRefPtr<CefBrowserClient> client = _client;
    // Start directly on the requested URL when there is one. The first
    // main frame is then created inside the initial renderer, whose
    // browser-info handshake is answered during browser creation. The old
    // about:blank start dropped the first cross-site navigation into CEF's
    // speculative-RFH browser-info race (upstream cef#4001; the proposed
    // fix was declined) and the frame sat hung until the 15 s info timeout.
    std::string startUrl = "about:blank";
    if (!_ctx->cfg.initialUrl.empty()) startUrl = _ctx->cfg.initialUrl;
    CefRefPtr<CefBrowser> browser = CefBrowserHost::CreateBrowserSync(
        windowInfo, client, startUrl, browserSettings, nullptr, nullptr);
    if (!browser) {
        std::cerr << "[lethe-cef] CreateBrowserSync failed" << std::endl;
        CefShutdown();
        std::exit(1);
    }
    LetheCefAutomation::shared()->set_browser(browser);

    // Honour --e2e-script if present.
    NSString* scriptPath = [[NSUserDefaults standardUserDefaults]
        stringForKey:@"e2e-script"];
    if (scriptPath.length) {
        LetheCefAutomation::shared()->Start(self, [scriptPath UTF8String]);
    } else if (!_ctx->e2eScript.empty()) {
        LetheCefAutomation::shared()->Start(self, _ctx->e2eScript);
    } else if (!_ctx->cfg.initialUrl.empty()) {
        // Non-e2e launch with a URL: CreateBrowserSync already navigated.
    }

    std::cout << "[lethe-cef] CefRunMessageLoop..." << std::endl;
    CefRunMessageLoop();
    // An e2e script quit the loop: tear CEF down on this same stack. Doing
    // it in applicationWillTerminate would re-enter CefShutdown from a
    // nested run loop and crash.
    if (LetheCefAutomation::shared()->hasRun()) {
        std::cout << "[lethe-cef] CefShutdown..." << std::endl;
        CefShutdown();
        if (_ctx && _ctx->onTerminate) _ctx->onTerminate();
        std::exit(LetheCefAutomation::shared()->exitCode());
    }
}

- (void)applicationWillTerminate:(NSNotification*)notification {
    (void)notification;
    std::cout << "[lethe-cef] CefShutdown..." << std::endl;
    CefShutdown();
    if (_ctx && _ctx->onTerminate) _ctx->onTerminate();
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication*)app {
    (void)app;
    return YES;
}

@end
