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

@implementation LetheCefAppDelegate {
    lethe::ShellContext* _ctx;
    CefRefPtr<CefBrowserClient::App> _cefApp;
    CefRefPtr<CefBrowserClient> _client;
}

@synthesize context = _ctx;
@synthesize client = _client;

- (instancetype)initWithContext:(lethe::ShellContext*)ctx
                           app:(CefRefPtr<CefBrowserClient::App>)cefApp
                        client:(CefRefPtr<CefBrowserClient>)client {
    if ((self = [super init])) {
        _ctx = ctx;
        _cefApp = cefApp;
        _client = client;
    }
    return self;
}

- (void)applicationDidFinishLaunching:(NSNotification*)notification {
    (void)notification;
    [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];

    CefMainArgs args(0, nullptr);  // CefExecuteProcess handled in main()
    CefSettings settings;
    // The CEF sandbox needs a fully-Apple-signed Helper.app that has been
    // blessed by codesign --entitlements. Without that, Chromium's
    // InitProcessSingleton path fails to find DIR_USER_DATA and aborts at
    // chrome_main_delegate.cc:1566 (NOTREACHED) before CefInitialize even
    // returns. We disable the sandbox and let our own macOS Seatbelt
    // profile (cfg.sandboxEnabled in the engine config) carry the policy
    // load. Turning the CEF sandbox back on requires a proper codesign
    // pass on the Helper, which is part of the v1.0 packaging work.
    settings.no_sandbox = true;
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
    [[NSFileManager defaultManager] createDirectoryAtPath:root
        withIntermediateDirectories:YES attributes:nil error:nil];
    // CefSettings exposes the underlying cef_settings_t fields directly;
    // root_cache_path is a raw cef_string_t (UTF-16 on macOS). Convert
    // the NSString path with cef_string_from_utf8.
    {
        const char* src = [root UTF8String] ?: "";
        cef_string_from_utf8(src, strlen(src), &settings.root_cache_path);
    }
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

    CefRefPtr<CefBrowserClient> client = _client;
    CefRefPtr<CefBrowser> browser = CefBrowserHost::CreateBrowserSync(
        windowInfo, client, "about:blank", browserSettings, nullptr, nullptr);
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
        browser->GetMainFrame()->LoadURL(_ctx->cfg.initialUrl);
    }

    std::cout << "[lethe-cef] CefRunMessageLoop..." << std::endl;
    CefRunMessageLoop();
}

- (void)applicationWillTerminate:(NSNotification*)notification {
    (void)notification;
    std::cout << "[lethe-cef] CefShutdown..." << std::endl;
    CefShutdown();
}

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication*)app {
    (void)app;
    return YES;
}

@end
