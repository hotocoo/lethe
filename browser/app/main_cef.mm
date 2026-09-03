// main_cef.mm - Lethe on macOS with Chromium Embedded Framework (Blink).
//
// This is the v1.0 CEF shell. The bootstrap (engine, DoH pool, policy
// proxy) is shared with the WebKit shell: shell_bootstrap.cc. CEF
// initialisation goes through CefBrowserClient::App which injects the
// local policy proxy into Chromium's net stack via
// OnBeforeCommandLineProcessing, so every request CEF makes is gated by
// the same DoH / HSTS / private-network / VPN pipeline the WebKit shell
// uses.
//
// Run: ./build-cef/lethe-cef.app/Contents/MacOS/lethe-cef [url]
//      ./build-cef/lethe-cef.app/Contents/MacOS/lethe-cef --e2e-script path/to/script
//
// Pick-engine: this is the Blink engine. The WebKit shell lives in
// main_mac.mm and is the default mac build; both share the same
// ShellBootstrap and policy proxy.

#include <cstdlib>
#include <iostream>

#include "include/cef_app.h"
#include "include/cef_application_mac.h"
#include "include/cef_version.h"
#include "include/wrapper/cef_helpers.h"

#include "app/cef_app_delegate.h"
#include "app/cef_browser_client.h"
#include "app/cef_automation.h"
#include "app/shell_bootstrap.h"

// CEF's macOS Views/Chrome-style popup implementation uses CefScopedSendingEvent
// while dispatching AppKit events. CEF requires the host NSApplication to
// implement CefAppProtocol; using a plain NSApplication leaves
// -isHandlingSendEvent/-setHandlingSendEvent: undefined and a popup close
// eventually raises NSInvalidArgumentException. This is the same AppKit
// contract used by CEF's own macOS client applications.
@interface LetheCefApplication : NSApplication <CefAppProtocol>
@property(nonatomic, assign) BOOL letheHandlingSendEvent;
@end

@implementation LetheCefApplication

- (BOOL)isHandlingSendEvent {
    return self.letheHandlingSendEvent;
}

- (void)setHandlingSendEvent:(BOOL)handlingSendEvent {
    self.letheHandlingSendEvent = handlingSendEvent;
}

- (void)sendEvent:(NSEvent*)event {
    const BOOL previous = self.letheHandlingSendEvent;
    self.letheHandlingSendEvent = YES;
    [super sendEvent:event];
    self.letheHandlingSendEvent = previous;
}

@end

int main(int argc, char** argv) {
    // Chromium's native macOS sandbox and Lethe's host Seatbelt are both
    // process-scoped and cannot be nested. Prefer Chromium's dedicated
    // renderer/GPU/network sandbox for Blink; keep the older host Seatbelt
    // available as an explicit compatibility mode.
    const char* nativeSandboxEnv = std::getenv("LETHE_CEF_NATIVE_SANDBOX");
    const bool nativeSandbox = !nativeSandboxEnv ||
        std::string(nativeSandboxEnv) != "0";
    if (nativeSandbox && !std::getenv("LETHE_SANDBOX")) {
        setenv("LETHE_SANDBOX", "0", 1);
    }

    // newArgv MUST outlive boot.init and the CEF main loop. The earlier
    // scope-block died before boot.init was called and argv[3] then
    // pointed to freed memory, which made _platform_strlen SIGSEGV.
    std::vector<char*> newArgv;
    // Step 0: pin a writable user data dir BEFORE CEF/Chromium ever
    // touch path_service. The macOS Chromium build resolves
    // DIR_USER_DATA on first access; if it is not registered yet
    // (CEF starts up before CefSettings.root_cache_path is wired
    // through) chrome_main_delegate.cc:1566 NOTREACHEDs and the
    // process aborts. The path here matches what the CefSettings
    // builder uses so the helper processes all agree on the same
    // location.
    {
        NSArray* dirs = NSSearchPathForDirectoriesInDomains(
            NSApplicationSupportDirectory, NSUserDomainMask, YES);
        NSString* root = [dirs.firstObject stringByAppendingPathComponent:@"Lethe CEF"];
        // Keep the profile inside Lethe's Seatbelt write allowlist. An
        // arbitrary environment-provided path would otherwise become a
        // sandbox escape hatch: the CEF bootstrap would explicitly grant
        // itself write access to whatever directory the launcher supplied.
        // Multiple instances use Chromium's normal per-process/profile
        // coordination rather than widening the host security boundary.
        [[NSFileManager defaultManager] createDirectoryAtPath:root
            withIntermediateDirectories:YES attributes:nil error:nil];
        setenv("CHROME_USER_DATA_DIR", [root UTF8String] ?: "", 1);
        // Every feature is a plugin and the settings toggles live in ONE
        // store: the preferences.json the WebKit shell's Settings window
        // (and lethe://plugins) writes. Point the shared bootstrap at it so
        // the Blink engine honors the same user choices. It stays optional:
        // a CEF-only install runs on registry defaults.
        NSString* prefs = [NSHomeDirectory()
            stringByAppendingPathComponent:
                @"Library/Application Support/Lethe/preferences.json"];
        if ([[NSFileManager defaultManager] fileExistsAtPath:prefs]) {
            setenv("LETHE_PREFS_FILE", [prefs UTF8String] ?: "", 1);
        }
    }
    // Force the singleton off in argv. The macOS Seatbelt sandbox
    // blocks the singleton lock write; OnBeforeCommandLineProcessing
    // runs too late to take effect for this check.
    newArgv.assign(argv, argv + argc);
    newArgv.push_back(const_cast<char*>("--disable-process-singleton"));
    newArgv.push_back(const_cast<char*>("--disable-default-apps"));
    newArgv.push_back(const_cast<char*>("--disable-dev-shm-usage"));
    argv = newArgv.data();
    argc = static_cast<int>(newArgv.size());
    // Step 1: parse argv, start the engine, start the policy proxy. This
    // populates ShellContext with the DoH pool, the policy proxy, and the
    // per-launch auth token we need to inject into CEF's net stack.
    lethe::ShellBootstrap boot;
    // Engine banner from the dist itself - stays honest across upgrades.
    const int initRc = boot.init(argc, argv, "CEF " CEF_VERSION);
    if (initRc >= 0) return initRc;

    // Step 2: build the CefApp + CefBrowserClient. CefExecuteProcess only
    // does work for non-browser processes; in the browser process it
    // returns -1 and we proceed.
    CefMainArgs cefArgs(argc, argv);
    CefRefPtr<CefBrowserClient::App> cefApp = new CefBrowserClient::App();
    cefApp->SetShellContext(&boot.ctx);
    {
        const int rc = CefExecuteProcess(cefArgs, cefApp, nullptr);
        if (rc >= 0) {
            boot.shutdown();
            return rc;
        }
    }
    CefRefPtr<CefBrowserClient> client = new CefBrowserClient();
    client->SetShellContext(&boot.ctx);

    // Step 3: run the AppKit / CEF event loop. CefInitialize happens in
    // applicationDidFinishLaunching after NSApplication is set up. The
    // delegate shuts CEF + the bootstrap down on terminate.
    @autoreleasepool {
        // CEF's macOS event bridge requires a CefAppProtocol NSApplication;
        // instantiate the subclass before CEFInitialize creates any Views
        // windows.
        NSApplication* app = [LetheCefApplication sharedApplication];
        [app setActivationPolicy:NSApplicationActivationPolicyRegular];
        LetheCefAppDelegate* delegate = [[LetheCefAppDelegate alloc]
            initWithContext:&boot.ctx app:cefApp client:client
                       argc:argc argv:argv];
        app.delegate = delegate;
        // CEF's macOS message loop owns the NSApplication event loop. Do not
        // call -[NSApplication run] and then nest CefRunMessageLoop from the
        // application delegate; that leaves CEF shutdown inside an AppKit
        // launch-notification stack and can retain browser-context observers.
        [delegate initializeCEF];
        std::cout << "[lethe-cef] CefRunMessageLoop..." << std::endl;
        CefRunMessageLoop();
        std::cout << "[lethe-cef] CefShutdown..." << std::endl;
        CefShutdown();
        const int e2eRc = LetheCefAutomation::shared()->exitCode();
        boot.shutdown();
        return e2eRc;
    }
    boot.shutdown();
    return 0;
}
