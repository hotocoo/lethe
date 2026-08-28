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
#include "include/wrapper/cef_helpers.h"

#include "app/cef_app_delegate.h"
#include "app/cef_browser_client.h"
#include "app/shell_bootstrap.h"

int main(int argc, char** argv) {
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
        [[NSFileManager defaultManager] createDirectoryAtPath:root
            withIntermediateDirectories:YES attributes:nil error:nil];
        setenv("CHROME_USER_DATA_DIR", [root UTF8String] ?: "", 1);
        // The shared Seatbelt profile (applied by the engine in
        // ShellBootstrap::init) denies file writes outside its allowlist.
        // Chromium needs to write its SingletonLock and per-profile caches
        // into this dir, so hand it to the profile builder.
        setenv("LETHE_SANDBOX_EXTRA_WRITE_DIRS", [root UTF8String] ?: "", 1);
    }
    // Force the singleton off in argv. The macOS Seatbelt sandbox
    // blocks the singleton lock write; OnBeforeCommandLineProcessing
    // runs too late to take effect for this check.
    newArgv.assign(argv, argv + argc);
    newArgv.push_back(const_cast<char*>("--disable-process-singleton"));
    newArgv.push_back(const_cast<char*>("--disable-default-apps"));
    newArgv.push_back(const_cast<char*>("--no-sandbox"));
    newArgv.push_back(const_cast<char*>("--disable-dev-shm-usage"));
    newArgv.push_back(const_cast<char*>("--disable-gpu-sandbox"));
    argv = newArgv.data();
    argc = static_cast<int>(newArgv.size());
    // Step 1: parse argv, start the engine, start the policy proxy. This
    // populates ShellContext with the DoH pool, the policy proxy, and the
    // per-launch auth token we need to inject into CEF's net stack.
    lethe::ShellBootstrap boot;
    const int initRc = boot.init(argc, argv, "Chromium 151.0.7922.174 (CEF 151.3.24)");
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
        NSApplication* app = [NSApplication sharedApplication];
        [app setActivationPolicy:NSApplicationActivationPolicyRegular];
        LetheCefAppDelegate* delegate = [[LetheCefAppDelegate alloc]
            initWithContext:&boot.ctx app:cefApp client:client
                       argc:argc argv:argv];
        app.delegate = delegate;
        [app run];
    }
    boot.shutdown();
    return 0;
}
