// main_mac.mm - Lethe on macOS with the system WebKit (AppKit + WKWebView).
//
// Default shell for v0.1.1 (LETHE_ENGINE=webkit). The CEF (Chromium /
// Blink) shell lives in main_cef.mm. Bootstrap (engine, DoH pool, policy
// proxy) is shared: shell_bootstrap.cc.
//
// Order of operations:
//   1. Load LethePreferences (JSON in ~/Library/Application Support/Lethe/).
//      It is read here so we can apply user-defined perf knobs (worker
//      pool size) BEFORE the policy proxy starts; runtime changes to
//      these knobs require a relaunch and the Settings UI surfaces that.
//   2. ShellBootstrap::init: engine, DoH, proxy.
//   3. AppKit + CefApp + CefRunMessageLoop.

#import <Cocoa/Cocoa.h>

#include <iostream>

#include "app/shell_bootstrap.h"
#include "ui/mac/LetheShell.h"
#include "ui/mac/LethePreferences.h"

int main(int argc, char** argv) {
    // Allow multiple instances via --new-instance flag.
    // When set, we use a unique bundle identifier so macOS doesn't
    // activate the existing instance instead of launching a new one.
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--new-instance") == 0) {
            // Generate a unique suffix based on PID
            NSString* uniqueId = [NSString stringWithFormat:@"org.aletheia.lethe.%d", (int)getpid()];
            setenv("LETHE_UNIQUE_BUNDLE_ID", [uniqueId UTF8String] ?: "", 1);
            break;
        }
    }

    // Load the user's preferences before bootstrap so we can apply the
    // user-defined worker-pool size to the policy proxy at start time.
    LethePreferences* prefs = [LethePreferences shared];
    if (prefs.policyProxyWorkerThreads > 0) {
        // The bootstrap reads this env var; see shell_bootstrap.cc. We set
        // it here so a changed Settings value takes effect on next launch.
        setenv("LETHE_PROXY_WORKER_THREADS",
               [[NSString stringWithFormat:@"%ld",
                   (long)prefs.policyProxyWorkerThreads] UTF8String], 1);
    }

    lethe::ShellBootstrap boot;
    const int rc = boot.init(argc, argv, "system WebKit");
    if (rc >= 0) return rc;

    @autoreleasepool {
        NSApplication* app = [NSApplication sharedApplication];
        [app setActivationPolicy:NSApplicationActivationPolicyRegular];
        LetheAppDelegate* delegate = [[LetheAppDelegate alloc] initWithContext:&boot.ctx];
        app.delegate = delegate;
        // [NSApp terminate:] never returns from -run; the delegate's
        // applicationWillTerminate calls ctx.onTerminate (= boot.shutdown).
        [app run];
    }
    boot.shutdown();
    return 0;
}
