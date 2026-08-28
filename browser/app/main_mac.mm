// main_mac.mm - Lethe on macOS with the system WebKit (AppKit + WKWebView).
//
// Alternative shell kept for the engine comparison (LETHE_MAC_ENGINE=webkit);
// the default macOS build is the Chromium/Blink shell in main_cef.mm.
// Bootstrap (engine, DoH pool, policy proxy) is shared: shell_bootstrap.cc.

#import <Cocoa/Cocoa.h>

#include <iostream>

#include "app/shell_bootstrap.h"
#include "ui/mac/LetheShell.h"

int main(int argc, char** argv) {
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
