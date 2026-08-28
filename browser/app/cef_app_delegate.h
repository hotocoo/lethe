// cef_app_delegate.h - NSApplication delegate for the CEF shell.
//
// One global CefApp + CefBrowserClient, one browser window. The AppDelegate
// owns the ShellBootstrap (engine, DoH pool, policy proxy) exactly like the
// WebKit shell, then hands the CefBrowserClient the context so it can route
// every navigation through the same policy pipeline.
#ifndef LETHE_BROWSER_APP_CEF_APP_DELEGATE_H
#define LETHE_BROWSER_APP_CEF_APP_DELEGATE_H

#import <Cocoa/Cocoa.h>
#include <memory>
#include <string>

#include "app/shell_bootstrap.h"
#include "app/cef_browser_client.h"

@interface LetheCefAppDelegate : NSObject <NSApplicationDelegate>
- (instancetype)initWithContext:(lethe::ShellContext*)ctx
                           app:(CefRefPtr<CefBrowserClient::App>)cefApp
                        client:(CefRefPtr<CefBrowserClient>)client
                          argc:(int)argc
                          argv:(char**)argv;
// CEF initialisation is a one-shot global; we run it in applicationDidFinishLaunching
// after the AppKit activation policy is set so the first window can win focus.
- (void)applicationDidFinishLaunching:(NSNotification*)notification;
- (void)applicationWillTerminate:(NSNotification*)notification;
- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication*)app;
@property (nonatomic, readonly) lethe::ShellContext* context;
@property (nonatomic, readonly) CefRefPtr<CefBrowserClient> client;
@end

#endif  // LETHE_BROWSER_APP_CEF_APP_DELEGATE_H
