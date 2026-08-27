// LetheShell.h - Native macOS browser shell (AppKit + WKWebView)
//
// The system WebKit renders pages (JavaScript, CSS, media); Lethe wraps it
// in real browser chrome (tabs, address bar, history, find, downloads,
// reader view) and gates EVERY navigation through lethe_core policy:
// DoH-only resolution, private-network guard on the RESOLVED address, VPN
// fail-closed routing. On macOS 14+ all engine traffic additionally rides
// the local PolicyProxyServer so subresources are enforced at transport.
//
// Honest limits: inside https the TLS session is WebKit's, not Lethe's, so
// the TLS 1.3 floor, certificate pinning and HSTS learning of lethe_core
// apply to reader-mode fetches and the proxy's own hops, not to WebKit's
// end-to-end connections. Cookies live in WebKit's data store (ephemeral
// unless --persistent), not Lethe's memory jar.

#ifndef LETHE_UI_MAC_LETHE_SHELL_H
#define LETHE_UI_MAC_LETHE_SHELL_H

#import <Cocoa/Cocoa.h>
#import <WebKit/WebKit.h>

#include <functional>
#include <memory>
#include <string>

#include "core/engine.h"
#include "network/http_client.h"
#include "network/tls_config.h"

namespace lethe {

struct ShellContext {
    Engine* engine = nullptr;
    Config cfg;
    TLSConfig tls;
    int proxyPort = 0;        // local PolicyProxyServer port (0 = none)
    std::string proxyAuthToken;  // per-launch secret WebKit presents to the proxy
    bool httpsFirst = true;   // upgrade top-level http:// to https:// first
    std::shared_ptr<SharedDohCache> dohCache;  // shared by gate, reader, proxy
    bool persistent = false;  // false = ephemeral (incognito) data store
    std::string homeUrl;      // "" = built-in new-tab page
    std::function<void()> onTerminate;  // engine/proxy shutdown
    std::string e2eScript;    // --e2e-script <file>: drive + assert, then exit
};

} // namespace lethe

@class LetheAppDelegate;
@class BrowserWindowController;

// Policy + reader fetches, off the main thread. One instance per app.
@interface LethePolicyGate : NSObject
- (instancetype)initWithContext:(const lethe::ShellContext&)ctx;
// Completion runs on the main queue: "" when allowed, else the refusal.
- (void)checkURL:(NSString*)url completion:(void (^)(NSString* reason))completion;
// Fetches through lethe_core (DoH, HSTS, pins, cookies) and hands back the
// extracted reader page HTML plus the final URL; error text on failure.
- (void)fetchReaderForURL:(NSString*)url
               completion:(void (^)(NSString* html, NSString* finalUrl,
                                    NSString* error))completion;
@end

@interface BrowserWindowController : NSWindowController
- (instancetype)initWithContext:(lethe::ShellContext*)ctx
                           gate:(LethePolicyGate*)gate
                        webView:(WKWebView*)existingWebView;
- (void)loadAddress:(NSString*)text;   // address-bar semantics (search, etc.)
- (void)loadURL:(NSURL*)url;
- (void)showNewTabPage;
- (void)focusAddressBar:(id)sender;
- (void)addressEntered:(id)sender;
- (void)toggleReader:(id)sender;
- (void)goBack:(id)sender;
- (void)goForward:(id)sender;
- (void)reloadPage:(id)sender;
- (void)stopLoading:(id)sender;
@property (nonatomic, readonly) WKWebView* webView;
@property (nonatomic, readonly) NSTextField* addressField;
@property (nonatomic, readonly) BOOL readerActive;
@property (nonatomic, readonly) BOOL busy;   // page load or reader fetch in flight
@end

// Scripted end-to-end driver (see docs/E2E.md). Runs on the main queue,
// one command at a time; exits the process with 0 (all passed) or 1.
@interface LetheAutomation : NSObject
- (instancetype)initWithDelegate:(LetheAppDelegate*)app scriptPath:(NSString*)path;
- (void)start;
@end

@interface LetheAppDelegate : NSObject <NSApplicationDelegate>
- (instancetype)initWithContext:(lethe::ShellContext*)ctx;
// Opens a tab beside \p parent (or a new window when parent is nil). When
// \p existingWebView is given (window.open / target=_blank) it becomes the
// tab's view and WebKit performs the load itself.
- (BrowserWindowController*)openTabWithURL:(NSString*)url
                                fromWindow:(NSWindow*)parent
                                   webView:(WKWebView*)existingWebView;
- (BrowserWindowController*)openWindowWithURL:(NSString*)url;
- (WKWebViewConfiguration*)webViewConfiguration;
- (void)controllerDidClose:(BrowserWindowController*)controller;
- (NSString*)securityStatusText;
- (NSArray<BrowserWindowController*>*)controllers;
// HTTPS-first: hosts the user explicitly allowed to load over plain http.
- (BOOL)isHttpAllowedForHost:(NSString*)host;
- (void)allowHttpForHost:(NSString*)host;
@property (nonatomic, readonly) LethePolicyGate* gate;
@property (nonatomic, readonly) lethe::ShellContext* context;
@end

#endif // LETHE_UI_MAC_LETHE_SHELL_H
