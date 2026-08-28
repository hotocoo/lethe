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


#include "browser/shell_context.h"
#include "ui/mac/LethePolicyGate.h"

@class LetheAppDelegate;
@class BrowserWindowController;



@interface BrowserWindowController : NSWindowController
- (instancetype)initWithContext:(lethe::ShellContext*)ctx
                           gate:(LethePolicyGate*)gate
                        webView:(WKWebView*)existingWebView;
// Oblivion window: its tabs share \p store (in-memory, wiped when the last
// tab closes), tracker protection is forced on, plaintext http is refused
// outright (no fallback link), the stealth low-entropy UA is used, and the
// tab group never merges with normal windows.
- (instancetype)initWithContext:(lethe::ShellContext*)ctx
                           gate:(LethePolicyGate*)gate
                        webView:(WKWebView*)existingWebView
                      dataStore:(WKWebsiteDataStore*)store
                       oblivion:(BOOL)oblivion;
@property (nonatomic, readonly) BOOL oblivion;
@property (nonatomic, readonly) WKWebsiteDataStore* dataStore;
- (void)loadAddress:(NSString*)text;   // address-bar semantics (search, etc.)
- (void)loadURL:(NSURL*)url;
- (void)showNewTabPage;
- (void)focusAddressBar:(id)sender;
- (void)addressEntered:(id)sender;
- (void)toggleReader:(id)sender;
- (void)toggleBookmark:(id)sender;
- (void)renderBookmarksPage;
- (void)renderHistoryPage;
- (void)renderPermissionsPage;
// renderStressPage: in-page torture for the renderer/main thread; used by
// the bench harness to compare Lethe and Chrome on the same workload.
- (void)renderStressPage;
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
// New Oblivion window with a fresh isolated store (File > New Oblivion Window).
- (BrowserWindowController*)openOblivionWindowWithURL:(NSString*)url;
- (WKWebViewConfiguration*)webViewConfiguration;
// Configuration bound to a specific (Oblivion) store; nil = the app store.
- (WKWebViewConfiguration*)webViewConfigurationWithStore:(WKWebsiteDataStore*)store;
// Fresh in-memory store carrying the same proxy binding as the app store.
- (WKWebsiteDataStore*)makeOblivionStore;
// Number of built-in tracker rules active in every web view (0 = off/failed).
@property (nonatomic, readonly) NSUInteger trackerRuleCount;
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
