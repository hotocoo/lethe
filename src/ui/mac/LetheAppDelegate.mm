// LetheAppDelegate.mm - application lifecycle, menu bar, tab/window factory

#import "ui/mac/LetheShell.h"
#import "ui/mac/LetheBookmarks.h"
#import "ui/mac/LetheHistory.h"
#import "ui/mac/LethePreferences.h"
#import "ui/mac/LetheSession.h"
#import "ui/mac/LethePermissions.h"
#import <Network/Network.h>
#import <objc/runtime.h>

#include <iostream>

#include "browser/url_input.h"
#include "security/tracker_blocklist.h"

@interface LetheAppDelegate () {
    lethe::ShellContext* ctx_;
    LethePolicyGate* gate_;
    NSMutableArray<BrowserWindowController*>* controllers_;
    WKWebsiteDataStore* dataStore_;
    NSMutableSet<NSString*>* httpAllowedHosts_;
    WKUserContentController* userContent_;   // shared: one rule list, every tab
    NSUInteger trackerRuleCount_;
    BOOL proxyApplied_;
    LetheAutomation* automation_;
}
@end

@implementation LetheAppDelegate

@synthesize gate = gate_;

- (instancetype)initWithContext:(lethe::ShellContext*)ctx {
    if ((self = [super init])) {
        ctx_ = ctx;
        gate_ = [[LethePolicyGate alloc] initWithContext:*ctx];
        controllers_ = [NSMutableArray array];
        proxyApplied_ = NO;
    }
    return self;
}

- (lethe::ShellContext*)context { return ctx_; }

#pragma mark - Lifecycle

- (NSUInteger)trackerRuleCount { return trackerRuleCount_; }

- (WKUserContentController*)userContentController {
    if (!userContent_) userContent_ = [[WKUserContentController alloc] init];
    return userContent_;
}

// Compile (or fetch from WebKit's on-disk store) the built-in tracker rules
// and attach them to the shared user-content controller BEFORE the first
// web view exists, so even the very first navigation is protected. The
// store is keyed by a hash of the list: editing trackers.txt recompiles.
- (void)prepareTrackerProtection:(void (^)(void))done {
    if (!ctx_->trackerBlocking) {
        std::cout << "[lethe] tracker protection: OFF (--no-tracker-block)" << std::endl;
        done();
        return;
    }
    const lethe::TrackerBlocklist& list = lethe::builtinTrackerBlocklist();
    const NSUInteger count = list.domains.size() + list.pathPatterns.size();
    NSString* ident = @(lethe::trackerRulesIdentifier(list).c_str());
    WKContentRuleListStore* store = [WKContentRuleListStore defaultStore];
    __weak LetheAppDelegate* weakSelf = self;
    void (^install)(WKContentRuleList*, NSString*) = ^(WKContentRuleList* rules, NSString* how) {
        LetheAppDelegate* self = weakSelf;
        if (!self) return;
        [[self userContentController] addContentRuleList:rules];
        self->trackerRuleCount_ = count;
        std::cout << "[lethe] tracker protection: " << count << " third-party rules ("
                  << how.UTF8String << ")" << std::endl;
    };
    [store lookUpContentRuleListForIdentifier:ident
                            completionHandler:^(WKContentRuleList* found, NSError* lookupErr) {
        (void)lookupErr;
        if (found) { install(found, @"cached"); done(); return; }
        NSString* json = @(lethe::trackerContentRulesJson(list).c_str());
        const NSTimeInterval t0 = [NSDate timeIntervalSinceReferenceDate];
        [store compileContentRuleListForIdentifier:ident
                            encodedContentRuleList:json
                                 completionHandler:^(WKContentRuleList* compiled, NSError* err) {
            if (compiled) {
                install(compiled, [NSString stringWithFormat:@"compiled in %.0f ms",
                                   ([NSDate timeIntervalSinceReferenceDate] - t0) * 1000.0]);
            } else {
                std::cerr << "[lethe] tracker protection: rule compile failed: "
                          << (err.localizedDescription.UTF8String ?: "unknown") << std::endl;
            }
            done();
        }];
    }];
}

- (void)applicationDidFinishLaunching:(NSNotification*)note {
    (void)note;
    // A binary launched from the command line (benchmarks, e2e) can start
    // without a regular activation policy; force it so the window can win
    // focus and WebKit keeps requestAnimationFrame running.
    [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
    [self buildMenuBar];
    [self prepareTrackerProtection:^{ [self openInitialWindow]; }];
}

- (void)openInitialWindow {
    // Restore last session (unless an explicit initial URL or e2e script was given).
    NSArray<NSDictionary*>* saved = @[];
    if (ctx_->cfg.initialUrl.empty() && ctx_->e2eScript.empty()) {
        saved = [[LetheSession shared] load];
    }
    NSString* initial = saved.count ? saved.firstObject[@"url"]
        : (ctx_->cfg.initialUrl.empty() ? nil : @(ctx_->cfg.initialUrl.c_str()));
    BrowserWindowController* c = [self openWindowWithURL:initial];
    // Chrome-style: the tab strip is always there, even with one tab.
    if (c.window.tabGroup && !c.window.tabGroup.tabBarVisible) {
        [c.window toggleTabBar:nil];
    }
    [NSApp activateIgnoringOtherApps:YES];
    if (!ctx_->e2eScript.empty()) {
        LetheAutomation* auto_ = [[LetheAutomation alloc]
            initWithDelegate:self scriptPath:@(ctx_->e2eScript.c_str())];
        automation_ = auto_;
        [auto_ start];
    }
}

- (NSArray<BrowserWindowController*>*)controllers { return [controllers_ copy]; }

- (BOOL)applicationShouldTerminateAfterLastWindowClosed:(NSApplication*)app {
    (void)app;
    return NO;
}

- (BOOL)applicationShouldHandleReopen:(NSApplication*)app hasVisibleWindows:(BOOL)visible {
    (void)app;
    if (!visible) [self openWindowWithURL:nil];
    return YES;
}

- (void)application:(NSApplication*)app openURLs:(NSArray<NSURL*>*)urls {
    (void)app;
    for (NSURL* u in urls) {
        NSWindow* key = [NSApp keyWindow];
        [self openTabWithURL:u.absoluteString fromWindow:key webView:nil];
    }
}

- (void)applicationWillTerminate:(NSNotification*)note {
    (void)note;
    // Persist the active tab URL of every visible window for restore-on-launch.
    NSMutableArray<NSDictionary*>* snap = [NSMutableArray array];
    for (BrowserWindowController* c in [controllers_ copy]) {
        NSString* url = c.webView.URL.absoluteString;
        if (url.length && [url hasPrefix:@"http"]) {
            [snap addObject:@{ @"url": url, @"title": c.webView.title ?: url }];
        }
    }
    [[LetheSession shared] saveWindows:snap];
    for (BrowserWindowController* c in [controllers_ copy]) {
        [c.window close];
    }
    if (ctx_->onTerminate) ctx_->onTerminate();
}

#pragma mark - WebKit configuration

- (WKWebsiteDataStore*)dataStore {
    if (!dataStore_) {
        dataStore_ = ctx_->persistent
            ? [WKWebsiteDataStore defaultDataStore]
            : [WKWebsiteDataStore nonPersistentDataStore];
        std::cout << "[lethe] site data store: "
                  << (ctx_->persistent ? "persistent" : "ephemeral (incognito)")
                  << std::endl;
    }
    if (!proxyApplied_ && ctx_->proxyPort > 0) {
        proxyApplied_ = YES;
        if ([self bindStoreToProxy:dataStore_]) {
            std::cout << "[lethe] WebKit traffic routed through policy proxy "
                         "127.0.0.1:" << ctx_->proxyPort << " (subresource enforcement on)"
                      << std::endl;
        } else {
            std::cout << "[lethe] macOS < 14: no per-datastore proxy API; "
                         "navigation gate only" << std::endl;
        }
    }
    return dataStore_;
}

- (BOOL)bindStoreToProxy:(WKWebsiteDataStore*)store {
    if (ctx_->proxyPort <= 0) return NO;
    if (@available(macOS 14.0, *)) {
        const std::string port = std::to_string(ctx_->proxyPort);
        nw_endpoint_t ep = nw_endpoint_create_host("127.0.0.1", port.c_str());
        nw_proxy_config_t pc = nw_proxy_config_create_http_connect(ep, nil);
        if (!ctx_->proxyAuthToken.empty()) {
            // The proxy refuses (407) anything without this per-launch
            // secret, so other local processes cannot ride Lethe's
            // policy identity or VPN tunnel.
            nw_proxy_config_set_username_and_password(
                pc, "lethe", ctx_->proxyAuthToken.c_str());
        }
        store.proxyConfigurations = @[pc];
        return YES;
    }
    return NO;
}

- (WKWebsiteDataStore*)makeOblivionStore {
    WKWebsiteDataStore* store = [WKWebsiteDataStore nonPersistentDataStore];
    [self bindStoreToProxy:store];
    return store;
}

- (WKWebViewConfiguration*)webViewConfiguration {
    return [self webViewConfigurationWithStore:nil];
}

- (WKWebViewConfiguration*)webViewConfigurationWithStore:(WKWebsiteDataStore*)store {
    WKWebViewConfiguration* c = [[WKWebViewConfiguration alloc] init];
    c.websiteDataStore = store ?: [self dataStore];
    c.userContentController = [self userContentController];
    c.defaultWebpagePreferences.allowsContentJavaScript = YES;
    // Popup blocking like Chrome: window.open needs a user gesture.
    c.preferences.javaScriptCanOpenWindowsAutomatically = NO;
    c.preferences.fraudulentWebsiteWarningEnabled = YES;
    if (@available(macOS 12.3, *)) {
        c.preferences.elementFullscreenEnabled = YES;
    }
    // "Inspect Element" in the context menu (Web Inspector).
    [c.preferences setValue:@YES forKey:@"developerExtrasEnabled"];
    // Try to raise WKWebView's animation rate to match the display. On
    // 144 Hz panels WKWebView caps rAF at ~72 Hz without these hints.
    return c;
}

#pragma mark - Windows and tabs

- (BrowserWindowController*)makeController:(WKWebView*)existing {
    return [self makeController:existing store:nil oblivion:NO];
}

- (BrowserWindowController*)makeController:(WKWebView*)existing
                                      store:(WKWebsiteDataStore*)store
                                   oblivion:(BOOL)oblivion {
    BrowserWindowController* c =
        [[BrowserWindowController alloc] initWithContext:ctx_ gate:gate_ webView:existing
                                               dataStore:store oblivion:oblivion];
    [controllers_ addObject:c];
    return c;
}

- (BrowserWindowController*)openWindowWithURL:(NSString*)url {
    BrowserWindowController* c = [self makeController:nil];
    // Keep the new window standalone even when the system prefers tabs.
    c.window.tabbingMode = NSWindowTabbingModeDisallowed;
    [c showWindow:nil];
    [c.window makeKeyAndOrderFront:nil];
    c.window.tabbingMode = NSWindowTabbingModePreferred;
    if (url.length) [c loadAddress:url]; else [c showNewTabPage];
    return c;
}

- (BrowserWindowController*)openOblivionWindowWithURL:(NSString*)url {
    BrowserWindowController* c = [self makeController:nil store:[self makeOblivionStore] oblivion:YES];
    c.window.tabbingMode = NSWindowTabbingModeDisallowed;
    [c showWindow:nil];
    [c.window makeKeyAndOrderFront:nil];
    c.window.tabbingMode = NSWindowTabbingModePreferred;
    if (url.length) [c loadAddress:url]; else [c showNewTabPage];
    std::cout << "[lethe] oblivion window opened (isolated in-memory store, https-only, "
                 "tracker protection forced, stealth UA)" << std::endl;
    return c;
}

- (BrowserWindowController*)openTabWithURL:(NSString*)url
                                fromWindow:(NSWindow*)parent
                                   webView:(WKWebView*)existing {
    // A tab born from an Oblivion window stays in Oblivion: same isolated
    // store, same rules. window.open already inherits the configuration.
    BrowserWindowController* parentCtl = nil;
    if ([parent.windowController isKindOfClass:[BrowserWindowController class]])
        parentCtl = (BrowserWindowController*)parent.windowController;
    const BOOL oblivion = parentCtl.oblivion;
    WKWebsiteDataStore* store = oblivion ? parentCtl.dataStore : nil;
    if (!parent) {
        BrowserWindowController* c = [self makeController:existing];
        [c showWindow:nil];
        [c.window makeKeyAndOrderFront:nil];
        if (!existing) { if (url.length) [c loadAddress:url]; else [c showNewTabPage]; }
        return c;
    }
    BrowserWindowController* c = [self makeController:existing store:store oblivion:oblivion];
    [parent addTabbedWindow:c.window ordered:NSWindowAbove];
    [c.window makeKeyAndOrderFront:nil];
    if (!existing) {
        if (url.length) [c loadAddress:url]; else [c showNewTabPage];
    }
    return c;
}

- (void)controllerDidClose:(BrowserWindowController*)controller {
    [controllers_ removeObject:controller];
}

// File > New Tab with no browser window open (responder chain ends here).
- (void)newWindowForTab:(id)sender {
    (void)sender;
    [self openWindowWithURL:nil];
}

- (void)newWindow:(id)sender {
    (void)sender;
    [self openWindowWithURL:nil];
}

- (void)newOblivionWindow:(id)sender {
    (void)sender;
    [self openOblivionWindowWithURL:nil];
}

#pragma mark - Status / privacy actions

- (BOOL)isHttpAllowedForHost:(NSString*)host {
    return host.length && [httpAllowedHosts_ containsObject:host.lowercaseString];
}

- (void)allowHttpForHost:(NSString*)host {
    if (!httpAllowedHosts_) httpAllowedHosts_ = [NSMutableSet set];
    if (host.length) [httpAllowedHosts_ addObject:host.lowercaseString];
}

- (NSString*)securityStatusText {
    const lethe::Config& cfg = ctx_->cfg;
    NSMutableString* s = [NSMutableString string];
    [s appendFormat:@"Lethe v%s\n\n", LETHE_VERSION];
    [s appendFormat:@"Tracker protection: %@\n", trackerRuleCount_
        ? [NSString stringWithFormat:@"on (%lu third-party rules)", (unsigned long)trackerRuleCount_]
        : (ctx_->trackerBlocking ? @"unavailable (rule compile failed)" : @"OFF")];
    NSUInteger oblivionWindows = 0;
    for (BrowserWindowController* c in controllers_) if (c.oblivion) oblivionWindows++;
    [s appendFormat:@"Oblivion windows open: %lu (isolated in-memory store wiped on close, "
                     "https-only, tracker protection forced, stealth UA; ⌘⇧N)\n",
        (unsigned long)oblivionWindows];
    [s appendFormat:@"HTTPS-first: %@\n", ctx_->httpsFirst
        ? [NSString stringWithFormat:@"on (%lu host%@ allowed plain http this session)",
           (unsigned long)httpAllowedHosts_.count, httpAllowedHosts_.count == 1 ? @"" : @"s"]
        : @"OFF"];
    [s appendFormat:@"Secure DNS (DoH): %@\n",
        cfg.dnsProvider.empty() ? @"OFF" : @(cfg.dnsProvider.c_str())];
    [s appendFormat:@"Private-network isolation: %@\n",
        cfg.isolatePrivateNetworks ? @"on (SSRF guard)" : @"OFF"];
    if (ctx_->proxyPort > 0) {
        if (@available(macOS 14.0, *)) {
            [s appendFormat:@"Transport enforcement: policy proxy 127.0.0.1:%d "
                             "(every WebKit request%@)\n", ctx_->proxyPort,
                             ctx_->proxyAuthToken.empty() ? @"" : @", per-launch auth token"];
        } else {
            [s appendString:@"Transport enforcement: navigation gate only "
                             "(macOS 14+ needed for the per-request proxy)\n"];
        }
    } else {
        [s appendString:@"Transport enforcement: navigation gate only\n"];
    }
    const bool vpn = ctx_->engine && ctx_->engine->isVpnConnected();
    [s appendFormat:@"Built-in VPN: %@\n",
        vpn ? @"connected" : (cfg.vpnConfig.endpointHost.empty()
            ? @"not configured" : @"disconnected")];
    [s appendFormat:@"Site data: %@\n",
        ctx_->persistent ? @"persistent" : @"ephemeral (cleared on quit)"];
    [s appendFormat:@"Process sandbox: %@\n",
        cfg.sandboxEnabled ? @"Seatbelt (writes: temp, Downloads, own caches)" : @"OFF"];
    [s appendFormat:@"User agent: %@\n",
        cfg.userAgentMode == "stealth" ? @"stealth (fixed profile)" : @"WebKit default"];
    [s appendString:@"\nInside https, TLS is WebKit's own (system trust); "
                     "Lethe's TLS 1.3 floor, pins and HSTS cover reader-mode "
                     "and proxy hops."];
    return s;
}

- (void)showSecurityStatus:(id)sender {
    (void)sender;
    NSAlert* a = [[NSAlert alloc] init];
    a.messageText = @"Security status";
    a.informativeText = [self securityStatusText];
    [a addButtonWithTitle:@"OK"];
    [a runModal];
}

- (void)toggleBookmark:(id)sender {
    (void)sender;
    BrowserWindowController* c = (BrowserWindowController*)[NSApp keyWindow].windowController;
    if (![c isKindOfClass:[BrowserWindowController class]]) {
        for (BrowserWindowController* cw in controllers_) {
            if (cw.window.isVisible) { c = cw; break; }
        }
    }
    if (!c) { NSBeep(); return; }
    [c toggleBookmark:nil];
}

- (void)showBookmarks:(id)sender {
    (void)sender;
    BrowserWindowController* c = [self openTabWithURL:@"lethe://bookmarks"
                                          fromWindow:[NSApp keyWindow] webView:nil];
    if (!c) return;
    __weak BrowserWindowController* weakC = c;
    // Give the navigation a moment to land, then inject the rendered list.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 250 * NSEC_PER_MSEC),
                   dispatch_get_main_queue(), ^{
        BrowserWindowController* strong = weakC;
        if (!strong) return;
        [strong renderBookmarksPage];
    });
}

- (void)clearBookmarks:(id)sender {
    (void)sender;
    NSAlert* a = [[NSAlert alloc] init];
    a.messageText = @"Clear all bookmarks?";
    a.informativeText = @"This removes every saved bookmark.";
    [a addButtonWithTitle:@"Cancel"];
    [a addButtonWithTitle:@"Clear"];
    if ([a runModal] != NSAlertSecondButtonReturn) return;
    for (LetheBookmark* b in [[LetheBookmarks shared] all]) {
        [[LetheBookmarks shared] removeURL:b.url];
    }
}

- (void)showHistory:(id)sender {
    (void)sender;
    BrowserWindowController* c = [self openTabWithURL:@"lethe://history"
                                          fromWindow:[NSApp keyWindow] webView:nil];
    if (!c) return;
    __weak BrowserWindowController* weakC = c;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 250 * NSEC_PER_MSEC),
                   dispatch_get_main_queue(), ^{
        BrowserWindowController* strong = weakC;
        if (strong) [strong renderHistoryPage];
    });
}

- (void)clearHistory:(id)sender {
    (void)sender;
    NSAlert* a = [[NSAlert alloc] init];
    a.messageText = @"Clear browsing history?";
    a.informativeText = @"This removes all recorded visits.";
    [a addButtonWithTitle:@"Cancel"];
    [a addButtonWithTitle:@"Clear"];
    if ([a runModal] != NSAlertSecondButtonReturn) return;
    [[LetheHistory shared] clear];
}

- (void)showPermissions:(id)sender {
    (void)sender;
    BrowserWindowController* c = [self openTabWithURL:@"lethe://permissions"
                                          fromWindow:[NSApp keyWindow] webView:nil];
    if (!c) return;
    __weak BrowserWindowController* weakC = c;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 250 * NSEC_PER_MSEC),
                   dispatch_get_main_queue(), ^{
        BrowserWindowController* strong = weakC;
        if (strong) [strong renderPermissionsPage];
    });
}

- (void)clearAllPermissions:(id)sender {
    (void)sender;
    NSAlert* a = [[NSAlert alloc] init];
    a.messageText = @"Clear all site permissions?";
    a.informativeText = @"Every site's allow/deny choice will be forgotten. Sites will be asked again.";
    [a addButtonWithTitle:@"Cancel"];
    [a addButtonWithTitle:@"Clear"];
    if ([a runModal] != NSAlertSecondButtonReturn) return;
    [[LethePermissions shared] clearAll];
}

- (void)toggleVpn:(id)sender {
    (void)sender;
    lethe::Engine* engine = ctx_->engine;
    if (!engine) return;
    if (engine->isVpnConnected()) {
        engine->disableVpn();
        return;
    }
    if (ctx_->cfg.vpnConfig.endpointHost.empty()) {
        NSAlert* a = [[NSAlert alloc] init];
        a.messageText = @"No VPN endpoint configured";
        a.informativeText = @"Lethe's built-in WireGuard-style tunnel needs an "
            "endpoint and keys in Config.vpnConfig (see README). Without one, "
            "browsing stays direct; DoH and the private-network guard still apply.";
        [a runModal];
        return;
    }
    if (!engine->enableVpn(ctx_->cfg.vpnConfig)) {
        NSAlert* a = [[NSAlert alloc] init];
        a.messageText = @"VPN handshake failed";
        a.informativeText = @"The endpoint did not complete the handshake. "
            "Traffic is NOT routed through the tunnel.";
        [a runModal];
    }
}

- (void)clearBrowsingData:(id)sender {
    (void)sender;
    WKWebsiteDataStore* store = [self dataStore];
    [store removeDataOfTypes:[WKWebsiteDataStore allWebsiteDataTypes]
               modifiedSince:[NSDate distantPast]
           completionHandler:^{
        std::cout << "[lethe] site data cleared" << std::endl;
    }];
}

- (void)openHelp:(id)sender {
    (void)sender;
    [self openTabWithURL:@"https://github.com/hotocoo/lethe#readme"
              fromWindow:[NSApp keyWindow] webView:nil];
}

- (BOOL)validateMenuItem:(NSMenuItem*)item {
    if (item.action == @selector(toggleVpn:)) {
        const bool on = ctx_->engine && ctx_->engine->isVpnConnected();
        item.title = on ? @"Disconnect VPN" : @"Connect VPN";
    }
    return YES;
}

#pragma mark - Menu bar

static NSMenuItem* addItem(NSMenu* menu, NSString* title, SEL action,
                           NSString* key, NSEventModifierFlags mods) {
    NSMenuItem* it = [[NSMenuItem alloc] initWithTitle:title action:action
                                         keyEquivalent:key];
    it.keyEquivalentModifierMask = mods;
    [menu addItem:it];
    return it;
}

static NSMenu* addSubmenu(NSMenu* bar, NSString* title) {
    NSMenuItem* holder = [[NSMenuItem alloc] initWithTitle:title action:nil
                                             keyEquivalent:@""];
    NSMenu* m = [[NSMenu alloc] initWithTitle:title];
    holder.submenu = m;
    [bar addItem:holder];
    return m;
}


- (void)showPreferences:(id)sender {
    (void)sender;
    LethePreferences* prefs = [LethePreferences shared];
    NSWindow* win = [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 460, 280)
                                                styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable
                                                  backing:NSBackingStoreBuffered defer:NO];
    win.title = @"Preferences";
    NSView* v = win.contentView;
    int y = 240;
    NSDictionary* labels = @{
        @"trackerBlocking": @"Block third-party trackers (built-in curated list)",
        @"httpsFirst": @"Upgrade http:// → https:// first",
        @"persistentCookies": @"Keep cookies/site data between launches",
        @"stealthUA": @"Stealth user agent (fixed low-entropy profile)",
    };
    NSArray* keys = @[@"trackerBlocking", @"httpsFirst", @"persistentCookies", @"stealthUA"];
    for (NSString* key in keys) {
        NSButton* cb = [NSButton buttonWithTitle:labels[key] target:self action:@selector(prefsToggle:)];
        cb.buttonType = NSSwitchButton;
        cb.frame = NSMakeRect(20, y, 420, 22);
        if ([key isEqualToString:@"trackerBlocking"]) cb.state = prefs.trackerBlocking ? NSControlStateValueOn : NSControlStateValueOff;
        if ([key isEqualToString:@"httpsFirst"]) cb.state = prefs.httpsFirst ? NSControlStateValueOn : NSControlStateValueOff;
        if ([key isEqualToString:@"persistentCookies"]) cb.state = prefs.persistentCookies ? NSControlStateValueOn : NSControlStateValueOff;
        if ([key isEqualToString:@"stealthUA"]) cb.state = prefs.stealthUA ? NSControlStateValueOn : NSControlStateValueOff;
        cb.tag = [keys indexOfObject:key];
        [v addSubview:cb];
        y -= 36;
    }
    NSTextField* note = [NSTextField labelWithString:@"Changes apply to new windows and pages. Some require restarting Lethe to take effect."];
    note.font = [NSFont systemFontOfSize:11];
    note.textColor = [NSColor secondaryLabelColor];
    note.frame = NSMakeRect(20, 20, 420, 40);
    note.lineBreakMode = NSLineBreakByWordWrapping;
    note.maximumNumberOfLines = 2;
    [v addSubview:note];
    [win center];
    [win makeKeyAndOrderFront:nil];
}

- (void)prefsToggle:(NSButton*)sender {
    LethePreferences* prefs = [LethePreferences shared];
    switch (sender.tag) {
        case 0: prefs.trackerBlocking = (sender.state == NSControlStateValueOn); break;
        case 1: prefs.httpsFirst = (sender.state == NSControlStateValueOn); break;
        case 2: prefs.persistentCookies = (sender.state == NSControlStateValueOn); break;
        case 3: prefs.stealthUA = (sender.state == NSControlStateValueOn); break;
    }
    [prefs save];
}
- (void)buildMenuBar {
    NSMenu* bar = [[NSMenu alloc] init];
    const NSEventModifierFlags cmd = NSEventModifierFlagCommand;
    const NSEventModifierFlags cmdShift = cmd | NSEventModifierFlagShift;
    const NSEventModifierFlags cmdCtrl = cmd | NSEventModifierFlagControl;
    const NSEventModifierFlags cmdAlt = cmd | NSEventModifierFlagOption;
    const NSEventModifierFlags ctrl = NSEventModifierFlagControl;

    NSMenu* app = addSubmenu(bar, @"Lethe");
    addItem(app, @"About Lethe", @selector(orderFrontStandardAboutPanel:), @"", 0);
    [app addItem:[NSMenuItem separatorItem]];
    addItem(app, @"Security Status…", @selector(showSecurityStatus:), @"i", cmdShift);
    addItem(app, @"Preferences…", @selector(showPreferences:), @",", cmd);
    [app addItem:[NSMenuItem separatorItem]];
    [app addItem:[NSMenuItem separatorItem]];
    addItem(app, @"Hide Lethe", @selector(hide:), @"h", cmd);
    addItem(app, @"Hide Others", @selector(hideOtherApplications:), @"h",
            cmd | NSEventModifierFlagOption);
    addItem(app, @"Show All", @selector(unhideAllApplications:), @"", 0);
    [app addItem:[NSMenuItem separatorItem]];
    addItem(app, @"Quit Lethe", @selector(terminate:), @"q", cmd);

    NSMenu* file = addSubmenu(bar, @"File");
    addItem(file, @"New Tab", @selector(newWindowForTab:), @"t", cmd);
    addItem(file, @"New Window", @selector(newWindow:), @"n", cmd);
    addItem(file, @"New Oblivion Window", @selector(newOblivionWindow:), @"n", cmdShift);
    addItem(file, @"Open Location…", @selector(focusAddressBar:), @"l", cmd);
    [file addItem:[NSMenuItem separatorItem]];
    addItem(file, @"Close Tab", @selector(performClose:), @"w", cmd);
    addItem(file, @"Close Window", @selector(closeWholeWindow:), @"w", cmdShift);
    [file addItem:[NSMenuItem separatorItem]];
    addItem(file, @"Downloads", @selector(openDownloadsFolder:), @"j", cmdShift);
    addItem(file, @"Reveal Downloads Folder", @selector(revealDownloads:), @"", 0);
    [file addItem:[NSMenuItem separatorItem]];
    addItem(file, @"Print…", @selector(printPage:), @"p", cmd);

    NSMenu* bookmarks = addSubmenu(bar, @"Bookmarks");
    addItem(bookmarks, @"Toggle Bookmark", @selector(toggleBookmark:), @"d", cmd);
    addItem(bookmarks, @"Show All Bookmarks…", @selector(showBookmarks:), @"", 0);
    [bookmarks addItem:[NSMenuItem separatorItem]];
    addItem(bookmarks, @"Clear Bookmarks", @selector(clearBookmarks:), @"", 0);

    NSMenu* edit = addSubmenu(bar, @"Edit");
    addItem(edit, @"Undo", @selector(undo:), @"z", cmd);
    addItem(edit, @"Redo", @selector(redo:), @"z", cmdShift);
    [edit addItem:[NSMenuItem separatorItem]];
    addItem(edit, @"Cut", @selector(cut:), @"x", cmd);
    addItem(edit, @"Copy", @selector(copy:), @"c", cmd);
    addItem(edit, @"Paste", @selector(paste:), @"v", cmd);
    addItem(edit, @"Select All", @selector(selectAll:), @"a", cmd);
    [edit addItem:[NSMenuItem separatorItem]];
    addItem(edit, @"Find…", @selector(showFindBar:), @"f", cmd);
    addItem(edit, @"Find Next", @selector(findNext:), @"g", cmd);
    addItem(edit, @"Find Previous", @selector(findPrevious:), @"g", cmdShift);

    NSMenu* view = addSubmenu(bar, @"View");
    addItem(view, @"Reload Page", @selector(reloadPage:), @"r", cmd);
    addItem(view, @"Stop", @selector(stopLoading:), @".", cmd);
    [view addItem:[NSMenuItem separatorItem]];
    addItem(view, @"Reader View", @selector(toggleReader:), @"r", cmdShift);
    [view addItem:[NSMenuItem separatorItem]];
    addItem(view, @"Show Web Inspector", @selector(showWebInspector:), @"i", cmdAlt);
    [view addItem:[NSMenuItem separatorItem]];
    addItem(view, @"Actual Size", @selector(zoomActual:), @"0", cmd);
    addItem(view, @"Zoom In", @selector(zoomIn:), @"=", cmd);
    addItem(view, @"Zoom Out", @selector(zoomOut:), @"-", cmd);
    [view addItem:[NSMenuItem separatorItem]];
    addItem(view, @"Enter Full Screen", @selector(toggleFullScreen:), @"f", cmdCtrl);

    NSMenu* history = addSubmenu(bar, @"History");
    addItem(history, @"Back", @selector(goBack:), @"[", cmd);
    addItem(history, @"Forward", @selector(goForward:), @"]", cmd);
    [history addItem:[NSMenuItem separatorItem]];
    addItem(history, @"Home", @selector(goHome:), @"h", cmdShift);
    [history addItem:[NSMenuItem separatorItem]];
    addItem(history, @"Show All History…", @selector(showHistory:), @"y", cmd);
    addItem(history, @"Clear History", @selector(clearHistory:), @"", 0);

    NSMenu* privacy = addSubmenu(bar, @"Privacy");
    addItem(privacy, @"Connect VPN", @selector(toggleVpn:), @"", 0);
    addItem(privacy, @"Clear Browsing Data", @selector(clearBrowsingData:), @"", 0);
    [privacy addItem:[NSMenuItem separatorItem]];
    addItem(privacy, @"Site Permissions…", @selector(showPermissions:), @"", 0);
    addItem(privacy, @"Clear All Permissions", @selector(clearAllPermissions:), @"", 0);
    [privacy addItem:[NSMenuItem separatorItem]];
    addItem(privacy, @"Security Status…", @selector(showSecurityStatus:), @"", 0);

    NSMenu* window = addSubmenu(bar, @"Window");
    addItem(window, @"Minimize", @selector(performMiniaturize:), @"m", cmd);
    addItem(window, @"Zoom", @selector(performZoom:), @"", 0);
    [window addItem:[NSMenuItem separatorItem]];
    addItem(window, @"Show Previous Tab", @selector(selectPreviousTab:), @"\t",
            ctrl | NSEventModifierFlagShift);
    addItem(window, @"Show Next Tab", @selector(selectNextTab:), @"\t", ctrl);
    addItem(window, @"Move Tab to New Window", @selector(moveTabToNewWindow:), @"", 0);
    addItem(window, @"Merge All Windows", @selector(mergeAllWindows:), @"", 0);
    [window addItem:[NSMenuItem separatorItem]];
    addItem(window, @"Bring All to Front", @selector(arrangeInFront:), @"", 0);
    [NSApp setWindowsMenu:window];

    NSMenu* help = addSubmenu(bar, @"Help");
    addItem(help, @"Lethe Help", @selector(openHelp:), @"?", cmd);
    [NSApp setHelpMenu:help];

    [NSApp setMainMenu:bar];
}

@end
