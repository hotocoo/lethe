// LetheAppDelegate.mm - application lifecycle, menu bar, tab/window factory

#import "ui/mac/LetheShell.h"
#import "ui/mac/LetheBookmarks.h"
#import "ui/mac/LetheHistory.h"
#import "ui/mac/LethePreferences.h"
#import "ui/mac/LetheMediaEnhancer.h"
#import "ui/mac/LethePluginLoader.h"
#import "ui/mac/LetheSession.h"
#import "ui/mac/LethePermissions.h"
#import "ui/mac/LetheTabSearch.h"
#import "ui/mac/LetheSettings.h"
#import <Network/Network.h>
#import <objc/runtime.h>

#include <iostream>

#include "browser/url_input.h"
#include "plugins/plugin_registry.h"
#include "security/tracker_blocklist.h"


@interface LetheAppDelegate () {
    lethe::ShellContext* ctx_;
    LethePolicyGate* gate_;
    NSMutableArray<BrowserWindowController*>* controllers_;
    WKWebsiteDataStore* dataStore_;
    NSMutableSet<NSString*>* httpAllowedHosts_;
    WKUserContentController* userContent_;   // shared: one rule list, every tab
    NSUInteger trackerRuleCount_;
    WKContentRuleList* trackerRuleList_;
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
        // Whenever the unified Settings window saves (Cmd+Enter or Save
        // button), [LethePreferences save] posts this. We need to repush
        // the runtime knobs to the live engine; that's exactly what
        // applyPreferences does for tracker rules, UA and https-first.
        // The persistent-cookies case additionally fires its own alert.
        [[NSNotificationCenter defaultCenter] addObserver:self
            selector:@selector(preferencesChanged:)
            name:LethePreferencesDidChangeNotification object:nil];
    }
    return self;
}

- (void)dealloc { [[NSNotificationCenter defaultCenter] removeObserver:self]; }

- (void)preferencesChanged:(NSNotification*)note {
    (void)note;
    [self applyPreferences];
    // Persistent cookies is a per-process choice: the WKWebsiteDataStore
    // is fixed at webView creation time. Tell the user it needs a relaunch.
    static BOOL lastPersistent = NO;
    LethePreferences* p = [LethePreferences shared];
    if (p.persistentCookies != lastPersistent) {
        lastPersistent = p.persistentCookies;
        NSAlert* a = [[NSAlert alloc] init];
        a.messageText = @"Restart Aletheia Browser to apply";
        a.informativeText = @"Persistent cookies are decided when a window opens. New windows will use this setting immediately; close existing windows or relaunch for them to pick it up too.";
        [a runModal];
    }
}

- (lethe::ShellContext*)context { return ctx_; }

#pragma mark - Lifecycle

- (NSUInteger)trackerRuleCount { return trackerRuleCount_; }

- (WKUserContentController*)userContentController {
    if (!userContent_) {
        userContent_ = [[WKUserContentController alloc] init];
        // The script is installed once, before any page document exists.
        // It only activates when the persisted Settings mode is non-zero.
        WKUserScript* media = [[WKUserScript alloc]
            initWithSource:LetheMediaUpscalerScript()
              injectionTime:WKUserScriptInjectionTimeAtDocumentStart
           forMainFrameOnly:YES];
        [userContent_ addUserScript:media];
    }
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
        self->trackerRuleList_ = rules;
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
                          << (err.localizedDescription.UTF8String ?: "unknown")
                          << " userInfo="
                          << (err.userInfo.description.UTF8String ?: "{}")
                          << std::endl;
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
    [self prepareTrackerProtection:^{
        // The full-web shell is only safe when WebKit has accepted the
        // authenticated policy proxy. Do not create a WKWebView if the
        // transport boundary could not be installed; otherwise every
        // subresource would have a direct WebKit network path.
        if (ctx_->proxyPort > 0) (void)[self dataStore];
        if (ctx_->proxyPort > 0 && !proxyApplied_) {
            NSAlert* alert = [[NSAlert alloc] init];
            alert.messageText = @"Aletheia Browser cannot start securely";
            alert.informativeText = @"WebKit transport enforcement could not be installed. Lethe refuses to run full-web mode without the policy proxy.";
            [alert addButtonWithTitle:@"Quit"];
            [alert runModal];
            [NSApp terminate:nil];
            return;
        }
        [self openInitialWindow];
    }];
}

- (void)openInitialWindow {
    NSArray<NSDictionary*>* saved = @[];
    if (ctx_->cfg.initialUrl.empty() && ctx_->e2eScript.empty()) saved = [[LetheSession shared] load];
    NSString* initial = saved.count ? saved.firstObject[@"url"]
        : (ctx_->cfg.initialUrl.empty() ? nil : @(ctx_->cfg.initialUrl.c_str()));
    BrowserWindowController* c = [self openWindowWithURL:initial];
    // Keep the native tab surface visible from the first tab. A browser should
    // communicate its tab model continuously rather than changing its chrome
    // geometry when the second tab appears; AppKit owns the interaction and
    // retains native drag/reorder behavior.
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
    // Apply saved preferences to the just-opened window (UA, etc.).
    [self applyPreferences];
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
    NSMutableArray<NSDictionary*>* snap = [NSMutableArray array];
    for (BrowserWindowController* c in [controllers_ copy]) {
        NSString* url = c.webView.URL.absoluteString;
        if (url.length && [url hasPrefix:@"http"]) [snap addObject:@{@"url":url, @"title":c.webView.title ?: url}];
        [c.window close];
    }
    [[LetheSession shared] saveWindows:snap];
    // The heavy shutdown (stopping the policy proxy + joining its workers,
    // tearing down the engine) can block for a while if live tunnels are
    // open. Run it off the main thread so the app always quits promptly
    // instead of hanging until force-quit. It is best-effort: if the process
    // exits first, the OS reclaims the resources.
    if (ctx_->onTerminate) {
        auto hook = std::move(ctx_->onTerminate);
        ctx_->onTerminate = nullptr;
        dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
            hook();
        });
    }
}

#pragma mark - WebKit configuration

- (WKWebsiteDataStore*)dataStore {
    // Persistent cookies now live in preferences (CLI flag still wins at
    // launch; runtime toggles take effect for new webViews).
    BOOL wantPersistent = [[LethePreferences shared] persistentCookies] || ctx_->persistent;
    if (!dataStore_) {
        dataStore_ = wantPersistent
            ? [WKWebsiteDataStore defaultDataStore]
            : [WKWebsiteDataStore nonPersistentDataStore];
        std::cout << "[lethe] site data store: "
                  << (wantPersistent ? "persistent" : "ephemeral (incognito)")
                  << std::endl;
    }
    if (!proxyApplied_ && ctx_->proxyPort > 0) {
        if ([self bindStoreToProxy:dataStore_]) {
            proxyApplied_ = YES;
            std::cout << "[lethe] WebKit traffic routed through policy proxy "
                         "127.0.0.1:" << ctx_->proxyPort << " (subresource enforcement on)"
                      << std::endl;
        } else {
            std::cerr << "[lethe] WebKit transport proxy could not be installed; "
                         "full-web mode will not start" << std::endl;
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
    // The build target is macOS 14+, so reaching this branch means the
    // runtime contract has been violated. Never silently fall back to a
    // navigation-only gate: WebKit subresources would bypass the transport
    // policy and private-network/VPN controls.
    NSLog(@"[lethe] FATAL: WebKit transport proxy requires macOS 14+");
    return NO;
}

- (WKWebsiteDataStore*)makeOblivionStore {
    WKWebsiteDataStore* store = [WKWebsiteDataStore nonPersistentDataStore];
    // Oblivion has the strongest isolation contract: if the policy proxy is
    // enabled, never hand a WebKit store to a window unless that store was
    // actually bound to the proxy. A failed bind must not silently degrade
    // to WebKit's direct network path.
    if (ctx_->proxyPort > 0 && ![self bindStoreToProxy:store]) {
        std::cerr << "[lethe] Oblivion store: policy proxy binding failed; "
                     "refusing to create an unprotected window" << std::endl;
        return nil;
    }
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
#if DEBUG
    // Keep Web Inspector available for developer builds only. Shipping
    // builds must not expose developer tooling to arbitrary page content.
    [c.preferences setValue:@YES forKey:@"developerExtrasEnabled"];
#endif
    if (@available(macOS 12.3, *)) {
        c.preferences.elementFullscreenEnabled = YES;
    }
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
    // A lone native tab consumes a full second titlebar row on macOS and
    // renders as a wide, stretched tab. Keep the single-tab state visually
    // compact; AppKit will reveal the native strip automatically once another
    // tab is attached.
    // AppKit may finish installing the tab group one run-loop turn after the
    // window is ordered front. Collapse it after that deferred setup rather
    // than racing the native titlebar layout.
    dispatch_async(dispatch_get_main_queue(), ^{
        NSWindowTabGroup* group = c.window.tabGroup;
        if (group && group.windows.count == 1 && group.tabBarVisible)
            [c.window toggleTabBar:nil];
    });
    if (url.length) [c loadAddress:url]; else [c showNewTabPage];
    return c;
}

- (BrowserWindowController*)openOblivionWindowWithURL:(NSString*)url {
    WKWebsiteDataStore* store = [self makeOblivionStore];
    if (!store) {
        NSAlert* alert = [[NSAlert alloc] init];
        alert.messageText = @"Aletheia Browser cannot start Oblivion securely";
        alert.informativeText = @"The isolated window requires the policy proxy. The window was not created because transport enforcement could not be installed.";
        [alert addButtonWithTitle:@"OK"];
        [alert runModal];
        return nil;
    }
    BrowserWindowController* c = [self makeController:nil store:store oblivion:YES];
    c.window.tabbingMode = NSWindowTabbingModeDisallowed;
    [c showWindow:nil];
    [c.window makeKeyAndOrderFront:nil];
    c.window.tabbingMode = NSWindowTabbingModePreferred;
    dispatch_async(dispatch_get_main_queue(), ^{
        NSWindowTabGroup* group = c.window.tabGroup;
        if (group && group.windows.count == 1 && group.tabBarVisible)
            [c.window toggleTabBar:nil];
    });
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
    // When the last tab in a group is closed, AppKit can leave the tab strip
    // visible on the surviving window. Collapse that stale single-tab strip
    // so the chrome keeps the same compact geometry as a fresh window.
    for (BrowserWindowController* c in controllers_) {
        NSWindowTabGroup* group = c.window.tabGroup;
        if (group && group.windows.count == 1 && group.tabBarVisible) {
            [c.window toggleTabBar:nil];
        }
    }
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
    [s appendFormat:@"Aletheia Browser v%s (Lethe engine)\n\n", LETHE_VERSION];
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
    BrowserWindowController* c = [self openTabWithURL:@"lethe://bookmarks" fromWindow:[NSApp keyWindow] webView:nil];
    if (!c) return;
    __weak BrowserWindowController* w = c;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 250 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
        BrowserWindowController* strong = w;
        if (strong) [strong renderBookmarksPage];
    });
}

- (void)clearBookmarks:(id)sender {
    (void)sender;
    NSAlert* a = [[NSAlert alloc] init]; a.messageText = @"Clear all bookmarks?";
    a.informativeText = @"This removes every saved bookmark.";
    [a addButtonWithTitle:@"Cancel"]; [a addButtonWithTitle:@"Clear"];
    if ([a runModal] == NSAlertSecondButtonReturn) for (LetheBookmark* b in [[LetheBookmarks shared] all]) [[LetheBookmarks shared] removeURL:b.url];
}

- (void)showHistory:(id)sender {
    (void)sender;
    BrowserWindowController* c = [self openTabWithURL:@"lethe://history" fromWindow:[NSApp keyWindow] webView:nil];
    if (!c) return;
    __weak BrowserWindowController* w = c;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 250 * NSEC_PER_MSEC), dispatch_get_main_queue(), ^{
        BrowserWindowController* strong = w;
        if (strong) [strong renderHistoryPage];
    });
}

- (void)clearHistory:(id)sender {
    (void)sender;
    NSAlert* a = [[NSAlert alloc] init]; a.messageText = @"Clear browsing history?";
    a.informativeText = @"This removes all recorded visits.";
    [a addButtonWithTitle:@"Cancel"]; [a addButtonWithTitle:@"Clear"];
    if ([a runModal] == NSAlertSecondButtonReturn) [[LetheHistory shared] clear];
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

- (void)showPlugins:(id)sender {
    (void)sender;
    BrowserWindowController* c = [self openTabWithURL:@"lethe://plugins"
                                          fromWindow:[NSApp keyWindow] webView:nil];
    if (!c) return;
    __weak BrowserWindowController* weakC = c;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 250 * NSEC_PER_MSEC),
                   dispatch_get_main_queue(), ^{
        BrowserWindowController* strong = weakC;
        if (strong) [strong renderPluginsPage];
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
    if (item.action == @selector(newOblivionWindow:)) {
        // Oblivion windows are a plugin like everything else: switching the
        // plugin off removes the way in.
        return lethe::PluginRegistry::instance().enabled("oblivion-windows");
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
    // The unified Settings window (sidebar + categories) replaces the old
    // four-checkbox dialog. Cmd+, (Preferences…) is still bound here.
    [[LetheSettings shared] show];
}

- (void)showTabSearch:(id)sender { (void)sender; [[LetheTabSearch shared] show]; }

- (void)prefsToggle:(NSButton*)sender {
    // Legacy: the old preferences dialog used this. The new LetheSettings
    // window writes through [LethePreferences save] directly. Kept as a
    // no-op so the old binary's menu wiring still resolves if a stale
    // .nib is loaded.
    (void)sender;
}

// Apply the current preferences to the running engine. Persistent cookies
// requires a restart (WKWebView's data store is fixed at creation time),
// so we alert the user; everything else is live.
- (void)applyPreferences {
    LethePreferences* prefs = [LethePreferences shared];
    // The document-start script handles new documents, but an existing tab
    // must change immediately when the setting changes. Keep the WebKit
    // page-local scaler and native renderer on the same mode. Environment
    // overrides remain authoritative for deterministic benchmark runs.
    // One resolver (env override, else Settings) for page and native paths.
    const NSInteger webMode = LetheMediaEnhancerMode();
    const lethe::MediaUpscalerMode nativeMode =
        webMode == 0 ? lethe::MediaUpscalerMode::None
      : webMode == 1 ? lethe::MediaUpscalerMode::Linear
                     : lethe::MediaUpscalerMode::MetalFX;
    if (ctx_ && ctx_->engine && ctx_->engine->renderer()->mediaUpscalerMode() != nativeMode)
        ctx_->engine->renderer()->setMediaUpscaler(nativeMode);
    NSString* modeScript = LetheMediaEnhancerApplyJS();
    for (BrowserWindowController* controller in controllers_) {
        WKWebView* web = controller.webView;
        if (!web) continue;
        [web evaluateJavaScript:modeScript completionHandler:^(id result, NSError* error) {
            // A navigation can race the preference update. The document-start
            // script applies the persisted mode to the next document, so a
            // transient evaluation failure is deliberately non-fatal.
            (void)result;
            (void)error;
        }];
    }
    // --- Plugins: the registry is the runtime view of every feature ------
    // 1. Mirror the preference-keyed plugins into the registry.
    lethe::PluginRegistry& reg = lethe::PluginRegistry::instance();
    reg.registerBuiltins();
    for (const lethe::PluginSpec& spec : reg.plugins()) {
        if (spec.prefKey.empty()) continue;
        id v = [prefs valueForKey:@(spec.prefKey.c_str())];
        if ([v respondsToSelector:@selector(boolValue)]) {
            reg.setEnabled(spec.id, [v boolValue]);
        }
    }
    // 2. Engine-only plugins (no pref key) live in pluginOverrides.
    for (NSString* k in prefs.pluginOverrides) {
        reg.setEnabled(std::string(k.UTF8String ?: ""),
                       [prefs.pluginOverrides[k] boolValue]);
    }
    // 3. Live-apply what the registry owns (https-first, tracker-block,
    //    stealth-ua, vpn flags) and (re)install the enabled script plugins.
    reg.applyTo(*ctx_);
    [[LethePluginLoader shared] installInto:[self userContentController]];
    // Tracker blocking is already prepared before the first window is
    // created. Avoid immediately doing the same WebKit store lookup/add a
    // second time from applyPreferences(); that duplicate async round-trip
    // sits directly on the cold-start path. Runtime preference changes still
    // take the update path when the desired state differs from the installed
    // state.
    WKUserContentController* uc = [self userContentController];
    const BOOL trackerInstalled = trackerRuleList_ != nil;
    if (prefs.trackerBlocking == trackerInstalled) {
        // prepareTrackerProtection: already installed the exact immutable
        // rules for the current blocklist when this is the initial apply.
    } else if (trackerInstalled) {
        [uc removeContentRuleList:trackerRuleList_];
        trackerRuleList_ = nil;
        trackerRuleCount_ = 0;
    } else if (prefs.trackerBlocking) {
        const lethe::TrackerBlocklist& list = lethe::builtinTrackerBlocklist();
        NSString* ident = @(lethe::trackerRulesIdentifier(list).c_str());
        WKContentRuleListStore* store = [WKContentRuleListStore defaultStore];
        [store lookUpContentRuleListForIdentifier:ident
                                completionHandler:^(WKContentRuleList* found, NSError* err) {
            (void)err;
            if (found) {
                [uc addContentRuleList:found];
                self->trackerRuleList_ = found;
                return;
            }
            NSString* json = @(lethe::trackerContentRulesJson(list).c_str());
            [store compileContentRuleListForIdentifier:ident
                                encodedContentRuleList:json
                                     completionHandler:^(WKContentRuleList* compiled, NSError* e) {
                (void)e;
                if (compiled) {
                    [uc addContentRuleList:compiled];
                    self->trackerRuleList_ = compiled;
                }
            }];
        }];
        trackerRuleCount_ = list.domains.size() + list.pathPatterns.size();
    } else {
        trackerRuleCount_ = 0;
    }
    // Stealth UA: push to every existing webView (tab/window).
    NSString* ua = (prefs.stealthUA) ? @(lethe::stealthUserAgentString())
                                     : @"";
    for (BrowserWindowController* c in [controllers_ copy]) {
        if (c.webView) c.webView.customUserAgent = ua.length ? ua : nil;
    }
    // HTTPS-first: the policy gate reads ctx_->httpsFirst; we update it
    // directly. Active navigations already in flight won't roll back.
    ctx_->httpsFirst = prefs.httpsFirst;
    // Persistent cookies: data store is fixed at webView creation time.
    NSUserDefaults* defaults = [NSUserDefaults standardUserDefaults];
    BOOL want = prefs.persistentCookies;
    if ([defaults boolForKey:@"LETHE_PERSISTENT_HINT"] != want) {
        [defaults setBool:want forKey:@"LETHE_PERSISTENT_HINT"];
    }
    // -- v0.1.1 perf: live perf knobs --------------------------------
    // The user may have set a maxFrameRate or AA via the Settings panel
    // mid-session; push the new values to every existing webView. The
    // policy proxy worker count is fixed at startup (we'd have to drain
    // and re-spawn the pool to change it live), so the Settings UI also
    // tells the user that a relaunch is required for that one knob.
    for (BrowserWindowController* c in [controllers_ copy]) {
        if (!c.webView) continue;
        if (prefs.maxFrameRate > 0) {
            NSLog(@"[lethe] maxFrameRate=%ld (best-effort)", (long)prefs.maxFrameRate);
        }
        // Browser media surfaces are owned by WebKit and are not exposed as
        // Metal textures. The injected WebGL scaler therefore handles the
        // media elements that WebGL is permitted to sample. Mode 1 is the
        // fast linear path; modes 2/3 select the high-quality reconstruction.
        NSInteger mediaMode = 0;
        const char* env = getenv("LETHE_UPSCALER");
        if (env && *env) {
            std::string v = env;
            for (char& ch : v) if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
            if (v == "linear") mediaMode = 1;
            else if (v == "metalfx-sharp") mediaMode = 3;
            else if (v == "metalfx" || v == "metalfx-spatial" || v == "fsr") mediaMode = 2;
        } else if (prefs.upscaler == LetheUpscalerLinear) mediaMode = 1;
        else if (prefs.upscaler == LetheUpscalerFSR1) mediaMode = 2;
        else if (prefs.upscaler == LetheUpscalerDLSSLike) mediaMode = 3;
        NSString* js = LetheMediaEnhancerApplyJS();
        [c.webView evaluateJavaScript:js completionHandler:^(id result, NSError* error) {
            (void)result;
            if (error) NSLog(@"[lethe] media upscaler injection: %@", error.localizedDescription);
        }];
    }
}
- (void)buildMenuBar {
    NSMenu* bar = [[NSMenu alloc] init];
    const NSEventModifierFlags cmd = NSEventModifierFlagCommand;
    const NSEventModifierFlags cmdShift = cmd | NSEventModifierFlagShift;
    const NSEventModifierFlags cmdCtrl = cmd | NSEventModifierFlagControl;
    const NSEventModifierFlags ctrl = NSEventModifierFlagControl;

    NSMenu* app = addSubmenu(bar, @"Aletheia Browser");
    addItem(app, @"About Aletheia Browser", @selector(orderFrontStandardAboutPanel:), @"", 0);
    [app addItem:[NSMenuItem separatorItem]];
    addItem(app, @"Security Status…", @selector(showSecurityStatus:), @"i", cmdShift);
    addItem(app, @"Preferences…", @selector(showPreferences:), @",", cmd);
    [app addItem:[NSMenuItem separatorItem]];
    [app addItem:[NSMenuItem separatorItem]];
    addItem(app, @"Hide Aletheia Browser", @selector(hide:), @"h", cmd);
    addItem(app, @"Hide Others", @selector(hideOtherApplications:), @"h",
            cmd | NSEventModifierFlagOption);
    addItem(app, @"Show All", @selector(unhideAllApplications:), @"", 0);
    [app addItem:[NSMenuItem separatorItem]];
    addItem(app, @"Quit Aletheia Browser", @selector(terminate:), @"q", cmd);

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

    NSMenu* bookmarks = addSubmenu(bar, @"Bookmarks");
    addItem(bookmarks, @"Toggle Bookmark", @selector(toggleBookmark:), @"d", cmd);
    addItem(bookmarks, @"Show All Bookmarks…", @selector(showBookmarks:), @"", 0);
    [bookmarks addItem:[NSMenuItem separatorItem]];
    addItem(bookmarks, @"Clear Bookmarks", @selector(clearBookmarks:), @"", 0);

    NSMenu* view = addSubmenu(bar, @"View");
    addItem(view, @"Reload Page", @selector(reloadPage:), @"r", cmd);
    addItem(view, @"Stop", @selector(stopLoading:), @".", cmd);
    [view addItem:[NSMenuItem separatorItem]];
    addItem(view, @"Reader View", @selector(toggleReader:), @"r", cmdShift);
    [view addItem:[NSMenuItem separatorItem]];
    addItem(view, @"Find in Tabs…", @selector(showTabSearch:), @"\\", cmd);
    [view addItem:[NSMenuItem separatorItem]];
    addItem(view, @"Show Web Inspector", @selector(showWebInspector:), @"i", cmd | NSEventModifierFlagOption);
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
    addItem(privacy, @"Plugins…", @selector(showPlugins:), @"", 0);
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
    addItem(help, @"Aletheia Browser Help", @selector(openHelp:), @"?", cmd);
    [NSApp setHelpMenu:help];

    [NSApp setMainMenu:bar];
}

@end
