// LetheAppDelegate.mm - application lifecycle, menu bar, tab/window factory

#import "ui/mac/LetheShell.h"
#import <Network/Network.h>

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
    [self buildMenuBar];
    [self prepareTrackerProtection:^{ [self openInitialWindow]; }];
}

- (void)openInitialWindow {
    NSString* initial = ctx_->cfg.initialUrl.empty()
        ? nil : @(ctx_->cfg.initialUrl.c_str());
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
            dataStore_.proxyConfigurations = @[pc];
            std::cout << "[lethe] WebKit traffic routed through policy proxy "
                         "127.0.0.1:" << port << " (subresource enforcement on)"
                      << std::endl;
        } else {
            std::cout << "[lethe] macOS < 14: no per-datastore proxy API; "
                         "navigation gate only" << std::endl;
        }
    }
    return dataStore_;
}

- (WKWebViewConfiguration*)webViewConfiguration {
    WKWebViewConfiguration* c = [[WKWebViewConfiguration alloc] init];
    c.websiteDataStore = [self dataStore];
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
    return c;
}

#pragma mark - Windows and tabs

- (BrowserWindowController*)makeController:(WKWebView*)existing {
    BrowserWindowController* c =
        [[BrowserWindowController alloc] initWithContext:ctx_ gate:gate_ webView:existing];
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

- (BrowserWindowController*)openTabWithURL:(NSString*)url
                                fromWindow:(NSWindow*)parent
                                   webView:(WKWebView*)existing {
    if (!parent) {
        BrowserWindowController* c = [self makeController:existing];
        [c showWindow:nil];
        [c.window makeKeyAndOrderFront:nil];
        if (!existing) { if (url.length) [c loadAddress:url]; else [c showNewTabPage]; }
        return c;
    }
    BrowserWindowController* c = [self makeController:existing];
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

- (void)buildMenuBar {
    NSMenu* bar = [[NSMenu alloc] init];
    const NSEventModifierFlags cmd = NSEventModifierFlagCommand;
    const NSEventModifierFlags cmdShift = cmd | NSEventModifierFlagShift;
    const NSEventModifierFlags cmdCtrl = cmd | NSEventModifierFlagControl;
    const NSEventModifierFlags ctrl = NSEventModifierFlagControl;

    NSMenu* app = addSubmenu(bar, @"Lethe");
    addItem(app, @"About Lethe", @selector(orderFrontStandardAboutPanel:), @"", 0);
    [app addItem:[NSMenuItem separatorItem]];
    addItem(app, @"Security Status…", @selector(showSecurityStatus:), @"i", cmdShift);
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
    addItem(file, @"Open Location…", @selector(focusAddressBar:), @"l", cmd);
    [file addItem:[NSMenuItem separatorItem]];
    addItem(file, @"Close Tab", @selector(performClose:), @"w", cmd);
    addItem(file, @"Close Window", @selector(closeWholeWindow:), @"w", cmdShift);
    [file addItem:[NSMenuItem separatorItem]];
    addItem(file, @"Downloads", @selector(openDownloadsFolder:), @"j", cmdShift);
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

    NSMenu* view = addSubmenu(bar, @"View");
    addItem(view, @"Reload Page", @selector(reloadPage:), @"r", cmd);
    addItem(view, @"Stop", @selector(stopLoading:), @".", cmd);
    [view addItem:[NSMenuItem separatorItem]];
    addItem(view, @"Reader View", @selector(toggleReader:), @"r", cmdShift);
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

    NSMenu* privacy = addSubmenu(bar, @"Privacy");
    addItem(privacy, @"Connect VPN", @selector(toggleVpn:), @"", 0);
    addItem(privacy, @"Clear Browsing Data", @selector(clearBrowsingData:), @"", 0);
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
