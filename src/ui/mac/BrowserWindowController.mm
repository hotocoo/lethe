// BrowserWindowController.mm - one browser tab: chrome + WKWebView
//
// Tabs are native NSWindow tabs (one window per tab, grouped by
// tabbingIdentifier), so ⌘T/⌘W/⌃⇥, drag-to-reorder and "Move Tab to New
// Window" come from AppKit and behave like every other Mac browser.

#import "ui/mac/LetheShell.h"
#import "ui/mac/LetheBookmarks.h"
#import "ui/mac/LetheHistory.h"
#import "ui/mac/LetheDownloads.h"
#import "ui/mac/LethePermissions.h"
#import "ui/mac/LethePreferences.h"
#import <objc/runtime.h>

#include <string>
#include <vector>

#include "browser/url_input.h"
#include "renderer/page_templates.h"

static void* const kObserverContext = (void*)&kObserverContext;
static NSString* const kTabbingIdentifier = @"org.aletheia.lethe.browser";
static NSString* const kOblivionTabbingIdentifier = @"org.aletheia.lethe.oblivion";
static const CGFloat kChromeHeight = 44.0;

@interface BrowserWindowController () <WKNavigationDelegate, WKUIDelegate,
                                       WKDownloadDelegate, NSWindowDelegate,
                                       NSTextFieldDelegate, WKScriptMessageHandler> {
    NSString* httpsUpgradedFrom_;   // http URL being tried as https (HTTPS-first)
    BOOL oblivion_;
    WKWebsiteDataStore* dataStore_;
    lethe::ShellContext* ctx_;
    LethePolicyGate* gate_;
    WKWebView* webView_;
    NSTextField* addressField_;
    NSImageView* lockIcon_;
    NSButton* backButton_;
    NSButton* forwardButton_;
    NSButton* reloadButton_;
    NSButton* readerButton_;
    NSButton* bookmarkButton_;
    NSProgressIndicator* progress_;
    NSView* findBar_;
    NSTextField* findField_;
    NSTextField* findStatus_;
    // Unique per-BWC names for the "bookmarks" and "perms" script message
    // handlers. The shared userContentController can only have one object
    // registered per name; suffixing with a counter lets every BWC register
    // its own handler. The injected JS reads the right name from
    // window.__letheHandlerNames injected at doc-start (see webView:
    // didStartProvisionalNavigation). The names are also stored so the
    // dealloc can remove them.
    NSArray* messageHandlerNames_;    NSLayoutConstraint* findBarHeight_;
    NSMutableArray<WKDownload*>* downloads_;
    BOOL observing_;
    BOOL addressEditing_;
    BOOL readerActive_;
    BOOL readerLoadPending_;
    BOOL readerFetching_;
    NSString* readerSourceUrl_;
    NSString* internalPageUrl_;   // address shown while an internal page is up
}
@end

@implementation BrowserWindowController

static const void* kLetheDownloadItemKey = (const void*)"letheDownloadItem";

@synthesize webView = webView_;
@synthesize addressField = addressField_;
@synthesize readerActive = readerActive_;

- (BOOL)busy { return webView_.loading || readerFetching_; }
- (BOOL)oblivion { return oblivion_; }
- (WKWebsiteDataStore*)dataStore { return dataStore_; }

#pragma mark - Construction

- (instancetype)initWithContext:(lethe::ShellContext*)ctx
                           gate:(LethePolicyGate*)gate
                        webView:(WKWebView*)existingWebView {
    return [self initWithContext:ctx gate:gate webView:existingWebView dataStore:nil oblivion:NO];
}

- (instancetype)initWithContext:(lethe::ShellContext*)ctx
                           gate:(LethePolicyGate*)gate
                        webView:(WKWebView*)existingWebView
                      dataStore:(WKWebsiteDataStore*)store
                       oblivion:(BOOL)oblivion {
    NSWindow* window = [[NSWindow alloc]
        initWithContentRect:NSMakeRect(0, 0, 1280, 860)
                  styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                            NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable
                    backing:NSBackingStoreBuffered
                      defer:NO];
    if ((self = [super initWithWindow:window])) {
        ctx_ = ctx;
        gate_ = gate;
        oblivion_ = oblivion;
        dataStore_ = store;
        downloads_ = [NSMutableArray array];
        window.title = oblivion ? @"Oblivion" : @"New Tab";
        window.releasedWhenClosed = NO;
        window.tabbingMode = NSWindowTabbingModePreferred;
        window.tabbingIdentifier = oblivion ? kOblivionTabbingIdentifier : kTabbingIdentifier;
        if (oblivion) {
            // Unmistakable: dark chrome regardless of the system appearance.
            window.appearance = [NSAppearance appearanceNamed:NSAppearanceNameDarkAqua];
        }
        window.minSize = NSMakeSize(480, 320);
        window.delegate = self;
        [window center];
        [window setFrameAutosaveName:@"LetheBrowserWindow"];

        if (existingWebView) {
            webView_ = existingWebView;
        } else {
            LetheAppDelegate* app = (LetheAppDelegate*)NSApp.delegate;
            webView_ = [[WKWebView alloc] initWithFrame:NSZeroRect
                                          configuration:[app webViewConfigurationWithStore:store]];
        }
        if (!dataStore_) dataStore_ = webView_.configuration.websiteDataStore;
        webView_.navigationDelegate = self;
        webView_.UIDelegate = self;
        webView_.allowsBackForwardNavigationGestures = YES;
        webView_.allowsMagnification = YES;
        // -- v0.1.1 perf --------------------------------------------------
        // NOTE on WebKit frame-rate control: CALayer.preferredFrameRateRange
        // is iOS-only; on macOS there is no public per-layer rAF cap. The
        // WKWebView has a private CADisplayLink preference but the exact
        // KVC key is version-dependent and absent in current WebKit on
        // macOS 13/14 - calling setValue:forUndefinedKey: throws.
        // The reliable wins on this platform are: the policy proxy worker
        // pool (page-load throughput), and letting the user set a cap via
        // the Settings panel. The cap is recorded here for the run; the
        // Engine settings UI explains the macOS limitation.
        LethePreferences* prefs = [LethePreferences shared];
        if (prefs.maxFrameRate > 0) {
            NSLog(@"[lethe] maxFrameRate=%ld (best-effort; macOS lacks a public rAF cap)",
                  (long)prefs.maxFrameRate);
        }
        if (oblivion_ || ctx_->cfg.userAgentMode == "stealth"
            || [[LethePreferences shared] stealthUA]) {
            // Oblivion and stealth mode (CLI or Preferences) present the
            // fixed low-entropy profile.
            webView_.customUserAgent = @(lethe::stealthUserAgentString());
        }
        // The userContentController is shared across all BWCs so that the
        // tracker rules compile once. The trade-off is that
        // addScriptMessageHandler: requires a unique name PER HANDLER
        // OBJECT - WebKit throws if a different object tries to register
        // a name that is already taken. Solution: give this BWC a unique
        // name by suffixing a per-instance counter. The JS calls
        // webkit.messageHandlers["bookmarks-<suffix>"] via the global
        // window.__letheHandlerNames() we inject at doc-start.
        static NSUInteger s_handlerCounter = 0;
        const NSUInteger n = ++s_handlerCounter;
        NSString* bmName = [NSString stringWithFormat:@"bookmarks-%lu", (unsigned long)n];
        NSString* pmName = [NSString stringWithFormat:@"perms-%lu", (unsigned long)n];
        messageHandlerNames_ = @[bmName, pmName];
        [webView_.configuration.userContentController addScriptMessageHandler:self name:bmName];
        [webView_.configuration.userContentController addScriptMessageHandler:self name:pmName];
        [self buildChrome];
        [self startObserving];
    }
    return self;
}

- (NSButton*)chromeButtonWithSymbol:(NSString*)symbol
                              label:(NSString*)label
                             action:(SEL)action {
    NSImage* img = [NSImage imageWithSystemSymbolName:symbol
                             accessibilityDescription:label];
    NSButton* b = [NSButton buttonWithImage:img target:self action:action];
    b.bezelStyle = NSBezelStyleTexturedRounded;
    b.bordered = NO;
    b.toolTip = label;
    b.imageScaling = NSImageScaleProportionallyDown;
    [b.widthAnchor constraintEqualToConstant:30].active = YES;
    [b.heightAnchor constraintEqualToConstant:28].active = YES;
    return b;
}

- (void)buildChrome {
    NSView* content = self.window.contentView;
    content.wantsLayer = YES;

    // --- Toolbar row -----------------------------------------------------
    NSView* chrome = [[NSView alloc] initWithFrame:NSZeroRect];
    chrome.translatesAutoresizingMaskIntoConstraints = NO;
    [content addSubview:chrome];

    backButton_ = [self chromeButtonWithSymbol:@"chevron.left" label:@"Back"
                                        action:@selector(goBack:)];
    forwardButton_ = [self chromeButtonWithSymbol:@"chevron.right" label:@"Forward"
                                           action:@selector(goForward:)];
    reloadButton_ = [self chromeButtonWithSymbol:@"arrow.clockwise" label:@"Reload"
                                          action:@selector(reloadOrStop:)];
    readerButton_ = [self chromeButtonWithSymbol:@"doc.plaintext" label:@"Reader View"
                                          action:@selector(toggleReader:)];

    bookmarkButton_ = [self chromeButtonWithSymbol:@"bookmark" label:@"Bookmark"
                                              action:@selector(toggleBookmark:)];

    lockIcon_ = [[NSImageView alloc] initWithFrame:NSZeroRect];
    lockIcon_.image = [NSImage imageWithSystemSymbolName:@"globe"
                                accessibilityDescription:@"Connection"];
    lockIcon_.contentTintColor = [NSColor secondaryLabelColor];
    [lockIcon_.widthAnchor constraintEqualToConstant:18].active = YES;

    addressField_ = [[NSTextField alloc] initWithFrame:NSZeroRect];
    addressField_.placeholderString = @"Search or enter address";
    addressField_.bezelStyle = NSTextFieldRoundedBezel;
    addressField_.font = [NSFont systemFontOfSize:14];
    addressField_.delegate = self;
    addressField_.target = self;
    addressField_.action = @selector(addressEntered:);
    addressField_.cell.usesSingleLineMode = YES;
    addressField_.cell.scrollable = YES;
    addressField_.cell.lineBreakMode = NSLineBreakByTruncatingTail;
    [addressField_ setContentHuggingPriority:NSLayoutPriorityDefaultLow - 1
                              forOrientation:NSLayoutConstraintOrientationHorizontal];

    NSStackView* row = [NSStackView stackViewWithViews:@[
        backButton_, forwardButton_, reloadButton_, lockIcon_, addressField_, readerButton_, bookmarkButton_ ]];
    row.orientation = NSUserInterfaceLayoutOrientationHorizontal;
    row.spacing = 6;
    row.alignment = NSLayoutAttributeCenterY;
    row.edgeInsets = NSEdgeInsetsMake(0, 8, 0, 8);
    row.translatesAutoresizingMaskIntoConstraints = NO;
    [chrome addSubview:row];

    NSBox* separator = [[NSBox alloc] initWithFrame:NSZeroRect];
    separator.boxType = NSBoxSeparator;
    separator.translatesAutoresizingMaskIntoConstraints = NO;
    [chrome addSubview:separator];

    // --- Find bar (collapsed until ⌘F) -----------------------------------
    findBar_ = [[NSView alloc] initWithFrame:NSZeroRect];
    findBar_.translatesAutoresizingMaskIntoConstraints = NO;
    findBar_.hidden = YES;
    [content addSubview:findBar_];
    findField_ = [[NSTextField alloc] initWithFrame:NSZeroRect];
    findField_.placeholderString = @"Find in page";
    findField_.bezelStyle = NSTextFieldRoundedBezel;
    findField_.delegate = self;
    findField_.target = self;
    findField_.action = @selector(findNext:);
    [findField_.widthAnchor constraintGreaterThanOrEqualToConstant:280].active = YES;
    findStatus_ = [NSTextField labelWithString:@""];
    findStatus_.textColor = [NSColor secondaryLabelColor];
    NSButton* prev = [self chromeButtonWithSymbol:@"chevron.up" label:@"Previous match"
                                           action:@selector(findPrevious:)];
    NSButton* next = [self chromeButtonWithSymbol:@"chevron.down" label:@"Next match"
                                           action:@selector(findNext:)];
    NSButton* done = [NSButton buttonWithTitle:@"Done" target:self
                                        action:@selector(hideFindBar:)];
    done.bezelStyle = NSBezelStyleRounded;
    done.controlSize = NSControlSizeSmall;
    NSStackView* findRow = [NSStackView stackViewWithViews:@[
        findField_, prev, next, findStatus_, done ]];
    findRow.orientation = NSUserInterfaceLayoutOrientationHorizontal;
    findRow.spacing = 6;
    findRow.edgeInsets = NSEdgeInsetsMake(0, 8, 0, 8);
    findRow.translatesAutoresizingMaskIntoConstraints = NO;
    [findBar_ addSubview:findRow];
    NSBox* findSep = [[NSBox alloc] initWithFrame:NSZeroRect];
    findSep.boxType = NSBoxSeparator;
    findSep.translatesAutoresizingMaskIntoConstraints = NO;
    [findBar_ addSubview:findSep];

    // --- Content ---------------------------------------------------------
    webView_.translatesAutoresizingMaskIntoConstraints = NO;
    [content addSubview:webView_];

    progress_ = [[NSProgressIndicator alloc] initWithFrame:NSZeroRect];
    progress_.style = NSProgressIndicatorStyleBar;
    progress_.indeterminate = NO;
    progress_.minValue = 0;
    progress_.maxValue = 1;
    progress_.controlSize = NSControlSizeSmall;
    progress_.translatesAutoresizingMaskIntoConstraints = NO;
    progress_.hidden = YES;
    [content addSubview:progress_];

    NSDictionary* v = @{ @"chrome": chrome, @"row": row, @"sep": separator,
                         @"find": findBar_, @"findRow": findRow, @"findSep": findSep,
                         @"web": webView_, @"progress": progress_ };
    NSMutableArray<NSLayoutConstraint*>* cs = [NSMutableArray array];
    [cs addObjectsFromArray:[NSLayoutConstraint constraintsWithVisualFormat:
        @"H:|[chrome]|" options:0 metrics:nil views:v]];
    [cs addObjectsFromArray:[NSLayoutConstraint constraintsWithVisualFormat:
        @"H:|[find]|" options:0 metrics:nil views:v]];
    [cs addObjectsFromArray:[NSLayoutConstraint constraintsWithVisualFormat:
        @"H:|[web]|" options:0 metrics:nil views:v]];
    [cs addObjectsFromArray:[NSLayoutConstraint constraintsWithVisualFormat:
        @"H:|[progress]|" options:0 metrics:nil views:v]];
    [cs addObjectsFromArray:[NSLayoutConstraint constraintsWithVisualFormat:
        @"V:|[chrome(==h)][find][web]|" options:0 metrics:@{ @"h": @(kChromeHeight) } views:v]];
    [cs addObjectsFromArray:[NSLayoutConstraint constraintsWithVisualFormat:
        @"H:|[row]|" options:0 metrics:nil views:v]];
    [cs addObjectsFromArray:[NSLayoutConstraint constraintsWithVisualFormat:
        @"V:|[row][sep(1)]|" options:0 metrics:nil views:v]];
    [cs addObjectsFromArray:[NSLayoutConstraint constraintsWithVisualFormat:
        @"H:|[sep]|" options:0 metrics:nil views:v]];
    [cs addObjectsFromArray:[NSLayoutConstraint constraintsWithVisualFormat:
        @"H:|[findRow]|" options:0 metrics:nil views:v]];
    [cs addObjectsFromArray:[NSLayoutConstraint constraintsWithVisualFormat:
        @"V:|[findRow][findSep(1)]|" options:0 metrics:nil views:v]];
    [cs addObjectsFromArray:[NSLayoutConstraint constraintsWithVisualFormat:
        @"H:|[findSep]|" options:0 metrics:nil views:v]];
    findBarHeight_ = [findBar_.heightAnchor constraintEqualToConstant:0];
    [cs addObject:findBarHeight_];
    [cs addObject:[progress_.topAnchor constraintEqualToAnchor:webView_.topAnchor]];
    [NSLayoutConstraint activateConstraints:cs];

    [self updateNavigationButtons];
}

#pragma mark - Observation

- (void)startObserving {
    if (observing_) return;
    observing_ = YES;
    for (NSString* key in [self observedKeys]) {
        [webView_ addObserver:self forKeyPath:key
                      options:NSKeyValueObservingOptionNew context:kObserverContext];
    }
}

- (void)stopObserving {
    if (!observing_) return;
    observing_ = NO;
    for (NSString* key in [self observedKeys]) {
        [webView_ removeObserver:self forKeyPath:key context:kObserverContext];
    }
}

- (NSArray<NSString*>*)observedKeys {
    return @[ @"title", @"URL", @"estimatedProgress", @"loading",
              @"canGoBack", @"canGoForward", @"hasOnlySecureContent" ];
}

- (void)observeValueForKeyPath:(NSString*)keyPath ofObject:(id)object
                        change:(NSDictionary*)change context:(void*)context {
    if (context != kObserverContext) {
        [super observeValueForKeyPath:keyPath ofObject:object change:change context:context];
        return;
    }
    if ([keyPath isEqualToString:@"title"] || [keyPath isEqualToString:@"URL"]) {
        [self updateTitle];
        [self updateAddress];
    } else if ([keyPath isEqualToString:@"estimatedProgress"]) {
        progress_.doubleValue = webView_.estimatedProgress;
    } else if ([keyPath isEqualToString:@"loading"]) {
        progress_.hidden = !webView_.loading;
        if (!webView_.loading) progress_.doubleValue = 0;
        [self updateReloadButton];
    } else if ([keyPath isEqualToString:@"hasOnlySecureContent"]) {
        [self updateLockIcon];
    } else {
        [self updateNavigationButtons];
    }
}

#pragma mark - Chrome state

- (void)updateTitle {
    NSString* title = webView_.title;
    if (!title.length) title = webView_.URL.host;
    if (!title.length) title = internalPageUrl_.length ? internalPageUrl_ : @"New Tab";
    if (oblivion_) title = [NSString stringWithFormat:@"%@ — Oblivion", title];
    self.window.title = title;
}

- (NSString*)displayAddress {
    NSURL* url = webView_.URL;
    if (internalPageUrl_ && (!url || [url.scheme isEqualToString:@"about"])) {
        return internalPageUrl_;
    }
    if (!url || [url.absoluteString isEqualToString:@"about:blank"]) return @"";
    return url.absoluteString;
}

- (void)updateAddress {
    if (addressEditing_) return;
    addressField_.stringValue = [self displayAddress];
    [self updateLockIcon];
    [self refreshBookmarkIcon];
}

- (void)updateLockIcon {
    NSURL* url = webView_.URL;
    NSString* symbol = @"globe";
    NSColor* tint = [NSColor secondaryLabelColor];
    NSString* tip = @"Internal page";
    if ([url.scheme isEqualToString:@"https"]) {
        if (webView_.hasOnlySecureContent) {
            symbol = @"lock.fill"; tint = [NSColor systemGreenColor];
            tip = @"Secure connection (HTTPS)";
        } else {
            symbol = @"lock.trianglebadge.exclamationmark"; tint = [NSColor systemOrangeColor];
            tip = @"HTTPS page with insecure content";
        }
    } else if ([url.scheme isEqualToString:@"http"]) {
        symbol = @"lock.open"; tint = [NSColor systemRedColor];
        tip = @"Not secure (plain HTTP)";
    }
    lockIcon_.image = [NSImage imageWithSystemSymbolName:symbol accessibilityDescription:tip];
    lockIcon_.contentTintColor = tint;
    lockIcon_.toolTip = tip;
}

- (void)updateNavigationButtons {
    backButton_.enabled = webView_.canGoBack;
    forwardButton_.enabled = webView_.canGoForward;
}

- (void)updateReloadButton {
    const BOOL loading = webView_.loading;
    reloadButton_.image = [NSImage imageWithSystemSymbolName:loading ? @"xmark" : @"arrow.clockwise"
                                    accessibilityDescription:loading ? @"Stop" : @"Reload"];
    reloadButton_.toolTip = loading ? @"Stop" : @"Reload";
}

#pragma mark - Loading

- (void)showNewTabPage {
    internalPageUrl_ = @"";
    readerActive_ = NO;
    std::vector<lethe::SpeedDialItem> bm;
    NSArray<LetheBookmark*>* allB = [[LetheBookmarks shared] all];
    NSUInteger n = MIN((NSUInteger)8, allB.count);
    for (NSUInteger i = 0; i < n; i++) {
        bm.push_back({std::string(allB[i].title.UTF8String ?: ""),
                     std::string(allB[i].url.UTF8String ?: "")});
    }
    std::vector<lethe::SpeedDialItem> rc;
    NSArray<LetheHistoryEntry*>* allH = [[LetheHistory shared] allEntries];
    NSUInteger m = MIN((NSUInteger)8, allH.count);
    for (NSUInteger i = 0; i < m; i++) {
        rc.push_back({std::string(allH[i].title.UTF8String ?: ""),
                     std::string(allH[i].url.UTF8String ?: "")});
    }
    [webView_ loadHTMLString:@(lethe::renderNewTabPage(rc, bm).c_str()) baseURL:nil];
    [self updateTitle];
    [self updateAddress];
    [self focusAddressBar:nil];
}

- (void)renderBookmarksPage {
    NSMutableString* rows = [NSMutableString string];
    NSArray<LetheBookmark*>* all = [[LetheBookmarks shared] all];
    for (LetheBookmark* b in all) {
        NSString* esc = [b.title stringByReplacingOccurrencesOfString:@"<" withString:@"&lt;"];
        esc = [esc stringByReplacingOccurrencesOfString:@">" withString:@"&gt;"];
        esc = [esc stringByReplacingOccurrencesOfString:@"&" withString:@"&amp;"];
        NSString* urlEsc = [b.url stringByReplacingOccurrencesOfString:@"\"" withString:@"&quot;"];
        [rows appendFormat:@"\n          <li><a href=\"%@\">%@</a><br><span class=\"u\">%@</span>\n                       <button class=\"rm\" data-url=\"%@\">Remove</button></li>", urlEsc, esc, urlEsc, urlEsc];
    }
    NSString* body = all.count ? [NSString stringWithFormat:@"<ul>%@</ul>", rows]
                                : @"<p class=\"empty\">No bookmarks yet. Press Cmd+D to bookmark the current page.</p>";
    NSString* html = [NSString stringWithFormat:@"\n        <!doctype html><meta charset=\"utf-8\">\n        <title>Bookmarks</title>\n        <style>\n          body{font:14px -apple-system,system-ui,sans-serif;margin:32px;max-width:780px;color:#222;background:#fafafa}\n          h1{margin:0 0 8px;font-size:22px;font-weight:600}\n          p.sub{color:#666;margin:0 0 24px}\n          ul{list-style:none;padding:0;margin:0}\n          li{padding:14px 16px;margin:6px 0;background:#fff;border:1px solid #e5e5e5;border-radius:8px}\n          li a{color:#0a66c2;text-decoration:none;font-weight:500;font-size:15px}\n          li a:hover{text-decoration:underline}\n          .u{color:#666;font-size:12px;font-family:ui-monospace,Menlo,monospace;word-break:break-all}\n          .rm{float:right;background:none;border:1px solid #ccc;border-radius:6px;padding:4px 10px;\n              color:#c0392b;cursor:pointer;font-size:12px}\n          .rm:hover{background:#fee}\n          .empty{color:#666;font-style:italic}\n        </style>\n        <h1>Bookmarks</h1>\n        <p class=\"sub\">%lu saved. Cmd+D toggles the bookmark on the current page.</p>\n        %@\n        <script>\n        document.addEventListener('click', function(e){\n          if (e.target.classList.contains('rm')) {\n            const u = e.target.getAttribute('data-url');\n            (window.webkit.messageHandlers[%@] || {postMessage:function(){}}).postMessage({op:\"remove\", url:u});\n          }\n        });\n        </script>\n      ", (unsigned long)all.count, body, messageHandlerNames_.firstObject ?: @"bookmarks"];
    internalPageUrl_ = @"lethe://bookmarks";
    [webView_ loadHTMLString:html baseURL:nil];
    [self updateTitle];
    [self updateAddress];
}


- (void)renderHistoryPage {
    NSArray<LetheHistoryEntry*>* entries = [[LetheHistory shared] allEntries];
    NSDateFormatter* fmt = [[NSDateFormatter alloc] init];
    fmt.dateStyle = NSDateFormatterShortStyle;
    fmt.timeStyle = NSDateFormatterShortStyle;
    NSMutableString* rows = [NSMutableString string];
    NSString* lastDay = nil;
    for (LetheHistoryEntry* h in entries) {
        NSString* day = [fmt stringFromDate:h.visitedAt];
        if (![day isEqualToString:lastDay]) {
            if (lastDay) [rows appendString:@"</ul>"];
            [rows appendFormat:@"<h2>%@</h2><ul>", day];
            lastDay = day;
        }
        NSString* esc = [h.title stringByReplacingOccurrencesOfString:@"<" withString:@"&lt;"];
        esc = [esc stringByReplacingOccurrencesOfString:@">" withString:@"&gt;"];
        esc = [esc stringByReplacingOccurrencesOfString:@"&" withString:@"&amp;"];
        NSString* urlEsc = [h.url stringByReplacingOccurrencesOfString:@"\"" withString:@"&quot;"];
        NSString* time = [[NSDateFormatter localizedStringFromDate:h.visitedAt dateStyle:NSDateFormatterNoStyle timeStyle:NSDateFormatterShortStyle] stringByReplacingOccurrencesOfString:@"\"" withString:@"&quot;"];
        [rows appendFormat:@"<li><a href=\"%@\">%@</a><br><span class=\"u\">%@</span> <span class=\"t\">%@</span></li>", urlEsc, esc, urlEsc, time];
    }
    if (lastDay) [rows appendString:@"</ul>"];
    NSString* body = entries.count ? rows : @"<p class=\"empty\">No history yet.</p>";
    NSString* html = [NSString stringWithFormat:@"<!doctype html><meta charset=\"utf-8\"><title>History</title>"
        @"<style>body{font:14px -apple-system,system-ui,sans-serif;margin:32px;max-width:780px;color:#222;background:#fafafa}"
        @"h1{margin:0 0 16px;font-size:22px}h2{margin:24px 0 6px;font-size:13px;color:#666;font-weight:600;text-transform:uppercase}"
        @"ul{list-style:none;padding:0;margin:0}li{padding:8px 12px;margin:2px 0;background:#fff;border:1px solid #e5e5e5;border-radius:6px}"
        @"li a{color:#0a66c2;text-decoration:none;font-weight:500}li a:hover{text-decoration:underline}"
        @".u{color:#666;font-size:11px;font-family:ui-monospace,Menlo,monospace;word-break:break-all;margin-right:8px}"
        @".t{color:#999;font-size:11px}.empty{color:#666;font-style:italic}</style>"
        @"<h1>History</h1><p class=\"empty\" style=\"margin:0 0 8px\">%lu entries. \\u2318Y opens this page.</p>%@",
        (unsigned long)entries.count, body];
    internalPageUrl_ = @"lethe://history";
    [webView_ loadHTMLString:html baseURL:nil];
    [self updateTitle];
    [self updateAddress];
}

- (void)renderPermissionsPage {
    NSMutableString* rows = [NSMutableString string];
    NSString* path = [[NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES).firstObject stringByAppendingPathComponent:@"Lethe"] stringByAppendingPathComponent:@"permissions.json"];
    NSDictionary* dict = [NSDictionary dictionaryWithContentsOfFile:path];
    NSArray<NSString*>* keys = dict.allKeys;
    keys = [keys sortedArrayUsingComparator:^NSComparisonResult(NSString* a, NSString* b) { return [a compare:b]; }];
    for (NSString* k in keys) {
        NSArray<NSString*>* parts = [k componentsSeparatedByString:@"|"];
        if (parts.count != 2) continue;
        NSString* host = parts[0];
        NSString* type = parts[1];
        NSInteger v = [dict[k] integerValue];
        NSString* state = (v == LethePermissionAllow) ? @"Allowed" : @"Blocked";
        NSString* escHost = [host stringByReplacingOccurrencesOfString:@"<" withString:@"&lt;"];
        escHost = [escHost stringByReplacingOccurrencesOfString:@">" withString:@"&gt;"];
        escHost = [escHost stringByReplacingOccurrencesOfString:@"&" withString:@"&amp;"];
        [rows appendFormat:@"<li><span class=\"h\">%@</span> <span class=\"t\">%@</span> <span class=\"s Allowed\">%@</span> <button class=\"rm\" data-host=\"%@\" data-type=\"%@\">Clear</button></li>", escHost, type, state, escHost, type];
    }
    NSString* body = keys.count ? [NSString stringWithFormat:@"<ul>%@</ul>", rows] : @"<p class=\"empty\">No sites have stored permissions yet.</p>";
    NSString* html = [NSString stringWithFormat:@"<!doctype html><meta charset=\"utf-8\"><title>Site Permissions</title>"
        @"<style>body{font:14px -apple-system,system-ui,sans-serif;margin:32px;max-width:780px;color:#222;background:#fafafa}"
        @"h1{margin:0 0 8px;font-size:22px}h1+p{color:#666;margin:0 0 24px}"
        @"ul{list-style:none;padding:0;margin:0}"
        @"li{padding:10px 12px;margin:2px 0;background:#fff;border:1px solid #e5e5e5;border-radius:6px;display:flex;align-items:center;gap:10px}"
        @".h{font-weight:600;min-width:140px}.t{color:#666;font-size:12px;min-width:80px}"
        @".s.Allowed{color:#0a7a3a}.s.Blocked{color:#a04020}"
        @".rm{margin-left:auto;background:none;border:1px solid #ccc;border-radius:6px;padding:3px 10px;color:#c0392b;cursor:pointer;font-size:12px}"
        @".rm:hover{background:#fee}.empty{color:#666;font-style:italic}</style>"
        @"<h1>Site Permissions</h1><p>Allow or block camera, microphone, and location per site. The browser prompts the first time; tick 'Remember' to persist.</p>%@"
        @"<script>document.addEventListener('click',function(e){"
        @"if(e.target.classList.contains('rm')){var u=e.target.getAttribute('data-host'),t=e.target.getAttribute('data-type');"
        @"(window.webkit.messageHandlers[%@]||{postMessage:function(){}}).postMessage({op:'clear',host:u,type:t});}"
        @"});</script>", body, messageHandlerNames_.lastObject ?: @"perms"];
    internalPageUrl_ = @"lethe://permissions";
    [webView_ loadHTMLString:html baseURL:nil];
    [self updateTitle];
    [self updateAddress];
}

// renderStressPage: in-page torture that exercises the renderer/main
// thread. 100k DOM nodes, a rotating WebGL quad, 20ms of JS work per
// frame, and a stats overlay that reports live FPS. Same workload in
// Chrome under the same harness (the bench calls this through a
// e2e command; the URL itself is never navigated to, so the policy
// gate cannot block it). v0.1.1 perf regression baseline.
- (void)renderStressPage {
    NSString* html = @"<!doctype html><meta charset=\"utf-8\">"
        "<title>Lethe stress</title>"
        "<style>body{margin:0;background:#000;color:#fff;font:14px monospace}</style>"
        "<canvas id=\"gl\" width=\"1280\" height=\"720\"></canvas>"
        "<div id=\"nodes\"></div>"
        "<div id=\"stats\" style=\"position:fixed;top:8px;right:8px;background:rgba(0,0,0,0.6);padding:6px 10px;border-radius:6px\"></div>"
        "<script>"
        "var nd=document.getElementById('nodes');"
        "for(var i=0;i<2000;i++){var row=document.createElement('div');var s='';"
        "for(var j=0;j<50;j++)s+='<span>'+(i*50+j)+'</span> ';row.innerHTML=s;nd.appendChild(row);}"
        "var gl=document.getElementById('gl').getContext('webgl');var prog=null;"
        "if(gl){var vs=gl.createShader(gl.VERTEX_SHADER);"
        "gl.shaderSource(vs,'attribute vec2 p;uniform float t;varying float v;void main(){v=t;gl_Position=vec2(p.x*cos(t)-p.y*sin(t),p.x*sin(t)+p.y*cos(t))*0.6,0,1);}');"
        "gl.compileShader(vs);var fs=gl.createShader(gl.FRAGMENT_SHADER);"
        "gl.shaderSource(fs,'precision mediump float;varying float v;void main(){gl_FragColor=vec4(0.5+0.5*sin(v),0.3+0.5*cos(v*0.7),0.6+0.4*sin(v*1.3),1);}');"
        "gl.compileShader(fs);prog=gl.createProgram();gl.attachShader(prog,vs);gl.attachShader(prog,fs);gl.linkProgram(prog);"
        "var buf=gl.createBuffer();gl.bindBuffer(gl.ARRAY_BUFFER,buf);"
        "gl.bufferData(gl.ARRAY_BUFFER,new Float32Array([-0.5,-0.5,0.5,-0.5,-0.5,0.5,0.5,-0.5,0.5,0.5,-0.5,0.5]),gl.STATIC_DRAW);}"
        "var frames=0,t0=performance.now(),lastJ=0;"
        "function tick(t){frames++;if(gl){gl.viewport(0,0,1280,720);gl.clearColor(0,0,0,1);gl.clear(gl.COLOR_BUFFER_BIT);gl.useProgram(prog);"
        "var loc=gl.getUniformLocation(prog,'t');gl.uniform1f(loc,t/1000);"
        "var pl=gl.getAttribLocation(prog,'p');gl.enableVertexAttribArray(pl);gl.vertexAttribPointer(pl,2,gl.FLOAT,false,0,0);gl.drawArrays(gl.TRIANGLES,0,6);}"
        "var x=0;for(var i=0;i<1e6;i++)x+=Math.sqrt(i)*Math.sin(i*0.001);lastJ=x;"
        "if(frames%30===0){var e=performance.now()-t0;"
        "document.getElementById('stats').textContent='fps='+(frames*1000/e).toFixed(1)+' frames='+frames+' dom=100k j='+lastJ.toFixed(2);}"
        "requestAnimationFrame(tick);}requestAnimationFrame(tick);"
        "</script>";
    internalPageUrl_ = @"lethe://stress";
    [webView_ loadHTMLString:html baseURL:nil];
    [self updateTitle];
    [self updateAddress];
}

- (void)loadAddress:(NSString*)text {
    const std::string in = text.UTF8String ? text.UTF8String : "";
    const std::string normalized = lethe::normalizeAddressInput(in);
    if (normalized.empty() || normalized == "about:blank") {
        [self showNewTabPage];
        return;
    }
    NSURL* url = [NSURL URLWithString:@(normalized.c_str())];
    if (!url) {
        // Unparseable even after normalization: search it instead.
        const std::string q = lethe::normalizeAddressInput("? " + in);
        url = [NSURL URLWithString:@(q.c_str())];
    }
    if (url) [self loadURL:url];
}

- (void)loadURL:(NSURL*)url {
    internalPageUrl_ = nil;
    readerActive_ = NO;
    readerLoadPending_ = NO;
    [webView_ loadRequest:[NSURLRequest requestWithURL:url]];
}

- (void)showBlockPageForURL:(NSString*)url reason:(NSString*)reason {
    const std::string html = lethe::renderBlockPage(
        url.UTF8String ? url.UTF8String : "", reason.UTF8String ? reason.UTF8String : "");
    internalPageUrl_ = url;
    [webView_ loadHTMLString:@(html.c_str()) baseURL:nil];
    [self updateAddress];
}

- (void)showErrorPageForURL:(NSString*)url message:(NSString*)message {
    [self showErrorPageForURL:url message:message httpFallback:nil];
}

- (void)showErrorPageForURL:(NSString*)url message:(NSString*)message httpFallback:(NSString*)fallback {
    const std::string html = lethe::renderErrorPage(
        url.UTF8String ? url.UTF8String : "", message.UTF8String ? message.UTF8String : "",
        fallback.UTF8String ? fallback.UTF8String : "");
    internalPageUrl_ = url;
    [webView_ loadHTMLString:@(html.c_str()) baseURL:nil];
    [self updateAddress];
}

#pragma mark - Actions (menu + toolbar)

- (void)addressEntered:(id)sender {
    (void)sender;
    addressEditing_ = NO;
    [self loadAddress:addressField_.stringValue];
    [self.window makeFirstResponder:webView_];
}

- (void)focusAddressBar:(id)sender {
    (void)sender;
    [self.window makeFirstResponder:addressField_];
    [addressField_ selectText:nil];
}

- (void)goBack:(id)sender { (void)sender; [webView_ goBack]; }
- (void)goForward:(id)sender { (void)sender; [webView_ goForward]; }

- (void)goHome:(id)sender {
    (void)sender;
    if (!ctx_->homeUrl.empty()) [self loadAddress:@(ctx_->homeUrl.c_str())];
    else [self showNewTabPage];
}

- (void)reloadOrStop:(id)sender {
    if (webView_.loading) [self stopLoading:sender];
    else [self reloadPage:sender];
}

- (void)reloadPage:(id)sender {
    (void)sender;
    if (readerActive_ && readerSourceUrl_.length) {
        [self loadURL:[NSURL URLWithString:readerSourceUrl_]];
        return;
    }
    if (internalPageUrl_.length) {
        NSURL* u = [NSURL URLWithString:internalPageUrl_];
        if (u) { [self loadURL:u]; return; }
    }
    if (webView_.URL && ![webView_.URL.scheme isEqualToString:@"about"]) {
        [webView_ reload];
    }
}

- (void)stopLoading:(id)sender { (void)sender; [webView_ stopLoading]; }

- (void)newWindowForTab:(id)sender {
    (void)sender;
    LetheAppDelegate* app = (LetheAppDelegate*)NSApp.delegate;
    [app openTabWithURL:nil fromWindow:self.window webView:nil];
}

- (void)closeWholeWindow:(id)sender {
    (void)sender;
    NSArray<NSWindow*>* group = self.window.tabGroup.windows ?: @[ self.window ];
    for (NSWindow* w in [group copy]) [w close];
}

- (void)openDownloadsFolder:(id)sender {
    (void)sender;
    [[LetheDownloadsController shared] showPanel];
}

- (void)revealDownloads:(id)sender {
    (void)sender;
    NSURL* dir = [[NSFileManager defaultManager] URLsForDirectory:NSDownloadsDirectory
                                                        inDomains:NSUserDomainMask].firstObject;
    if (dir) [[NSWorkspace sharedWorkspace] openURL:dir];
}

- (void)showWebInspector:(id)sender {
    (void)sender;
    SEL sel = NSSelectorFromString(@"_openInspector");
    if ([webView_ respondsToSelector:sel]) {
        #pragma clang diagnostic push
        #pragma clang diagnostic ignored "-Warc-performSelector-leaks"
        [webView_ performSelector:sel];
        #pragma clang diagnostic pop
    }
}

- (void)printPage:(id)sender {
    (void)sender;
    NSPrintInfo* info = [[NSPrintInfo sharedPrintInfo] copy];
    info.horizontalPagination = NSPrintingPaginationModeFit;
    info.verticalPagination = NSPrintingPaginationModeAutomatic;
    NSPrintOperation* op = [webView_ printOperationWithPrintInfo:info];
    op.showsPrintPanel = YES;
    op.showsProgressPanel = YES;
    [op runOperationModalForWindow:self.window delegate:nil didRunSelector:nil contextInfo:nil];
}

- (void)zoomActual:(id)sender { (void)sender; webView_.pageZoom = 1.0; }
- (void)zoomIn:(id)sender { (void)sender; webView_.pageZoom = MIN(5.0, webView_.pageZoom * 1.1); }
- (void)zoomOut:(id)sender { (void)sender; webView_.pageZoom = MAX(0.25, webView_.pageZoom / 1.1); }

- (void)toggleReader:(id)sender {
    (void)sender;
    if (readerActive_) {
        if (readerSourceUrl_.length) [self loadURL:[NSURL URLWithString:readerSourceUrl_]];
        return;
    }
    NSURL* current = webView_.URL;
    NSString* scheme = current.scheme.lowercaseString;
    if (!current || !([scheme isEqualToString:@"http"] || [scheme isEqualToString:@"https"])) {
        NSBeep();
        return;
    }
    if (readerFetching_) return;
    NSString* source = current.absoluteString;
    readerFetching_ = YES;
    progress_.hidden = NO;
    progress_.doubleValue = 0.3;
    __weak BrowserWindowController* weakSelf = self;
    [gate_ fetchReaderForURL:source completion:^(NSString* html, NSString* finalUrl, NSString* error) {
        BrowserWindowController* self = weakSelf;
        if (!self) return;
        self->readerFetching_ = NO;
        self->progress_.hidden = YES;
        NSLog(@"[lethe] reader fetch %@: %@", source, html ? @"ok" : error);
        if (!html) {
            [self showErrorPageForURL:source
                              message:[NSString stringWithFormat:@"Reader view unavailable: %@", error]];
            return;
        }
        self->readerActive_ = YES;
        self->readerLoadPending_ = YES;
        self->readerSourceUrl_ = source;
        self->internalPageUrl_ = finalUrl ?: source;
        [self->webView_ loadHTMLString:html baseURL:[NSURL URLWithString:finalUrl ?: source]];
    }];
}

- (void)toggleBookmark:(id)sender {
    (void)sender;
    NSString* url = webView_.URL.absoluteString;
    if (!url.length) { NSBeep(); return; }
    NSString* title = webView_.title.length ? webView_.title : url;
    BOOL added = [[LetheBookmarks shared] toggleURL:url title:title];
    [self refreshBookmarkIcon];
    NSString* symbol = added ? @"bookmark.fill" : @"bookmark";
    NSImage* img = [NSImage imageWithSystemSymbolName:symbol
                          accessibilityDescription:added ? @"Bookmarked" : @"Bookmark"];
    bookmarkButton_.image = img;
}

- (void)refreshBookmarkIcon {
    NSString* url = webView_.URL.absoluteString;
    BOOL has = url.length && [[LetheBookmarks shared] containsURL:url];
    NSString* symbol = has ? @"bookmark.fill" : @"bookmark";
    bookmarkButton_.image = [NSImage imageWithSystemSymbolName:symbol
                              accessibilityDescription:has ? @"Bookmarked" : @"Bookmark"];
}

- (void)showFindBar:(id)sender {
    (void)sender;
    findBar_.hidden = NO;
    findBarHeight_.constant = 36;
    [self.window makeFirstResponder:findField_];
    [findField_ selectText:nil];
}

- (void)hideFindBar:(id)sender {
    (void)sender;
    findBar_.hidden = YES;
    findBarHeight_.constant = 0;
    findStatus_.stringValue = @"";
    [self.window makeFirstResponder:webView_];
}

- (void)findWithBackwards:(BOOL)backwards {
    NSString* term = findField_.stringValue;
    if (!term.length) { findStatus_.stringValue = @""; return; }
    WKFindConfiguration* cfg = [[WKFindConfiguration alloc] init];
    cfg.backwards = backwards;
    cfg.caseSensitive = NO;
    cfg.wraps = YES;
    __weak BrowserWindowController* weakSelf = self;
    [webView_ findString:term withConfiguration:cfg completionHandler:^(WKFindResult* result) {
        BrowserWindowController* self = weakSelf;
        if (!self) return;
        self->findStatus_.stringValue = result.matchFound ? @"" : @"Not found";
    }];
}

- (void)findNext:(id)sender {
    (void)sender;
    if (findBar_.hidden) { [self showFindBar:sender]; return; }
    [self findWithBackwards:NO];
}

- (void)findPrevious:(id)sender {
    (void)sender;
    if (findBar_.hidden) { [self showFindBar:sender]; return; }
    [self findWithBackwards:YES];
}

- (BOOL)validateMenuItem:(NSMenuItem*)item {
    const SEL a = item.action;
    if (a == @selector(goBack:)) return webView_.canGoBack;
    if (a == @selector(goForward:)) return webView_.canGoForward;
    if (a == @selector(stopLoading:)) return webView_.loading;
    if (a == @selector(toggleReader:)) {
        item.title = readerActive_ ? @"Leave Reader View" : @"Reader View";
        item.state = readerActive_ ? NSControlStateValueOn : NSControlStateValueOff;
        NSString* scheme = webView_.URL.scheme.lowercaseString;
        return readerActive_ || [scheme isEqualToString:@"http"] || [scheme isEqualToString:@"https"];
    }
    return YES;
}

#pragma mark - NSTextFieldDelegate (address + find)

- (void)controlTextDidBeginEditing:(NSNotification*)note {
    if (note.object == addressField_) addressEditing_ = YES;
}

- (void)controlTextDidEndEditing:(NSNotification*)note {
    if (note.object == addressField_) {
        addressEditing_ = NO;
        [self updateAddress];
    }
}

- (BOOL)control:(NSControl*)control textView:(NSTextView*)textView
    doCommandBySelector:(SEL)command {
    (void)textView;
    if (command == @selector(cancelOperation:)) {
        if (control == addressField_) {
            addressEditing_ = NO;
            [self updateAddress];
            [self.window makeFirstResponder:webView_];
            return YES;
        }
        if (control == findField_) { [self hideFindBar:nil]; return YES; }
    }
    if (control == findField_ && command == @selector(insertNewline:) &&
        ([NSEvent modifierFlags] & NSEventModifierFlagShift)) {
        [self findWithBackwards:YES];
        return YES;
    }
    if (control == addressField_ && command == @selector(insertNewline:)) {
        // NSTextField does not always fire its action on Return when the
        // cell is configured for single-line / scrollable / truncating
        // mode. Handle the key here so Enter reliably submits the address.
        [self addressEntered:nil];
        return YES;
    }
    return NO;
}

#pragma mark - WKNavigationDelegate

- (void)webView:(WKWebView*)webView
    decidePolicyForNavigationAction:(WKNavigationAction*)action
                    decisionHandler:(void (^)(WKNavigationActionPolicy))handler {
    (void)webView;
    NSURL* url = action.request.URL;
    NSString* scheme = url.scheme.lowercaseString ?: @"";
    const BOOL isMainFrame = action.targetFrame ? action.targetFrame.isMainFrame : YES;

    if (@available(macOS 11.3, *)) {
        if (action.shouldPerformDownload) { handler(WKNavigationActionPolicyDownload); return; }
    }
    if ([scheme isEqualToString:@"about"] || [scheme isEqualToString:@"blob"]) {
        handler(WKNavigationActionPolicyAllow);
        return;
    }
    if ([scheme isEqualToString:@"data"]) {
        // Top-level data: navigations are a phishing vector (Chrome blocks them too).
        handler(isMainFrame ? WKNavigationActionPolicyCancel : WKNavigationActionPolicyAllow);
        return;
    }
    if ([scheme isEqualToString:@(lethe::kHttpFallbackScheme)]) {
        // Link on our own error page: the user chose plain http for this
        // host after the https upgrade failed. Allow-list, then load.
        handler(WKNavigationActionPolicyCancel);
        const std::string target = lethe::parseHttpFallbackActionUrl(url.absoluteString.UTF8String ?: "");
        if (!target.empty() && !oblivion_) {
            LetheAppDelegate* app = (LetheAppDelegate*)NSApp.delegate;
            [app allowHttpForHost:@(lethe::urlHost(target).c_str())];
            NSLog(@"[lethe] https-first: user allowed plain http for %s", lethe::urlHost(target).c_str());
            httpsUpgradedFrom_ = nil;
            [webView_ loadRequest:[NSURLRequest requestWithURL:[NSURL URLWithString:@(target.c_str())]]];
        }
        return;
    }
    if (!([scheme isEqualToString:@"http"] || [scheme isEqualToString:@"https"])) {
        NSLog(@"[lethe] refused non-web scheme: %@", url.absoluteString);
        handler(WKNavigationActionPolicyCancel);
        if (isMainFrame && action.navigationType == WKNavigationTypeLinkActivated) {
            [self showBlockPageForURL:url.absoluteString
                               reason:[NSString stringWithFormat:@"scheme '%@' is not allowed", scheme]];
        }
        return;
    }
    if (!action.targetFrame) {
        // target=_blank without a window.open path: open beside this tab.
        LetheAppDelegate* app = (LetheAppDelegate*)NSApp.delegate;
        [app openTabWithURL:url.absoluteString fromWindow:self.window webView:nil];
        handler(WKNavigationActionPolicyCancel);
        return;
    }
    if (oblivion_ && [scheme isEqualToString:@"http"]) {
        // Oblivion is https-only: no upgrade dance, no fallback, for every
        // frame. Plaintext never leaves an Oblivion window.
        handler(WKNavigationActionPolicyCancel);
        NSLog(@"[lethe] oblivion refused plaintext %@", url.absoluteString);
        if (isMainFrame)
            [self showBlockPageForURL:url.absoluteString
                               reason:@"Oblivion windows are https-only: unencrypted (http://) pages are never loaded"];
        return;
    }
    if (isMainFrame && ctx_->httpsFirst && [scheme isEqualToString:@"http"]) {
        // HTTPS-first: try the encrypted version before ever sending
        // plaintext. IP literals, localhost, .local and custom ports are
        // exempt; a host the user explicitly allowed stays plain.
        const std::string upgraded = lethe::httpsUpgradeCandidate(url.absoluteString.UTF8String ?: "");
        LetheAppDelegate* app = (LetheAppDelegate*)NSApp.delegate;
        if (!upgraded.empty() && ![app isHttpAllowedForHost:url.host]) {
            handler(WKNavigationActionPolicyCancel);
            httpsUpgradedFrom_ = url.absoluteString;
            NSLog(@"[lethe] https-first: %@ -> %s", url.absoluteString, upgraded.c_str());
            [webView_ loadRequest:[NSURLRequest requestWithURL:[NSURL URLWithString:@(upgraded.c_str())]]];
            return;
        }
    }
    NSString* target = url.absoluteString;
    __weak BrowserWindowController* weakSelf = self;
    [gate_ checkURL:target completion:^(NSString* reason) {
        if (reason.length == 0) { handler(WKNavigationActionPolicyAllow); return; }
        handler(WKNavigationActionPolicyCancel);
        NSLog(@"[lethe] policy refused %@: %@", target, reason);
        BrowserWindowController* self = weakSelf;
        if (self && isMainFrame) [self showBlockPageForURL:target reason:reason];
    }];
}

- (void)webView:(WKWebView*)webView
    decidePolicyForNavigationResponse:(WKNavigationResponse*)response
                      decisionHandler:(void (^)(WKNavigationResponsePolicy))handler {
    (void)webView;
    if (!response.canShowMIMEType) {
        if (@available(macOS 11.3, *)) { handler(WKNavigationResponsePolicyDownload); return; }
        handler(WKNavigationResponsePolicyCancel);
        return;
    }
    handler(WKNavigationResponsePolicyAllow);
}

- (void)webView:(WKWebView*)webView didStartProvisionalNavigation:(WKNavigation*)nav {
    (void)webView; (void)nav;
    if (readerLoadPending_) {
        readerLoadPending_ = NO;
    } else if (!internalPageUrl_ || webView_.URL.absoluteString.length > 0) {
        readerActive_ = NO;
        if (webView_.URL && ![webView_.URL.scheme isEqualToString:@"about"]) internalPageUrl_ = nil;
    }
    progress_.hidden = NO;
    [self updateAddress];
}

- (void)webView:(WKWebView*)webView
    didReceiveServerRedirectForProvisionalNavigation:(WKNavigation*)nav {
    (void)webView; (void)nav;
    [self updateAddress];
}

- (void)webView:(WKWebView*)webView didCommitNavigation:(WKNavigation*)nav {
    (void)webView; (void)nav;
    [self updateAddress];
}

- (void)webView:(WKWebView*)webView didFinishNavigation:(WKNavigation*)nav {
    (void)webView; (void)nav;
    httpsUpgradedFrom_ = nil;
    [self updateTitle];
    [self updateAddress];
    NSString* url = webView_.URL.absoluteString;
    if (url.length && [url hasPrefix:@"http"]) {
        [[LetheHistory shared] recordVisit:url title:webView_.title ?: url];
    }
}

- (void)handleLoadError:(NSError*)error {
    if ([error.domain isEqualToString:NSURLErrorDomain] && error.code == NSURLErrorCancelled) return;
    // 102 = WebKitErrorFrameLoadInterruptedByPolicyChange (download / policy cancel)
    if ([error.domain isEqualToString:@"WebKitErrorDomain"] && error.code == 102) return;
    // The failing URL: the error's own key when present; otherwise, for a
    // provisional failure of an HTTPS-first upgrade, the upgraded URL (the
    // view's URL still points at the previous page then).
    NSString* upgraded = nil;
    if (httpsUpgradedFrom_.length) {
        const std::string expected = lethe::httpsUpgradeCandidate(httpsUpgradedFrom_.UTF8String ?: "");
        if (!expected.empty()) upgraded = @(expected.c_str());
    }
    NSString* failing = error.userInfo[NSURLErrorFailingURLStringErrorKey]
        ?: upgraded ?: webView_.URL.absoluteString ?: @"";
    NSLog(@"[lethe] load failed %@: %@ (%ld)", failing, error.localizedDescription, (long)error.code);
    // HTTPS-first upgrade that did not answer: offer the plain URL once,
    // explicitly, on the error page. Never silently.
    NSString* fallback = nil;
    if (upgraded) {
        NSString* failingHost = [NSURL URLWithString:failing].host ?: @"";
        NSString* upgradedHost = [NSURL URLWithString:upgraded].host ?: @"";
        if (failingHost.length && [failingHost isEqualToString:upgradedHost]) fallback = httpsUpgradedFrom_;
    }
    httpsUpgradedFrom_ = nil;
    [self showErrorPageForURL:failing message:error.localizedDescription httpFallback:fallback];
}

- (void)webView:(WKWebView*)webView didFailProvisionalNavigation:(WKNavigation*)nav
      withError:(NSError*)error {
    (void)webView; (void)nav;
    [self handleLoadError:error];
}

- (void)webView:(WKWebView*)webView didFailNavigation:(WKNavigation*)nav withError:(NSError*)error {
    (void)webView; (void)nav;
    [self handleLoadError:error];
}

- (void)webViewWebContentProcessDidTerminate:(WKWebView*)webView {
    NSLog(@"[lethe] web content process terminated; reloading");
    [webView reload];
}

- (void)webView:(WKWebView*)webView
    didReceiveAuthenticationChallenge:(NSURLAuthenticationChallenge*)challenge
                    completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition,
                                                NSURLCredential*))handler {
    (void)webView;
    NSString* method = challenge.protectionSpace.authenticationMethod;
    if ([method isEqualToString:NSURLAuthenticationMethodHTTPBasic] ||
        [method isEqualToString:NSURLAuthenticationMethodHTTPDigest]) {
        if (challenge.previousFailureCount > 1) {
            handler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
            return;
        }
        [self promptCredentialsForChallenge:challenge completion:handler];
        return;
    }
    // Server trust: WebKit performs system certificate validation itself.
    handler(NSURLSessionAuthChallengePerformDefaultHandling, nil);
}

- (void)promptCredentialsForChallenge:(NSURLAuthenticationChallenge*)challenge
                           completion:(void (^)(NSURLSessionAuthChallengeDisposition,
                                                NSURLCredential*))handler {
    NSAlert* alert = [[NSAlert alloc] init];
    alert.messageText = [NSString stringWithFormat:@"Sign in to %@",
                         challenge.protectionSpace.host];
    alert.informativeText = challenge.protectionSpace.realm ?: @"";
    [alert addButtonWithTitle:@"Sign In"];
    [alert addButtonWithTitle:@"Cancel"];
    NSStackView* stack = [[NSStackView alloc] initWithFrame:NSMakeRect(0, 0, 260, 56)];
    stack.orientation = NSUserInterfaceLayoutOrientationVertical;
    NSTextField* user = [[NSTextField alloc] initWithFrame:NSMakeRect(0, 0, 260, 24)];
    user.placeholderString = @"Username";
    NSSecureTextField* pass = [[NSSecureTextField alloc] initWithFrame:NSMakeRect(0, 0, 260, 24)];
    pass.placeholderString = @"Password";
    [stack addView:user inGravity:NSStackViewGravityTop];
    [stack addView:pass inGravity:NSStackViewGravityTop];
    alert.accessoryView = stack;
    [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse r) {
        if (r != NSAlertFirstButtonReturn) {
            handler(NSURLSessionAuthChallengeCancelAuthenticationChallenge, nil);
            return;
        }
        NSURLCredential* cred = [NSURLCredential credentialWithUser:user.stringValue
                                                           password:pass.stringValue
                                                        persistence:NSURLCredentialPersistenceForSession];
        handler(NSURLSessionAuthChallengeUseCredential, cred);
    }];
}

#pragma mark - Downloads

- (void)webView:(WKWebView*)webView navigationAction:(WKNavigationAction*)action
    didBecomeDownload:(WKDownload*)download {
    (void)webView; (void)action;
    [self trackDownload:download];
}

- (void)webView:(WKWebView*)webView navigationResponse:(WKNavigationResponse*)response
    didBecomeDownload:(WKDownload*)download {
    (void)webView; (void)response;
    [self trackDownload:download];
}

- (void)trackDownload:(WKDownload*)download {
    download.delegate = self;
    [downloads_ addObject:download];
    LetheDownloadItem* item = [[LetheDownloadItem alloc] init];
    item.filename = download.originalRequest.URL.lastPathComponent ?: @"download";
    item.sourceURL = download.originalRequest.URL.absoluteString;
    item.bytesReceived = 0;
    item.bytesExpected = -1;
    item.state = LetheDownloadStateRunning;
    objc_setAssociatedObject(download, kLetheDownloadItemKey, item, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    [[LetheDownloadsController shared] addItem:item];
    NSLog(@"[lethe] download started: %@", download.originalRequest.URL.absoluteString);
}

- (void)download:(WKDownload*)download
    decideDestinationUsingResponse:(NSURLResponse*)response
                 suggestedFilename:(NSString*)suggestedFilename
                 completionHandler:(void (^)(NSURL*))handler {
    (void)download; (void)response;
    NSURL* dir = [[NSFileManager defaultManager] URLsForDirectory:NSDownloadsDirectory
                                                        inDomains:NSUserDomainMask].firstObject;
    if (!dir) { handler(nil); return; }
    NSString* name = suggestedFilename.length ? suggestedFilename : @"download";
    name = [name stringByReplacingOccurrencesOfString:@"/" withString:@"_"];
    NSURL* dest = [dir URLByAppendingPathComponent:name];
    NSString* base = name.stringByDeletingPathExtension;
    NSString* ext = name.pathExtension;
    for (int i = 1; [dest checkResourceIsReachableAndReturnError:nil] && i < 1000; i++) {
        NSString* candidate = ext.length
            ? [NSString stringWithFormat:@"%@ (%d).%@", base, i, ext]
            : [NSString stringWithFormat:@"%@ (%d)", base, i];
        dest = [dir URLByAppendingPathComponent:candidate];
    }
    LetheDownloadItem* item = objc_getAssociatedObject(download, kLetheDownloadItemKey);
    if (item) { item.destination = dest; item.filename = dest.lastPathComponent; [[LetheDownloadsController shared] updateItem:item]; }
    handler(dest);
}

- (void)downloadDidFinish:(WKDownload*)download {
    [downloads_ removeObject:download];
    LetheDownloadItem* item = objc_getAssociatedObject(download, kLetheDownloadItemKey);
    if (item) { item.state = LetheDownloadStateFinished; item.bytesReceived = item.bytesExpected > 0 ? item.bytesExpected : item.bytesReceived; [[LetheDownloadsController shared] updateItem:item]; }
    NSLog(@"[lethe] download finished: %@", download.originalRequest.URL.absoluteString);
    [NSApp requestUserAttention:NSInformationalRequest];
}

- (void)download:(WKDownload*)download
   didWriteData:(NSData*)data
 totalBytesWritten:(int64_t)totalBytesWritten
 totalBytesExpectedToWrite:(int64_t)totalBytesExpectedToWrite {
    (void)data;
    LetheDownloadItem* item = objc_getAssociatedObject(download, kLetheDownloadItemKey);
    if (item) { item.bytesReceived = totalBytesWritten; item.bytesExpected = totalBytesExpectedToWrite; [[LetheDownloadsController shared] updateItem:item]; }
}

- (void)download:(WKDownload*)download didFailWithError:(NSError*)error resumeData:(NSData*)resumeData {
    (void)resumeData;
    [downloads_ removeObject:download];
    NSLog(@"[lethe] download failed: %@", error.localizedDescription);
    NSAlert* alert = [[NSAlert alloc] init];
    alert.messageText = @"Download failed";
    alert.informativeText = error.localizedDescription ?: @"";
    [alert beginSheetModalForWindow:self.window completionHandler:nil];
}

#pragma mark - WKUIDelegate

- (WKWebView*)webView:(WKWebView*)webView
    createWebViewWithConfiguration:(WKWebViewConfiguration*)configuration
               forNavigationAction:(WKNavigationAction*)action
                    windowFeatures:(WKWindowFeatures*)features {
    (void)webView; (void)action; (void)features;
    WKWebView* child = [[WKWebView alloc] initWithFrame:NSZeroRect configuration:configuration];
    LetheAppDelegate* app = (LetheAppDelegate*)NSApp.delegate;
    BrowserWindowController* c = [app openTabWithURL:nil fromWindow:self.window webView:child];
    return c.webView;
}

- (void)webView:(WKWebView*)webView
    requestMediaCapturePermissionForOrigin:(WKSecurityOrigin*)origin
    initiatedByFrame:(WKFrameInfo*)frame
                              type:(WKMediaCaptureType)type
                   decisionHandler:(void (^)(WKPermissionDecision))decisionHandler {
    (void)webView; (void)frame;
    NSString* kind = @"camera";
    if (type & WKMediaCaptureTypeMicrophone) kind = @"microphone";
    if ((type & WKMediaCaptureTypeCamera) && (type & WKMediaCaptureTypeMicrophone)) kind = @"camera and microphone";
    LethePermissionRequest* req = [[LethePermissionRequest alloc]
        initWithHost:origin.host type:@"media" detail:kind];
    [[LethePermissions shared] promptForRequest:req fromWindow:self.window remember:YES
                                         allow:^(BOOL allow) {
        decisionHandler(allow ? WKPermissionDecisionGrant : WKPermissionDecisionDeny);
    }];
}

- (void)webView:(WKWebView*)webView
    requestGeolocationPermissionForOrigin:(WKSecurityOrigin*)origin
    initiatedByFrame:(WKFrameInfo*)frame
                        decisionHandler:(void (^)(WKPermissionDecision))decisionHandler {
    (void)webView; (void)frame;
    LethePermissionRequest* req = [[LethePermissionRequest alloc]
        initWithHost:origin.host type:@"geolocation" detail:@"location"];
    [[LethePermissions shared] promptForRequest:req fromWindow:self.window remember:YES
                                         allow:^(BOOL allow) {
        decisionHandler(allow ? WKPermissionDecisionGrant : WKPermissionDecisionDeny);
    }];
}

- (void)webViewDidClose:(WKWebView*)webView {
    (void)webView;
    [self.window performClose:nil];
}

- (void)webView:(WKWebView*)webView runJavaScriptAlertPanelWithMessage:(NSString*)message
    initiatedByFrame:(WKFrameInfo*)frame completionHandler:(void (^)(void))handler {
    (void)webView;
    NSAlert* alert = [[NSAlert alloc] init];
    alert.messageText = frame.securityOrigin.host.length
        ? [NSString stringWithFormat:@"%@ says", frame.securityOrigin.host] : @"This page says";
    alert.informativeText = message ?: @"";
    [alert addButtonWithTitle:@"OK"];
    [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse r) {
        (void)r; handler();
    }];
}

- (void)webView:(WKWebView*)webView runJavaScriptConfirmPanelWithMessage:(NSString*)message
    initiatedByFrame:(WKFrameInfo*)frame completionHandler:(void (^)(BOOL))handler {
    (void)webView;
    NSAlert* alert = [[NSAlert alloc] init];
    alert.messageText = frame.securityOrigin.host.length
        ? [NSString stringWithFormat:@"%@ says", frame.securityOrigin.host] : @"This page says";
    alert.informativeText = message ?: @"";
    [alert addButtonWithTitle:@"OK"];
    [alert addButtonWithTitle:@"Cancel"];
    [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse r) {
        handler(r == NSAlertFirstButtonReturn);
    }];
}

- (void)webView:(WKWebView*)webView runJavaScriptTextInputPanelWithPrompt:(NSString*)prompt
    defaultText:(NSString*)defaultText initiatedByFrame:(WKFrameInfo*)frame
    completionHandler:(void (^)(NSString*))handler {
    (void)webView;
    NSAlert* alert = [[NSAlert alloc] init];
    alert.messageText = frame.securityOrigin.host.length
        ? [NSString stringWithFormat:@"%@ asks", frame.securityOrigin.host] : @"This page asks";
    alert.informativeText = prompt ?: @"";
    [alert addButtonWithTitle:@"OK"];
    [alert addButtonWithTitle:@"Cancel"];
    NSTextField* input = [[NSTextField alloc] initWithFrame:NSMakeRect(0, 0, 280, 24)];
    input.stringValue = defaultText ?: @"";
    alert.accessoryView = input;
    [alert beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse r) {
        handler(r == NSAlertFirstButtonReturn ? input.stringValue : nil);
    }];
}

- (void)webView:(WKWebView*)webView
    runOpenPanelWithParameters:(WKOpenPanelParameters*)parameters
              initiatedByFrame:(WKFrameInfo*)frame
             completionHandler:(void (^)(NSArray<NSURL*>*))handler {
    (void)webView; (void)frame;
    NSOpenPanel* panel = [NSOpenPanel openPanel];
    panel.allowsMultipleSelection = parameters.allowsMultipleSelection;
    panel.canChooseDirectories = parameters.allowsDirectories;
    panel.canChooseFiles = YES;
    [panel beginSheetModalForWindow:self.window completionHandler:^(NSModalResponse r) {
        handler(r == NSModalResponseOK ? panel.URLs : nil);
    }];
}

#pragma mark - NSWindowDelegate

- (void)windowWillClose:(NSNotification*)note {
    (void)note;
    [self stopObserving];
    [webView_ stopLoading];
    webView_.navigationDelegate = nil;
    webView_.UIDelegate = nil;
    LetheAppDelegate* app = (LetheAppDelegate*)NSApp.delegate;
    [app controllerDidClose:self];
    if (oblivion_ && dataStore_) {
        // Last tab sharing this store gone -> wipe it explicitly. The store
        // is in-memory already; this closes the window of time between
        // "window closed" and "object released" and makes the guarantee
        // independent of WebKit's internal lifetime.
        BOOL othersAlive = NO;
        for (BrowserWindowController* c in app.controllers)
            if (c != self && c.oblivion && c.dataStore == dataStore_) othersAlive = YES;
        if (!othersAlive) {
            WKWebsiteDataStore* store = dataStore_;
            [store removeDataOfTypes:[WKWebsiteDataStore allWebsiteDataTypes]
                       modifiedSince:[NSDate distantPast]
                   completionHandler:^{ NSLog(@"[lethe] oblivion store wiped"); }];
        }
        dataStore_ = nil;
    }
}

- (void)dealloc {
    [self stopObserving];
    // Drop the per-BWC script message handlers from the shared controller
    // so the names can be reused by another tab.
    if (webView_ && messageHandlerNames_.count == 2) {
        WKUserContentController* uc = webView_.configuration.userContentController;
        [uc removeScriptMessageHandlerForName:messageHandlerNames_[0]];
        [uc removeScriptMessageHandlerForName:messageHandlerNames_[1]];
    }
}


- (void)userContentController:(WKUserContentController *)uc
 didReceiveScriptMessage:(WKScriptMessage *)msg {
    NSDictionary* body = [msg.body isKindOfClass:[NSDictionary class]] ? msg.body : nil;
    NSString* op = body[@"op"];
    if ([msg.name isEqualToString:messageHandlerNames_.firstObject]) {
        // bookmarks handler
        NSString* url = body[@"url"];
        if ([op isEqualToString:@"remove"] && url.length) {
            [[LetheBookmarks shared] removeURL:url];
            if ([internalPageUrl_ isEqualToString:@"lethe://bookmarks"]) {
                [self renderBookmarksPage];
            }
        }
    } else if ([msg.name isEqualToString:messageHandlerNames_.lastObject]) {
        // perms handler
        NSString* host = body[@"host"];
        NSString* type = body[@"type"];
        if ([op isEqualToString:@"clear"] && host.length && type.length) {
            [[LethePermissions shared] clearforHost:host type:type];
            if ([internalPageUrl_ isEqualToString:@"lethe://permissions"]) {
                [self renderPermissionsPage];
            }
        }
    }
}
@end
