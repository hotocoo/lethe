// BrowserWindowController.mm - one browser tab: chrome + WKWebView
//
// Tabs are native NSWindow tabs (one window per tab, grouped by
// tabbingIdentifier), so ⌘T/⌘W/⌃⇥, drag-to-reorder and "Move Tab to New
// Window" come from AppKit and behave like every other Mac browser.

#import "ui/mac/LetheShell.h"

#include <string>

#include "browser/url_input.h"
#include "renderer/page_templates.h"

static void* const kObserverContext = (void*)&kObserverContext;
static NSString* const kTabbingIdentifier = @"org.aletheia.lethe.browser";
static const CGFloat kChromeHeight = 44.0;

@interface BrowserWindowController () <WKNavigationDelegate, WKUIDelegate,
                                       WKDownloadDelegate, NSWindowDelegate,
                                       NSTextFieldDelegate> {
    NSString* httpsUpgradedFrom_;   // http URL being tried as https (HTTPS-first)
    lethe::ShellContext* ctx_;
    LethePolicyGate* gate_;
    WKWebView* webView_;
    NSTextField* addressField_;
    NSImageView* lockIcon_;
    NSButton* backButton_;
    NSButton* forwardButton_;
    NSButton* reloadButton_;
    NSButton* readerButton_;
    NSProgressIndicator* progress_;
    NSView* findBar_;
    NSTextField* findField_;
    NSTextField* findStatus_;
    NSLayoutConstraint* findBarHeight_;
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

@synthesize webView = webView_;
@synthesize addressField = addressField_;
@synthesize readerActive = readerActive_;

- (BOOL)busy { return webView_.loading || readerFetching_; }

#pragma mark - Construction

- (instancetype)initWithContext:(lethe::ShellContext*)ctx
                           gate:(LethePolicyGate*)gate
                        webView:(WKWebView*)existingWebView {
    NSWindow* window = [[NSWindow alloc]
        initWithContentRect:NSMakeRect(0, 0, 1280, 860)
                  styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                            NSWindowStyleMaskMiniaturizable | NSWindowStyleMaskResizable
                    backing:NSBackingStoreBuffered
                      defer:NO];
    if ((self = [super initWithWindow:window])) {
        ctx_ = ctx;
        gate_ = gate;
        downloads_ = [NSMutableArray array];
        window.title = @"New Tab";
        window.releasedWhenClosed = NO;
        window.tabbingMode = NSWindowTabbingModePreferred;
        window.tabbingIdentifier = kTabbingIdentifier;
        window.minSize = NSMakeSize(480, 320);
        window.delegate = self;
        [window center];
        [window setFrameAutosaveName:@"LetheBrowserWindow"];

        if (existingWebView) {
            webView_ = existingWebView;
        } else {
            LetheAppDelegate* app = (LetheAppDelegate*)NSApp.delegate;
            webView_ = [[WKWebView alloc] initWithFrame:NSZeroRect
                                          configuration:[app webViewConfiguration]];
        }
        webView_.navigationDelegate = self;
        webView_.UIDelegate = self;
        webView_.allowsBackForwardNavigationGestures = YES;
        webView_.allowsMagnification = YES;
        if (ctx_->cfg.userAgentMode == "stealth") {
            webView_.customUserAgent = @(lethe::stealthUserAgentString());
        }
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
        backButton_, forwardButton_, reloadButton_, lockIcon_, addressField_, readerButton_ ]];
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
    [webView_ loadHTMLString:@(lethe::renderNewTabPage().c_str()) baseURL:nil];
    [self updateTitle];
    [self updateAddress];
    [self focusAddressBar:nil];
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
    NSURL* dir = [[NSFileManager defaultManager] URLsForDirectory:NSDownloadsDirectory
                                                        inDomains:NSUserDomainMask].firstObject;
    if (dir) [[NSWorkspace sharedWorkspace] openURL:dir];
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
        if (!target.empty()) {
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
    handler(dest);
}

- (void)downloadDidFinish:(WKDownload*)download {
    [downloads_ removeObject:download];
    NSLog(@"[lethe] download finished: %@", download.originalRequest.URL.absoluteString);
    [NSApp requestUserAttention:NSInformationalRequest];
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
}

- (void)dealloc {
    [self stopObserving];
}

@end
