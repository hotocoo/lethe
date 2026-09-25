#import <Cocoa/Cocoa.h>

#include "app/cef_chrome.h"
#include "browser/url_input.h"
#include "renderer/page_templates.h"

#import "ui/mac/LethePreferences.h"
#import "ui/mac/LetheBookmarks.h"
#import "ui/mac/LetheSettings.h"
#import "ui/mac/LetheDesign.h"
#import "ui/mac/LetheOmnibox.h"

#include <iostream>
#include <cmath>

// Keep the browser chrome compact enough that the content viewport dominates
// the window, while still giving every control a comfortable 30pt target.
// AppKit's unified-compact titlebar already contributes the native tab strip;
// duplicating vertical chrome here only steals renderer pixels.
static const CGFloat kToolbarHeight = 48.0;
static const CGFloat kChromeHeight = kToolbarHeight;
static const CGFloat kControl = 30.0;
static const CGFloat kToolbarHorizontalInset = 12.0;
static const CGFloat kToolbarVerticalInset = 9.0;
static const CGFloat kControlGap = 4.0;
static const CGFloat kGroupGap = 12.0;
static const CGFloat kAddressMinWidth = 240.0;
static const CGFloat kAddressMaxWidth = 760.0;

// Focus feedback stays local to the address field. This avoids invalidating
// the whole chrome row when focus changes, while keeping keyboard focus
// obvious without a heavy native bezel.
@interface LetheCefAddressField : NSTextField
@end

@implementation LetheCefAddressField
- (BOOL)becomeFirstResponder {
    BOOL result = [super becomeFirstResponder];
    if (result) {
        NSView* pill = self.superview;
        pill.wantsLayer = YES;
        pill.layer.borderWidth = 1.0;
        pill.layer.borderColor = LetheAccentColor().CGColor;
    }
    return result;
}

- (BOOL)resignFirstResponder {
    BOOL result = [super resignFirstResponder];
    if (result) {
        NSView* pill = self.superview;
        pill.wantsLayer = YES;
        pill.layer.borderWidth = 1.0;
        pill.layer.borderColor = [NSColor separatorColor].CGColor;
    }
    return result;
}
@end

@class LetheCefChromeController;
// The controller owns all AppKit targets for the browser chrome. A raw C++
// pointer does not retain an Objective-C object under ARC, so the previous
// unordered_map let the controller deallocate as soon as Attach returned.
// That left the controls rendered but with dead targets (notably Settings).
static NSMutableDictionary<NSNumber*, LetheCefChromeController*>* g_chrome;
static void LayoutChromeControls(LetheCefChromeController* controller,
                                 NSView* row, NSButton* back, NSButton* forward,
                                 NSButton* reload, NSButton* settings);
namespace { void ShowCefSettings(); }


@interface LetheCefChromeView : NSView
@end

@implementation LetheCefChromeView
- (BOOL)isFlipped { return YES; }
- (void)drawRect:(NSRect)dirtyRect {
    [super drawRect:dirtyRect];
    // A single bottom hairline separates browser chrome from content without
    // boxing the entire toolbar. Drawing it here avoids another separator
    // view and keeps the visual boundary pixel-crisp on Retina displays.
    [[NSColor separatorColor] setFill];
    NSRect line = NSMakeRect(0, NSMaxY(self.bounds) - 1.0,
                             self.bounds.size.width, 1.0);
    NSRectFillUsingOperation(NSIntersectionRect(line, dirtyRect),
                             NSCompositingOperationSourceOver);
}
@end

// Keep hover feedback local to each control. It changes only the button's
// layer and never invalidates the toolbar row, so mouse movement cannot cause
// a layout pass or touch the CEF renderer.
@interface LetheCefChromeButton : NSButton
@end

@implementation LetheCefChromeButton {
    NSTrackingArea* trackingArea_;
}

- (BOOL)becomeFirstResponder {
    BOOL result = [super becomeFirstResponder];
    if (result) {
        self.wantsLayer = YES;
        self.layer.borderWidth = 1.0;
        self.layer.borderColor = LetheAccentColor().CGColor;
        self.layer.cornerRadius = 7.0;
    }
    return result;
}

- (BOOL)resignFirstResponder {
    BOOL result = [super resignFirstResponder];
    if (result) {
        self.layer.borderWidth = 0.0;
        self.layer.backgroundColor = [NSColor clearColor].CGColor;
    }
    return result;
}

- (void)updateTrackingAreas {
    if (trackingArea_) [self removeTrackingArea:trackingArea_];
    trackingArea_ = [[NSTrackingArea alloc]
        initWithRect:self.bounds
             options:NSTrackingMouseEnteredAndExited | NSTrackingActiveInKeyWindow
               owner:self
            userInfo:nil];
    [self addTrackingArea:trackingArea_];
    [super updateTrackingAreas];
}

- (void)mouseEntered:(NSEvent*)event {
    (void)event;
    self.contentTintColor = [NSColor labelColor];
    self.wantsLayer = YES;
    self.layer.backgroundColor = [NSColor colorWithWhite:0.5 alpha:0.10].CGColor;
    self.layer.cornerRadius = 7.0;
}

- (void)mouseDown:(NSEvent*)event {
    self.wantsLayer = YES;
    self.layer.backgroundColor = [NSColor colorWithWhite:0.5 alpha:0.16].CGColor;
    self.layer.cornerRadius = 7.0;
    [super mouseDown:event];
}

- (void)mouseExited:(NSEvent*)event {
    (void)event;
    self.contentTintColor = [NSColor labelColor];
    self.layer.backgroundColor = [NSColor clearColor].CGColor;
}
@end

@interface LetheCefChromeRow : NSView
@property(nonatomic, weak) NSButton* backButton;
@property(nonatomic, weak) NSButton* forwardButton;
@property(nonatomic, weak) NSButton* reloadButton;
@property(nonatomic, weak) NSButton* readerButton;
@property(nonatomic, weak) NSButton* bookmarkButton;
@property(nonatomic, weak) NSTextField* address;
@property(nonatomic, weak) NSView* addressPill;
@property(nonatomic, weak) NSImageView* securityIcon;
@property(nonatomic, weak) NSButton* settingsButton;
@end

@implementation LetheCefChromeRow
- (BOOL)isFlipped { return YES; }

- (void)layout {
    [super layout];
    const CGFloat w = self.bounds.size.width;
    const CGFloat h = self.bounds.size.height;
    const CGFloat control = kControl;
    // Keep the chrome usable all the way down to the window's 480pt minimum.
    // Chrome-like browsers progressively remove secondary actions rather than
    // allowing controls to overlap the omnibox. Settings remains the stable
    // final action at every width.
    const BOOL compact = w < 760.0;
    const BOOL veryCompact = w < 570.0;
    self.readerButton.hidden = compact;
    self.bookmarkButton.hidden = compact;
    self.forwardButton.hidden = veryCompact;

    // Derive the left cluster from the controls that are actually visible.
    // The old fixed third-slot calculation left an 8pt collision window at
    // the smallest width because Reload kept its third position after
    // Forward was hidden. Keep every visible control in a contiguous cluster
    // before calculating the flexible omnibox region.
    const CGFloat visibleNavCount = (veryCompact ? 2.0 : 3.0);
    const CGFloat navWidth = visibleNavCount * control +
        MAX(0.0, visibleNavCount - 1.0) * kControlGap;
    const CGFloat visibleActionCount = compact ? 1.0 : 3.0;
    const CGFloat actionsWidth = visibleActionCount * control +
        MAX(0.0, visibleActionCount - 1.0) * kControlGap;
    // Keep the first/last controls off the titlebar edges.  The previous
    // layout defined the inset token but started the clusters at x=0 and
    // w-control, which looked cramped beside the traffic lights and was
    // noticeably less balanced than Chrome at compact widths.
    const CGFloat leftInset = kToolbarHorizontalInset;
    const CGFloat rightInset = kToolbarHorizontalInset;
    const CGFloat leftBoundary = leftInset + navWidth + kGroupGap;
    const CGFloat rightBoundary = w - rightInset - actionsWidth - kGroupGap;
    const CGFloat available = MAX(0.0, rightBoundary - leftBoundary);
    const CGFloat minAddress = compact ? 180.0 : kAddressMinWidth;
    CGFloat addressWidth = MIN(kAddressMaxWidth, available);
    if (available >= minAddress)
        addressWidth = MIN(kAddressMaxWidth, MAX(minAddress, available * 0.68));
    const CGFloat addressX = leftBoundary + MAX(0.0, (available - addressWidth) * 0.5);
    const CGFloat y = MAX(0.0, (h - control) * 0.5);

    self.backButton.frame = NSMakeRect(leftInset, y, control, control);
    const CGFloat forwardX = leftInset + control + kControlGap;
    self.forwardButton.frame = NSMakeRect(forwardX, y, control, control);
    self.reloadButton.frame = NSMakeRect(veryCompact ? forwardX :
                                         leftInset + 2.0 * (control + kControlGap),
                                         y, control, control);
    self.settingsButton.frame = NSMakeRect(w - rightInset - control, y, control, control);
    self.bookmarkButton.frame = NSMakeRect(w - rightInset - 2.0 * control - kControlGap,
                                           y, control, control);
    self.readerButton.frame = NSMakeRect(w - rightInset - 3.0 * control - 2.0 * kControlGap,
                                         y, control, control);
    self.addressPill.frame = NSMakeRect(addressX, y, addressWidth, control);
    self.securityIcon.frame = NSMakeRect(8.0, 6.0, 16.0, 16.0);
    // Return submits the omnibox, so a permanent Go icon is redundant visual
    // chrome. Giving that space back to the text field makes long URLs easier
    // to scan and matches the conventional desktop-browser omnibox pattern.
    self.address.frame = NSMakeRect(30.0, 0.0,
                                    MAX(1.0, addressWidth - 38.0), control);
}
@end

std::string LetheCefNewTabDataUrl() {
    const std::string html = lethe::renderNewTabPage({}, {});
    const char hex[] = "0123456789ABCDEF";
    std::string out = "data:text/html;charset=utf-8,";
    out.reserve(out.size() + html.size() * 2);
    for (unsigned char c : html) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '-' || c == '_' ||
            c == '.' || c == '~' || c == ' ' || c == '\n' || c == '\r') {
            out += static_cast<char>(c);
        } else {
            out += '%';
            out += hex[c >> 4];
            out += hex[c & 0x0f];
        }
    }
    return out;
}

static NSString* const kLetheCefToolbarChrome = @"LetheCefToolbarChrome";

@interface LetheCefChromeController : NSObject <NSTextFieldDelegate, NSToolbarDelegate>
// A retained reference: the chrome outlives individual navigations, and a
// raw pointer here let a closed browser leave a dangling target behind
// (menu validation then read freed CEF memory).
@property(nonatomic, assign) CefRefPtr<CefBrowser> browser;
@property(nonatomic, strong) NSWindow* hostWindow;
@property(nonatomic, strong) NSView* chrome;
@property(nonatomic, strong) NSToolbar* toolbar;
@property(nonatomic, strong) NSTextField* address;
@property(nonatomic, strong) NSButton* backButton;
@property(nonatomic, strong) NSButton* forwardButton;
@property(nonatomic, strong) NSButton* reloadButton;
@property(nonatomic, strong) NSButton* readerButton;
@property(nonatomic, strong) NSButton* bookmarkButton;
@property(nonatomic, strong) NSView* addressPill;
@property(nonatomic, strong) NSImageView* securityIcon;
@property(nonatomic, copy) NSString* readerSourceURL;
@property(nonatomic, assign) BOOL readerActive;
@property(nonatomic, assign) BOOL loading;
@property(nonatomic, strong) CALayer* progressLayer;
@property(nonatomic, assign) double loadingProgress;
@property(nonatomic, assign) double pendingProgress;
@property(nonatomic, assign) BOOL progressUpdatePending;
@property(nonatomic, copy) NSString* lastDisplayedURL;
@property(nonatomic, copy) NSString* lastTitle;
@property(nonatomic, assign) BOOL addressEditing;
- (void)toggleReader:(id)sender;
- (void)toggleBookmark:(id)sender;
@end

@implementation LetheCefChromeController

- (void)submitAddress:(id)sender {
    (void)sender;
    if (!self.browser || !self.address) return;
    std::string text = self.address.stringValue.UTF8String ?: "";
    const std::string url = lethe::normalizeAddressInput(text);
    if (!url.empty()) self.browser->GetMainFrame()->LoadURL(url);
}

- (void)goBack:(id)sender {
    (void)sender;
    if (self.browser && self.browser->CanGoBack()) self.browser->GoBack();
}

- (void)goForward:(id)sender {
    (void)sender;
    if (self.browser && self.browser->CanGoForward()) self.browser->GoForward();
}

- (void)reload:(id)sender {
    (void)sender;
    if (!self.browser) return;
    if (self.loading) self.browser->StopLoad();
    else self.browser->Reload();
}

- (void)focusAddress:(id)sender {
    (void)sender;
    [self.address selectText:nil];
    [self.address.window makeFirstResponder:self.address];
}

- (void)controlTextDidBeginEditing:(NSNotification*)note {
    if (note.object != self.address) return;
    self.addressEditing = YES;
    self.addressPill.layer.borderColor = LetheAccentColor().CGColor;
}

- (void)controlTextDidEndEditing:(NSNotification*)note {
    if (note.object != self.address) return;
    self.addressEditing = NO;
    self.addressPill.layer.borderColor = [NSColor separatorColor].CGColor;
}

- (void)showSettings:(id)sender {
    (void)sender;
    ShowCefSettings();
}

#pragma mark - Native AppKit toolbar host

- (NSToolbarItem*)toolbar:(NSToolbar*)toolbar
    itemForItemIdentifier:(NSToolbarItemIdentifier)identifier
willBeInsertedIntoToolbar:(BOOL)flag {
    (void)toolbar;
    (void)flag;
    if (![identifier isEqualToString:kLetheCefToolbarChrome]) return nil;
    NSToolbarItem* item = [[NSToolbarItem alloc]
        initWithItemIdentifier:kLetheCefToolbarChrome];
    item.view = self.chrome;
    item.visibilityPriority = NSToolbarItemVisibilityPriorityHigh;
    item.label = @"Browser Controls";
    item.paletteLabel = @"Browser Controls";
    return item;
}

- (NSArray<NSToolbarItemIdentifier>*)toolbarAllowedItemIdentifiers:(NSToolbar*)toolbar {
    (void)toolbar;
    return @[ kLetheCefToolbarChrome ];
}

- (NSArray<NSToolbarItemIdentifier>*)toolbarDefaultItemIdentifiers:(NSToolbar*)toolbar {
    (void)toolbar;
    return @[ kLetheCefToolbarChrome ];
}

- (void)toggleBookmark:(id)sender {
    (void)sender;
    if (!self.browser) return;
    NSString* url = [NSString stringWithUTF8String:self.browser->GetMainFrame()->GetURL().ToString().c_str()];
    if (!url.length) return;
    BOOL added = [[LetheBookmarks shared] toggleURL:url title:url];
    self.bookmarkButton.image = [NSImage imageWithSystemSymbolName:
        (added ? @"bookmark.fill" : @"bookmark")
        accessibilityDescription:(added ? @"Bookmarked" : @"Bookmark")];
}

- (void)toggleReader:(id)sender {
    (void)sender;
    if (!self.browser) return;
    if (self.readerActive) {
        self.readerActive = NO;
        if (self.readerSourceURL.length)
            self.browser->GetMainFrame()->LoadURL(self.readerSourceURL.UTF8String);
        return;
    }
    const std::string url = self.browser->GetMainFrame()->GetURL().ToString();
    if (url.rfind("http://", 0) != 0 && url.rfind("https://", 0) != 0) return;
    self.readerSourceURL = [NSString stringWithUTF8String:url.c_str()];
    self.readerActive = YES;
    self.browser->GetMainFrame()->ExecuteJavaScript(
        "(function(){var s=document.body?document.body.innerText:'';"
        "var esc=s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');"
        "document.documentElement.innerHTML='<head><meta charset=\\\"utf-8\\\"><title>Reader View</title>'"
        "+'<style>body{margin:0;background:#16181a;color:#e5e7eb;font:18px/1.75 -apple-system,BlinkMacSystemFont,sans-serif}'"
        "+'main{max-width:760px;margin:0 auto;padding:64px 32px}h1{font-size:32px}pre{white-space:pre-wrap;font:inherit}</style></head>'"
        "+'<body><main><h1>'+((document.title||'Reader View').replace(/</g,'&lt;'))+'</h1><pre>'+esc+'</pre></main></body>';"
        "})()",
        self.readerSourceURL.UTF8String, 0);
}

@end

namespace {
NSButton* Button(NSString* symbol, NSString* label, id target, SEL action) {
    NSImage* image = [NSImage imageWithSystemSymbolName:symbol accessibilityDescription:label];
    image = [image imageWithSymbolConfiguration:[NSImageSymbolConfiguration configurationWithPointSize:14.0 weight:NSFontWeightMedium]];
    NSButton* b = [LetheCefChromeButton buttonWithImage:image target:target action:action];
    b.buttonType = NSButtonTypeMomentaryPushIn;
    b.enabled = YES;
    b.target = target;
    b.action = action;
    b.refusesFirstResponder = YES;
    // Flat ghost controls match the native WebKit shell and avoid an extra
    // bezel/background layer per button. Hover/focus remains discoverable
    // through AppKit's standard highlight state and the tooltip.
    b.bezelStyle = NSBezelStyleTexturedRounded;
    b.bordered = NO;
    // These are custom controls rather than NSToolbarItems, so allow the
    // keyboard to enter them. VoiceOver and full-keyboard navigation should
    // reach every chrome action, not only the omnibox.
    b.refusesFirstResponder = NO;
    b.showsBorderOnlyWhileMouseInside = NO;
    b.focusRingType = NSFocusRingTypeNone;
    // secondaryLabelColor on the unified titlebar reads as disabled; these
    // are primary navigation controls and should look clickable at rest.
    b.contentTintColor = [NSColor labelColor];
    b.imageScaling = NSImageScaleProportionallyDown;
    b.toolTip = label;
    b.accessibilityRole = NSAccessibilityButtonRole;
    b.accessibilityLabel = label;
    // Stable identity for scripted clicks and the control audit.
    b.accessibilityIdentifier = label;
    b.accessibilityHelp = label;
    b.translatesAutoresizingMaskIntoConstraints = YES;
    return b;
}

void ShowCefSettings() {
    // CEF must use the same Settings surface as the native/WebKit shell.
    // Do not maintain a second, reduced settings implementation here: that
    // would make Blink/CEF behavior diverge from Lethe's authoritative UI.
    // Defer one run-loop turn. Both a native menu command and an NSButton
    // action can arrive while AppKit is still tracking the originating event;
    // presenting another key window synchronously from that event can leave
    // the Settings window constructed but visually suppressed behind CEF.
    dispatch_async(dispatch_get_main_queue(), ^{
        [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
        [NSApp activateIgnoringOtherApps:YES];
        [[LetheSettings shared] show];
        for (NSWindow* candidate in NSApp.windows) {
            if ([candidate.title isEqualToString:@"Settings"]) {
                candidate.level = NSModalPanelWindowLevel;
                [candidate orderFrontRegardless];
                [candidate makeKeyAndOrderFront:nil];
                break;
            }
        }
    });
}

static void EnsureSingleTabBar(NSWindow* window) {
    if (!window) return;
    // AppKit's native strip is useful once there are multiple tabs, but its
    // single-tab presentation stretches one tab across the whole titlebar and
    // looks unlike desktop browser chrome. Keep the compact one-tab state and
    // reveal the native strip only when it has real tabs to switch between.
    if (window.tabGroup && window.tabGroup.windows.count <= 1 &&
        window.tabGroup.tabBarVisible)
        [window toggleTabBar:nil];
}

void Layout(NSView* browserView, NSView* chrome) {
    if (!browserView || !chrome) return;
    NSView* container = browserView.superview;
    if (!container) return;

    // The browser content now lives below a real NSToolbar. AppKit owns the
    // toolbar/titlebar geometry; the CEF view should simply consume the full
    // content rectangle left below it. This removes the fragile titlebar
    // overlay arithmetic and prevents Chromium from ever painting over the
    // native browser chrome.
    browserView.translatesAutoresizingMaskIntoConstraints = YES;
    container.translatesAutoresizingMaskIntoConstraints = YES;
    browserView.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
    container.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;

    // Use the window's content layout rect, not the full content view: with a
    // transparent unified titlebar the content view extends *under* the
    // toolbar, so a full-bounds CEF surface painted its own rounded top
    // corners across the toolbar edge. The layout rect is exactly the area
    // AppKit leaves below the toolbar.
    NSWindow* window = container.window ?: chrome.window;
    NSRect bounds = container.superview ? container.superview.bounds : container.bounds;
    if (window && window.contentView) {
        const NSRect layout = [window.contentView convertRect:window.contentLayoutRect
                                                     fromView:nil];
        if (layout.size.height > 1.0 && layout.size.width > 1.0) bounds = layout;
    }
    container.frame = bounds;
    browserView.frame = NSMakeRect(0, 0, bounds.size.width, bounds.size.height);
    // Never let the renderer surface round or clip itself: the window already
    // owns the corner treatment.
    if (browserView.layer) {
        browserView.layer.cornerRadius = 0.0;
        browserView.layer.masksToBounds = NO;
    }
    for (NSNumber* key in g_chrome) {
        LetheCefChromeController* controller = g_chrome[key];
        if (controller.chrome != chrome || !controller.progressLayer) continue;
        controller.progressLayer.frame = NSMakeRect(
            0.0, chrome.bounds.size.height - 2.0,
            chrome.bounds.size.width * static_cast<CGFloat>(controller.loadingProgress), 2.0);
        controller.progressLayer.hidden = !controller.loading;
        break;
    }
}

} // namespace

void LetheCefChromeAttach(CefRefPtr<CefBrowser> browser) {
    if (!browser) return;
    const int id = browser->GetIdentifier();
    if (!g_chrome) g_chrome = [NSMutableDictionary dictionary];
    NSNumber* key = @(id);
    if (g_chrome[key]) return;

    CefWindowHandle handle = browser->GetHost()->GetWindowHandle();
    if (!handle) return;
    NSView* browserView = (__bridge NSView*)handle;
    NSWindow* window = browserView.window;
    if (!window || !window.contentView) return;

    // Keep CEF windows in the same native Mac tab group as the rest of the
    // Lethe browser. CEF owns each browser view, while AppKit owns the tab
    // chrome/lifecycle.
    window.tabbingMode = NSWindowTabbingModePreferred;
    window.tabbingIdentifier = @"org.aletheia.lethe.cef.browser";
    window.titleVisibility = NSWindowTitleHidden;
    window.titlebarAppearsTransparent = YES;
    window.toolbarStyle = NSWindowToolbarStyleUnifiedCompact;

    LetheCefChromeController* c = [LetheCefChromeController new];
    c.browser = browser;
    c.hostWindow = window;

    LetheCefChromeView* chrome = [LetheCefChromeView new];
    chrome.wantsLayer = YES;
    chrome.layer.backgroundColor = [NSColor windowBackgroundColor].CGColor;
    chrome.layer.borderWidth = 0.0;
    chrome.translatesAutoresizingMaskIntoConstraints = NO;
    [chrome.widthAnchor constraintGreaterThanOrEqualToConstant:500.0].active = YES;
    [chrome.widthAnchor constraintLessThanOrEqualToConstant:2000.0].active = YES;
    [chrome.heightAnchor constraintEqualToConstant:kChromeHeight].active = YES;
    c.chrome = chrome;
    // A 2px determinate progress line gives immediate navigation feedback
    // without adding another AppKit view or disturbing the content viewport.
    // It is a sublayer of the chrome surface, so progress updates stay local
    // to the native toolbar and never trigger CEF layout.
    CALayer* progressLayer = [CALayer layer];
    progressLayer.backgroundColor = LetheAccentColor().CGColor;
    progressLayer.cornerRadius = 1.0;
    progressLayer.hidden = YES;
    progressLayer.actions = @{
        @"frame": [NSNull null],
        @"hidden": [NSNull null]
    };
    c.progressLayer = progressLayer;
    [chrome.layer addSublayer:progressLayer];

    NSButton* back = Button(@"chevron.left", @"Back", c, @selector(goBack:));
    NSButton* forward = Button(@"chevron.right", @"Forward", c, @selector(goForward:));
    NSButton* reload = Button(@"arrow.clockwise", @"Reload", c, @selector(reload:));
    NSButton* reader = Button(@"doc.plaintext", @"Reader View", c, @selector(toggleReader:));
    NSButton* bookmark = Button(@"bookmark", @"Bookmark", c, @selector(toggleBookmark:));
    // The controller is retained in g_chrome for the browser lifetime, so
    // its action target remains valid for the entire CEF tab lifetime.
    NSButton* settings = Button(@"gearshape", @"Settings", c,
                                @selector(showSettings:));
    // Keep toolbar actions compact. Tooltips provide full labels without
    // stealing horizontal space from the address field.
    settings.toolTip = @"Settings (⌘,)";
    c.readerButton = reader;
    c.bookmarkButton = bookmark;
    c.backButton = back;
    c.forwardButton = forward;
    c.reloadButton = reload;
    NSTextField* address = [[LetheCefAddressField alloc] initWithFrame:NSZeroRect];
    address.placeholderString = @"Search or enter address";
    // The pill is the control surface. A second NSTextField bezel creates a
    // nested rounded rectangle, wastes pixels, and produces a heavier focus
    // transition than native browser chrome.
    address.bezelStyle = NSTextFieldSquareBezel;
    address.bordered = NO;
    address.drawsBackground = NO;
    address.focusRingType = NSFocusRingTypeNone;
    address.font = [NSFont systemFontOfSize:13.0];
    address.delegate = c;
    address.target = c;
    address.action = @selector(submitAddress:);
    address.translatesAutoresizingMaskIntoConstraints = YES;
    c.address = address;

    // Treat the omnibox as one control rather than a text field with a
    // separate decoration. The leading security glyph gives the user an
    // immediate transport cue without consuming another toolbar slot.
    NSView* addressPill = [[NSView alloc] initWithFrame:NSZeroRect];
    addressPill.wantsLayer = YES;
    addressPill.layer.backgroundColor = [NSColor controlBackgroundColor].CGColor;
    addressPill.layer.borderColor = [NSColor separatorColor].CGColor;
    addressPill.layer.borderWidth = 1.0;
    addressPill.layer.cornerRadius = 7.0;
    addressPill.clipsToBounds = YES;
    c.addressPill = addressPill;

    NSImageView* securityIcon = [[NSImageView alloc] initWithFrame:NSZeroRect];
    securityIcon.image = [NSImage imageWithSystemSymbolName:@"globe"
                                   accessibilityDescription:@"Connection security"];
    securityIcon.contentTintColor = [NSColor secondaryLabelColor];
    c.securityIcon = securityIcon;
    [addressPill addSubview:securityIcon];
    [addressPill addSubview:address];

    LetheCefChromeRow* row = [LetheCefChromeRow new];
    row.translatesAutoresizingMaskIntoConstraints = YES;
    row.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
    row.backButton = back;
    row.forwardButton = forward;
    row.reloadButton = reload;
    row.readerButton = reader;
    row.bookmarkButton = bookmark;
    row.address = address;
    row.addressPill = addressPill;
    row.securityIcon = securityIcon;
    row.settingsButton = settings;
    [row addSubview:back];
    [row addSubview:forward];
    [row addSubview:reload];
    [row addSubview:reader];
    [row addSubview:bookmark];
    [row addSubview:addressPill];
    [row addSubview:settings];
    [chrome addSubview:row];

    // CEF has already inserted the browser view into an intermediate
    // container supplied through CefWindowInfo::SetAsChild. Let AppKit's
    // NSToolbar own the browser controls in the native titlebar; the CEF
    // subtree remains untouched and therefore cannot reorder over the chrome.
    NSView* browserContainer = browserView.superview;
    if (!browserContainer) return;
    NSView* contentView = window.contentView;
    if (!contentView) return;
    // Alloy can create the top-level NSWindow with a zero-width content
    // frame until its native view is attached. Do not let Auto Layout inherit
    // that transient size; establish a real browser window before presenting
    // the chrome. Without this, the renderer exists but the entire CEF window
    // can collapse to a 0px-wide strip behind other applications.
    NSRect frame = window.frame;
    if (frame.size.width < 900.0 || frame.size.height < 600.0) {
        frame.size = NSMakeSize(1280.0, 860.0);
        [window setFrame:frame display:NO];
    }

    // Register before the first geometry pass. AppKit measures the custom
    // toolbar item from its constraints (the modern replacement for the
    // deprecated minSize/maxSize properties), so the control row stays
    // centered and responsive as the window changes width.
    g_chrome[key] = c;
    NSToolbar* toolbar = [[NSToolbar alloc]
        initWithIdentifier:@"org.aletheia.lethe.cef.chrome"];
    toolbar.delegate = c;
    toolbar.displayMode = NSToolbarDisplayModeIconOnly;
    toolbar.allowsUserCustomization = NO;
    toolbar.autosavesConfiguration = NO;
    toolbar.showsBaselineSeparator = NO;
    toolbar.centeredItemIdentifiers =
        [NSSet setWithObject:kLetheCefToolbarChrome];
    c.toolbar = toolbar;
    window.toolbar = toolbar;
    [window displayIfNeeded];

    LayoutChromeControls(c, row, back, forward, reload, settings);
    Layout(browserView, chrome);
    [row setNeedsLayout:YES];
    [row layoutSubtreeIfNeeded];
    [window makeKeyAndOrderFront:nil];
    [window setTitle:@"Lethe"];
    EnsureSingleTabBar(window);
    std::cout << "[lethe-cef] native tab bar visible="
              << (window.tabGroup && window.tabGroup.tabBarVisible ? 1 : 0)
              << " tabs=" << (window.tabbedWindows ? [window.tabbedWindows count] : 1)
              << std::endl;
    LetheCefChromeUpdate(browser);

    // CEF's Alloy macOS window can report a zero horizontal fitting size on
    // its first native layout even when CefWindowInfo supplied real bounds.
    // Establish the content size only after all embedder views are attached;
    // doing it earlier is overwritten by CEF's first browser-view layout.
    // This is also a hard guard against ever presenting a 0px-wide Blink
    // window to the user.
    NSRect finalFrame = window.frame;
    if (finalFrame.size.width < 480.0 || finalFrame.size.height < 320.0) {
        [window setContentSize:NSMakeSize(1280.0, 860.0)];
        [window setMinSize:NSMakeSize(480.0, 320.0)];
        Layout(browserView, chrome);
        [window makeKeyAndOrderFront:nil];
        [window displayIfNeeded];
    }
}

static void LayoutChromeControls(LetheCefChromeController* controller,
                                 NSView* row, NSButton* back,
                                 NSButton* forward, NSButton* reload,
                                 NSButton* settings) {
    if (!controller || !controller.chrome || !row) return;

    // Keep the compact visual treatment while making the toolbar fully
    // navigable by VoiceOver and other AppKit accessibility clients. The
    // symbol-only controls must expose stable semantic names; tooltips alone
    // are not sufficient for non-pointer users.
    back.accessibilityLabel = @"Back";
    forward.accessibilityLabel = @"Forward";
    reload.accessibilityLabel = controller.loading ? @"Stop loading" : @"Reload";
    controller.readerButton.accessibilityLabel = controller.readerActive
        ? @"Exit Reader View" : @"Reader View";
    controller.bookmarkButton.accessibilityLabel = @"Bookmark";
    settings.accessibilityLabel = @"Settings";
    controller.address.accessibilityLabel = @"Address and search field";

    // Address bar should read as one calm surface, with a subtle focus ring
    // rather than a heavy desktop-control bezel.
    controller.address.bezelStyle = NSTextFieldSquareBezel;
    controller.address.bordered = NO;
    controller.address.drawsBackground = NO;
    controller.address.focusRingType = NSFocusRingTypeNone;
    controller.address.font = [NSFont systemFontOfSize:13.0 weight:NSFontWeightRegular];
    controller.address.placeholderString = @"Search or enter address";
    controller.address.lineBreakMode = NSLineBreakByTruncatingTail;

    row.frame = NSMakeRect(kToolbarHorizontalInset, kToolbarVerticalInset,
                           MAX(0.0, controller.chrome.bounds.size.width -
                               2.0 * kToolbarHorizontalInset),
                           MAX(0.0, controller.chrome.bounds.size.height -
                               2.0 * kToolbarVerticalInset));

}

void LetheCefChromeShowSettings() {
    ShowCefSettings();
}

void LetheCefChromeUpdate(CefRefPtr<CefBrowser> browser) {
    if (!browser) return;
    LetheCefChromeController* c = g_chrome[@(browser->GetIdentifier())];
    if (!c) return;
    const std::string rawURL = browser->GetMainFrame()->GetURL().ToString();
    NSString* url = [NSString stringWithUTF8String:rawURL.c_str()];
    if (url.length) {
        // Never expose Lethe's internal data: URL payload in the address bar.
        // It is implementation detail, not useful navigation state.
        NSString* displayURL = url;
        if ([url hasPrefix:@"data:text/html"])
            displayURL = @"New Tab";
        // LoadStart/LoadEnd can both report the same URL. Avoid repeating
        // bookmark persistence lookup and AppKit title/image transactions on
        // those duplicate callbacks; the navigation buttons still update on
        // every call below.
        // The address field can intentionally differ from the committed URL
        // while the user is editing it. Keep a separate committed value so a
        // duplicate CEF callback cannot overwrite in-progress input, and so
        // the hot callback path does not repeatedly touch AppKit text state.
        const BOOL urlChanged = ![c.lastDisplayedURL isEqualToString:displayURL];
        if (urlChanged) {
            c.lastDisplayedURL = displayURL;
            if (!c.addressEditing) c.address.stringValue = displayURL;
            c.chrome.window.title = displayURL;
            c.chrome.window.tab.title = displayURL;
            BOOL bookmarked = [[LetheBookmarks shared] containsURL:url];
            c.bookmarkButton.image = [NSImage imageWithSystemSymbolName:
                (bookmarked ? @"bookmark.fill" : @"bookmark")
                accessibilityDescription:(bookmarked ? @"Bookmarked" : @"Bookmark")];
        }
        const BOOL secure = [url hasPrefix:@"https://"];
        const BOOL insecureHttp = [url hasPrefix:@"http://"];
        NSString* securitySymbol = secure ? @"lock.fill"
            : (insecureHttp ? @"lock.open" : @"globe");
        NSString* securityLabel = secure ? @"Secure connection"
            : (insecureHttp ? @"Not secure: plain HTTP" : @"Connection");
        c.securityIcon.image = [NSImage imageWithSystemSymbolName:securitySymbol
                                      accessibilityDescription:securityLabel];
        c.securityIcon.contentTintColor = secure
            ? LetheAccentColor()
            : (insecureHttp ? [NSColor systemRedColor] : [NSColor secondaryLabelColor]);
        c.securityIcon.toolTip = securityLabel;
        c.securityIcon.accessibilityLabel = securityLabel;
        c.readerButton.enabled = [url hasPrefix:@"http://"] || [url hasPrefix:@"https://"];
        c.readerButton.contentTintColor = c.readerActive
            ? LetheAccentColor() : [NSColor secondaryLabelColor];
        c.readerButton.toolTip = c.readerActive ? @"Exit Reader View" : @"Reader View";
        c.address.placeholderString = @"Search or enter address";
    }
    c.browser = browser;
    c.backButton.enabled = browser->CanGoBack();
    c.forwardButton.enabled = browser->CanGoForward();
}

void LetheCefChromeSetTitle(CefRefPtr<CefBrowser> browser, const std::string& title) {
    if (!browser) return;
    LetheCefChromeController* c = g_chrome[@(browser->GetIdentifier())];
    if (!c || !c.chrome.window) return;

    NSString* value = [NSString stringWithUTF8String:title.c_str()];
    if (!value.length) value = @"Lethe";
    if ([c.lastTitle isEqualToString:value]) return;
    c.lastTitle = value;
    // The native tab should identify the document, not expose its transport
    // URL. Keep the window title in sync as well so macOS accessibility and
    // window-switching surfaces receive the same useful label.
    c.chrome.window.title = value;
    if (c.chrome.window.tab) c.chrome.window.tab.title = value;
}

void LetheCefChromeSetAddress(CefRefPtr<CefBrowser> browser, const std::string& url) {
    if (!browser) return;
    LetheCefChromeController* c = g_chrome[@(browser->GetIdentifier())];
    if (!c) return;
    NSString* value = [NSString stringWithUTF8String:url.c_str()];
    if (!value.length) return;
    // CEF can deliver an address update while the user is still typing. Never
    // replace live input from a navigation callback; the committed URL is
    // reconciled by LetheCefChromeUpdate once editing ends.
    if (c.addressEditing) return;
    // Internal data: documents are implementation details of the browser
    // chrome, not useful navigation state. Keep the omnibox consistent with
    // LetheCefChromeUpdate so CEF callbacks cannot briefly expose a giant
    // data: payload while a native block/new-tab page is committing.
    NSString* shown = [value hasPrefix:@"data:text/html"] ? @"New Tab" : value;
    NSAttributedString* styled = LetheOmniboxAttributedAddress(shown, c.address.font);
    if (styled) {
        c.address.attributedStringValue = styled;
    } else {
        c.address.stringValue = shown;
    }
}

void LetheCefChromeSetLoading(CefRefPtr<CefBrowser> browser, bool loading) {
    if (!browser) return;
    LetheCefChromeController* c = g_chrome[@(browser->GetIdentifier())];
    if (!c || !c.reloadButton) return;
    // LoadStart/LoadEnd may be repeated by CEF for the same navigation. Avoid
    // rebuilding the SF Symbol and touching AppKit when the state is stable.
    if (c.loading == loading) return;
    c.loading = loading;
    NSString* symbol = loading ? @"xmark" : @"arrow.clockwise";
    NSString* label = loading ? @"Stop" : @"Reload";
    NSImage* image = [NSImage imageWithSystemSymbolName:symbol
                                      accessibilityDescription:label];
    image = [image imageWithSymbolConfiguration:
        [NSImageSymbolConfiguration configurationWithPointSize:14.0
                                                         weight:NSFontWeightMedium]];
    c.reloadButton.image = image;
    c.reloadButton.toolTip = loading ? @"Stop loading" : @"Reload";
    c.reloadButton.accessibilityLabel = loading ? @"Stop loading" : @"Reload";
    if (!loading) {
        c.loadingProgress = 0.0;
        if (c.progressLayer) {
            CGRect frame = c.progressLayer.frame;
            frame.size.width = 0.0;
            c.progressLayer.frame = frame;
            c.progressLayer.hidden = YES;
        }
    } else if (c.progressLayer) {
        c.progressLayer.hidden = NO;
        c.loadingProgress = 0.0;
    }
}

void LetheCefChromeSetLoadingProgress(CefRefPtr<CefBrowser> browser,
                                      double progress) {
    if (!browser) return;
    LetheCefChromeController* c = g_chrome[@(browser->GetIdentifier())];
    if (!c || !c.progressLayer || !c.loading) return;
    const double clamped = std::max(0.0, std::min(1.0, progress));
    if (std::abs(clamped - c.loadingProgress) < 0.01 && clamped < 0.99)
        return;
    c.pendingProgress = clamped;
    // CEF can deliver progress callbacks much faster than the display can
    // present them. Coalesce those callbacks to one layer transaction per
    // display interval; progress remains monotonic and the loading-end path
    // still hides the layer immediately.
    if (c.progressUpdatePending) return;
    c.progressUpdatePending = YES;
    __weak LetheCefChromeController* weakC = c;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,
                                  (int64_t)(NSEC_PER_SEC / 60)),
                   dispatch_get_main_queue(), ^{
        LetheCefChromeController* strongC = weakC;
        if (!strongC) return;
        strongC.progressUpdatePending = NO;
        if (!strongC.loading || !strongC.progressLayer) return;
        strongC.loadingProgress = strongC.pendingProgress;
        NSView* chrome = strongC.chrome;
        const CGFloat width = chrome ? chrome.bounds.size.width : 0.0;
        CGRect frame = strongC.progressLayer.frame;
        frame.size.width = width * static_cast<CGFloat>(strongC.loadingProgress);
        strongC.progressLayer.frame = frame;
        strongC.progressLayer.hidden = NO;
    });
}

void LetheCefChromeFocusAddress(CefRefPtr<CefBrowser> browser) {
    if (!browser) return;
    LetheCefChromeController* c = g_chrome[@(browser->GetIdentifier())];
    if (!c || !c.address) return;
    [c.address selectText:nil];
    [c.address.window makeFirstResponder:c.address];
}

static LetheCefChromeController* ActiveChromeController() {
    if (!g_chrome) return nil;
    NSWindow* keyWindow = NSApp.keyWindow;
    LetheCefChromeController* fallback = nil;
    for (NSNumber* key in g_chrome) {
        LetheCefChromeController* c = g_chrome[key];
        if (!c || !c.chrome.window || !c.browser) continue;
        if (c.chrome.window == keyWindow || c.chrome.window.isMainWindow)
            return c;
        if (!fallback) fallback = c;
    }
    // No key or main window: the app is in the background (a scripted run
    // never steals focus) or AppKit has not finished promoting the new
    // window yet. A menu command still has one unambiguous target then, so
    // acting on the surviving browser beats doing nothing.
    return fallback;
}

void LetheCefChromeFocusActiveAddress() {
    dispatch_async(dispatch_get_main_queue(), ^{
        LetheCefChromeController* c = ActiveChromeController();
        if (!c || !c.address) return;
        [c.address selectText:nil];
        [c.address.window makeFirstResponder:c.address];
    });
}

void LetheCefChromeReloadActive() {
    dispatch_async(dispatch_get_main_queue(), ^{
        LetheCefChromeController* c = ActiveChromeController();
        if (!c || !c.browser) return;
        if (c.loading) c.browser->StopLoad();
        else c.browser->Reload();
    });
}

CefRefPtr<CefBrowser> LetheCefActiveBrowser() {
    LetheCefChromeController* c = ActiveChromeController();
    return c ? c.browser : nullptr;
}

void LetheCefChromeToggleReaderActive() {
    LetheCefChromeController* c = ActiveChromeController();
    if (c) [c toggleReader:nil];
}

void LetheCefChromeToggleBookmarkActive() {
    LetheCefChromeController* c = ActiveChromeController();
    if (c) [c toggleBookmark:nil];
}

void LetheCefChromeLoadActive(const std::string& url) {
    LetheCefChromeController* c = ActiveChromeController();
    if (!c || !c.browser || url.empty()) return;
    c.browser->GetMainFrame()->LoadURL(url);
}

void LetheCefChromeDetach(CefRefPtr<CefBrowser> browser) {
    if (!browser) return;
    NSNumber* key = @(browser->GetIdentifier());
    LetheCefChromeController* c = g_chrome[key];
    if (!c) return;
    // CEF may already be tearing down its native NSView by the time
    // OnBeforeClose reaches this function. Dereferencing GetWindowHandle()
    // here can therefore turn into objc_msgSend(-window) on freed memory.
    // The AppKit host window is retained by the chrome controller from the
    // moment of attachment, so use that stable object for tab-group cleanup.
    NSWindow* window = c.hostWindow;
    if (window && window.tabbedWindows.count > 1) {
        // Remove the CEF window from the native tab group before CEF destroys
        // its browser surface. AppKit exposes this operation on the tab-group
        // object; doing it here keeps native and CEF tab lifecycles aligned.
        NSWindowTabGroup* group = window.tabGroup;
        [group removeWindow:window];
        NSWindow* remaining = group.windows.firstObject;
        if (remaining && group.windows.count == 1 && group.tabBarVisible) {
            [remaining toggleTabBar:nil];
        }
    }
    // The chrome belongs exclusively to this browser window. Always remove
    // it during detach; the previous conditional could leave an orphaned
    // toolbar behind when AppKit had already collapsed the tab group.
    [c.chrome removeFromSuperview];
    [g_chrome removeObjectForKey:key];
}
