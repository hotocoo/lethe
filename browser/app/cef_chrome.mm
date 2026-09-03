#import <Cocoa/Cocoa.h>

#include "app/cef_chrome.h"
#include "browser/url_input.h"
#include "renderer/page_templates.h"

#include <unordered_map>

static const CGFloat kChromeHeight = 52.0;
static const CGFloat kControl = 30.0;

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

@interface LetheCefChromeController : NSObject <NSTextFieldDelegate>
@property(nonatomic, assign) CefBrowser* browser;
@property(nonatomic, strong) NSView* chrome;
@property(nonatomic, strong) NSTextField* address;
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
    if (self.browser) self.browser->Reload();
}

- (void)focusAddress:(id)sender {
    (void)sender;
    [self.address selectText:nil];
    [self.address.window makeFirstResponder:self.address];
}

@end

namespace {
std::unordered_map<int, LetheCefChromeController*> g_chrome;

NSButton* Button(NSString* symbol, NSString* label, id target, SEL action) {
    NSButton* b = [NSButton buttonWithImage:
        [NSImage imageWithSystemSymbolName:symbol accessibilityDescription:label]
        target:target action:action];
    b.buttonType = NSButtonTypeMomentaryPushIn;
    b.enabled = YES;
    b.target = target;
    b.action = action;
    b.refusesFirstResponder = YES;
    b.bezelStyle = NSBezelStyleTexturedRounded;
    b.bordered = NO;
    b.contentTintColor = [NSColor secondaryLabelColor];
    b.toolTip = label;
    b.translatesAutoresizingMaskIntoConstraints = NO;
    [b.widthAnchor constraintEqualToConstant:kControl].active = YES;
    [b.heightAnchor constraintEqualToConstant:kControl].active = YES;
    return b;
}

void Layout(NSView* browserView, NSView* chrome) {
    if (!browserView || !chrome) return;
    NSView* parent = browserView.superview;
    if (!parent) return;
    browserView.translatesAutoresizingMaskIntoConstraints = NO;
    chrome.translatesAutoresizingMaskIntoConstraints = NO;
    [NSLayoutConstraint activateConstraints:@[
        [chrome.leadingAnchor constraintEqualToAnchor:parent.leadingAnchor],
        [chrome.trailingAnchor constraintEqualToAnchor:parent.trailingAnchor],
        [chrome.topAnchor constraintEqualToAnchor:parent.topAnchor],
        [chrome.heightAnchor constraintEqualToConstant:kChromeHeight],
        [browserView.leadingAnchor constraintEqualToAnchor:parent.leadingAnchor],
        [browserView.trailingAnchor constraintEqualToAnchor:parent.trailingAnchor],
        [browserView.topAnchor constraintEqualToAnchor:chrome.bottomAnchor],
        [browserView.bottomAnchor constraintEqualToAnchor:parent.bottomAnchor],
    ]];
}

} // namespace

void LetheCefChromeAttach(CefRefPtr<CefBrowser> browser) {
    if (!browser) return;
    const int id = browser->GetIdentifier();
    if (g_chrome.count(id)) return;

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
    c.browser = browser.get();

    NSView* chrome = [NSView new];
    chrome.wantsLayer = YES;
    chrome.layer.backgroundColor = [NSColor windowBackgroundColor].CGColor;
    chrome.layer.borderColor = [NSColor separatorColor].CGColor;
    chrome.layer.borderWidth = 1.0;
    c.chrome = chrome;

    NSButton* back = Button(@"chevron.left", @"Back", c, @selector(goBack:));
    NSButton* forward = Button(@"chevron.right", @"Forward", c, @selector(goForward:));
    NSButton* reload = Button(@"arrow.clockwise", @"Reload", c, @selector(reload:));
    NSButton* addressGo = Button(@"arrow.right.circle", @"Go", c, @selector(submitAddress:));
    NSTextField* address = [[NSTextField alloc] initWithFrame:NSZeroRect];
    address.placeholderString = @"Search or enter address";
    address.bezelStyle = NSTextFieldRoundedBezel;
    address.bordered = YES;
    address.font = [NSFont systemFontOfSize:13.0];
    address.delegate = c;
    address.target = c;
    address.action = @selector(submitAddress:);
    address.translatesAutoresizingMaskIntoConstraints = NO;
    c.address = address;

    NSStackView* row = [NSStackView stackViewWithViews:@[back, forward, reload, address, addressGo]];
    row.orientation = NSUserInterfaceLayoutOrientationHorizontal;
    row.spacing = 6;
    row.edgeInsets = NSEdgeInsetsMake(9, 10, 9, 10);
    row.translatesAutoresizingMaskIntoConstraints = NO;
    [chrome addSubview:row];
    [NSLayoutConstraint activateConstraints:@[
        [row.leadingAnchor constraintEqualToAnchor:chrome.leadingAnchor],
        [row.trailingAnchor constraintEqualToAnchor:chrome.trailingAnchor],
        [row.topAnchor constraintEqualToAnchor:chrome.topAnchor],
        [row.bottomAnchor constraintEqualToAnchor:chrome.bottomAnchor],
        [address.widthAnchor constraintGreaterThanOrEqualToConstant:240],
    ]];

    // CEF creates the browser view directly in the content view. Put our
    // browser view and chrome into the same constraint hierarchy so resizing
    // remains correct; chrome is added last so it stays above the renderer.
    [window.contentView addSubview:browserView];
    [window.contentView addSubview:chrome];
    Layout(browserView, chrome);
    [window makeKeyAndOrderFront:nil];
    [window setTitle:@"Lethe"];
    g_chrome[id] = c;
    LetheCefChromeUpdate(browser);
}

void LetheCefChromeUpdate(CefRefPtr<CefBrowser> browser) {
    if (!browser) return;
    auto it = g_chrome.find(browser->GetIdentifier());
    if (it == g_chrome.end()) return;
    LetheCefChromeController* c = it->second;
    NSString* url = [NSString stringWithUTF8String:browser->GetMainFrame()->GetURL().ToString().c_str()];
    if (url.length) c.address.stringValue = url;
    if (url.length) c.chrome.window.title = url;
}

void LetheCefChromeSetAddress(CefRefPtr<CefBrowser> browser, const std::string& url) {
    if (!browser) return;
    auto it = g_chrome.find(browser->GetIdentifier());
    if (it == g_chrome.end()) return;
    NSString* value = [NSString stringWithUTF8String:url.c_str()];
    if (value.length) it->second.address.stringValue = value;
}

void LetheCefChromeFocusAddress(CefRefPtr<CefBrowser> browser) {
    if (!browser) return;
    auto it = g_chrome.find(browser->GetIdentifier());
    if (it == g_chrome.end() || !it->second.address) return;
    [it->second.address selectText:nil];
    [it->second.address.window makeFirstResponder:it->second.address];
}

void LetheCefChromeDetach(CefRefPtr<CefBrowser> browser) {
    if (!browser) return;
    auto it = g_chrome.find(browser->GetIdentifier());
    if (it == g_chrome.end()) return;
    CefWindowHandle handle = browser->GetHost()->GetWindowHandle();
    NSWindow* window = handle ? [(__bridge NSView*)handle window] : nil;
    if (window && window.tabbedWindows.count > 1) {
        // Remove the CEF window from the native tab group before CEF destroys
        // its browser surface. AppKit exposes this operation on the tab-group
        // object; doing it here keeps native and CEF tab lifecycles aligned.
        [window.tabGroup removeWindow:window];
    }
    [it->second.chrome removeFromSuperview];
    g_chrome.erase(it);
}
