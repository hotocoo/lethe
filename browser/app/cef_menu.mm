// cef_menu.mm - see cef_menu.h

#import "app/cef_menu.h"

#include <string>

#include "include/cef_browser.h"
#include "include/cef_cookie.h"
#include "include/cef_request_context.h"

#import "app/cef_app_delegate.h"
#include "app/cef_chrome.h"

#import "ui/mac/LetheBookmarks.h"
#import "ui/mac/LetheHistory.h"
#import "ui/mac/LetheInternalPages.h"
#import "ui/mac/LetheSettings.h"

namespace {

constexpr double kZoomStep = 0.5;

CefRefPtr<CefFrame> ActiveFrame() {
    CefRefPtr<CefBrowser> browser = LetheCefActiveBrowser();
    return browser ? browser->GetFocusedFrame() : nullptr;
}

// True when a native text control owns the keyboard, in which case the edit
// commands belong to AppKit's field editor rather than to the renderer.
bool NativeTextHasFocus() {
    NSResponder* responder = NSApp.keyWindow.firstResponder;
    return [responder isKindOfClass:[NSText class]] ||
           [responder isKindOfClass:[NSTextView class]];
}

NSMenuItem* AddItem(NSMenu* menu, NSString* title, SEL action, NSString* key,
                    NSEventModifierFlags mods, id target) {
    NSMenuItem* item = [[NSMenuItem alloc] initWithTitle:title
                                                  action:action
                                           keyEquivalent:key];
    item.keyEquivalentModifierMask = mods;
    item.target = target;
    [menu addItem:item];
    return item;
}

NSMenu* AddSubmenu(NSMenu* bar, NSString* title) {
    NSMenuItem* holder = [[NSMenuItem alloc] initWithTitle:title
                                                    action:nil
                                             keyEquivalent:@""];
    NSMenu* menu = [[NSMenu alloc] initWithTitle:title];
    holder.submenu = menu;
    [bar addItem:holder];
    return menu;
}

}  // namespace

// Menu command target. Commands that need the CefBrowserClient are forwarded
// to the application delegate; everything else acts on the active browser.
@interface LetheCefMenuActions : NSObject <NSMenuItemValidation>
@property(nonatomic, weak) LetheCefAppDelegate* delegate;
@property(nonatomic, strong) NSPanel* findPanel;
@property(nonatomic, strong) NSTextField* findField;
@end

@implementation LetheCefMenuActions

#pragma mark - Application

- (void)showSettings:(id)sender {
    (void)sender;
    LetheCefChromeShowSettings();
}

- (void)showSecurityStatus:(id)sender {
    (void)sender;
    LetheCefChromeShowSettings();
}

#pragma mark - File

- (void)newTab:(id)sender {
    [self.delegate newTabFromMenu:sender];
}

- (void)newOblivionWindow:(id)sender {
    [self.delegate newOblivionWindowFromMenu:sender];
}

- (void)focusAddress:(id)sender {
    (void)sender;
    LetheCefChromeFocusActiveAddress();
}

- (void)closeTab:(id)sender {
    (void)sender;
    CefRefPtr<CefBrowser> browser = LetheCefActiveBrowser();
    if (!browser) return;
    browser->GetHost()->CloseBrowser(false);
}

- (void)closeWindow:(id)sender {
    (void)sender;
    [NSApp.keyWindow performClose:nil];
}

- (void)openDownloads:(id)sender {
    (void)sender;
    NSURL* downloads = [NSFileManager.defaultManager
                              URLsForDirectory:NSDownloadsDirectory
                                     inDomains:NSUserDomainMask].firstObject;
    if (downloads) [NSWorkspace.sharedWorkspace openURL:downloads];
}

- (void)printPage:(id)sender {
    (void)sender;
    CefRefPtr<CefBrowser> browser = LetheCefActiveBrowser();
    if (browser) browser->GetHost()->Print();
}

#pragma mark - Edit

- (void)undo:(id)sender {
    if (NativeTextHasFocus()) { [NSApp sendAction:@selector(undo:) to:nil from:sender]; return; }
    if (CefRefPtr<CefFrame> frame = ActiveFrame()) frame->Undo();
}

- (void)redo:(id)sender {
    if (NativeTextHasFocus()) { [NSApp sendAction:@selector(redo:) to:nil from:sender]; return; }
    if (CefRefPtr<CefFrame> frame = ActiveFrame()) frame->Redo();
}

- (void)cut:(id)sender {
    if (NativeTextHasFocus()) { [NSApp sendAction:@selector(cut:) to:nil from:sender]; return; }
    if (CefRefPtr<CefFrame> frame = ActiveFrame()) frame->Cut();
}

- (void)copy:(id)sender {
    if (NativeTextHasFocus()) { [NSApp sendAction:@selector(copy:) to:nil from:sender]; return; }
    if (CefRefPtr<CefFrame> frame = ActiveFrame()) frame->Copy();
}

- (void)paste:(id)sender {
    if (NativeTextHasFocus()) { [NSApp sendAction:@selector(paste:) to:nil from:sender]; return; }
    if (CefRefPtr<CefFrame> frame = ActiveFrame()) frame->Paste();
}

- (void)selectAll:(id)sender {
    if (NativeTextHasFocus()) { [NSApp sendAction:@selector(selectAll:) to:nil from:sender]; return; }
    if (CefRefPtr<CefFrame> frame = ActiveFrame()) frame->SelectAll();
}

- (void)showFindBar:(id)sender {
    (void)sender;
    if (!self.findPanel) {
        NSPanel* panel = [[NSPanel alloc]
            initWithContentRect:NSMakeRect(0, 0, 320, 56)
                      styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable |
                                NSWindowStyleMaskUtilityWindow
                        backing:NSBackingStoreBuffered
                          defer:NO];
        panel.title = @"Find";
        panel.hidesOnDeactivate = NO;
        NSTextField* field = [NSTextField textFieldWithString:@""];
        field.placeholderString = @"Find on page";
        field.translatesAutoresizingMaskIntoConstraints = NO;
        field.target = self;
        field.action = @selector(findNext:);
        [panel.contentView addSubview:field];
        [NSLayoutConstraint activateConstraints:@[
            [field.leadingAnchor constraintEqualToAnchor:panel.contentView.leadingAnchor
                                                constant:14],
            [field.trailingAnchor constraintEqualToAnchor:panel.contentView.trailingAnchor
                                                 constant:-14],
            [field.centerYAnchor constraintEqualToAnchor:panel.contentView.centerYAnchor],
        ]];
        self.findPanel = panel;
        self.findField = field;
    }
    [self.findPanel center];
    [self.findPanel makeKeyAndOrderFront:nil];
    [self.findPanel makeFirstResponder:self.findField];
}

- (void)findNext:(id)sender {
    (void)sender;
    [self findForward:YES];
}

- (void)findPrevious:(id)sender {
    (void)sender;
    [self findForward:NO];
}

- (void)findForward:(BOOL)forward {
    CefRefPtr<CefBrowser> browser = LetheCefActiveBrowser();
    NSString* text = self.findField.stringValue;
    if (!browser || !text.length) return;
    browser->GetHost()->Find(text.UTF8String, forward, /*matchCase=*/false,
                             /*findNext=*/true);
}

#pragma mark - View

- (void)reloadPage:(id)sender {
    (void)sender;
    LetheCefChromeReloadActive();
}

- (void)hardReload:(id)sender {
    (void)sender;
    CefRefPtr<CefBrowser> browser = LetheCefActiveBrowser();
    if (browser) browser->ReloadIgnoreCache();
}

- (void)stopLoading:(id)sender {
    (void)sender;
    CefRefPtr<CefBrowser> browser = LetheCefActiveBrowser();
    if (browser) browser->StopLoad();
}

- (void)toggleReader:(id)sender {
    (void)sender;
    LetheCefChromeToggleReaderActive();
}

- (void)zoomIn:(id)sender {
    (void)sender;
    [self adjustZoomBy:kZoomStep];
}

- (void)zoomOut:(id)sender {
    (void)sender;
    [self adjustZoomBy:-kZoomStep];
}

- (void)zoomActual:(id)sender {
    (void)sender;
    CefRefPtr<CefBrowser> browser = LetheCefActiveBrowser();
    if (browser) browser->GetHost()->SetZoomLevel(0.0);
}

- (void)adjustZoomBy:(double)delta {
    CefRefPtr<CefBrowser> browser = LetheCefActiveBrowser();
    if (!browser) return;
    const double level = browser->GetHost()->GetZoomLevel() + delta;
    // Chromium's zoom levels are logarithmic; clamp to the same range the
    // Chrome UI offers so a held key cannot zoom into an unusable state.
    browser->GetHost()->SetZoomLevel(std::max(-7.6, std::min(7.6, level)));
}

- (void)showDevTools:(id)sender {
    (void)sender;
    CefRefPtr<CefBrowser> browser = LetheCefActiveBrowser();
    if (!browser) return;
    CefWindowInfo info;
    CefBrowserSettings settings;
    browser->GetHost()->ShowDevTools(info, nullptr, settings, CefPoint());
}

#pragma mark - History and bookmarks

- (void)goBack:(id)sender {
    (void)sender;
    CefRefPtr<CefBrowser> browser = LetheCefActiveBrowser();
    if (browser && browser->CanGoBack()) browser->GoBack();
}

- (void)goForward:(id)sender {
    (void)sender;
    CefRefPtr<CefBrowser> browser = LetheCefActiveBrowser();
    if (browser && browser->CanGoForward()) browser->GoForward();
}

- (void)goHome:(id)sender {
    (void)sender;
    LetheCefChromeLoadActive(LetheCefNewTabDataUrl());
}

- (void)showHistory:(id)sender {
    (void)sender;
    LetheCefChromeLoadActive(
        LetheDataURLForHTML(LetheHistoryPageHTML()).UTF8String);
}

- (void)clearHistory:(id)sender {
    (void)sender;
    [[LetheHistory shared] clear];
}

- (void)toggleBookmark:(id)sender {
    (void)sender;
    LetheCefChromeToggleBookmarkActive();
}

- (void)showBookmarks:(id)sender {
    (void)sender;
    LetheCefChromeLoadActive(
        LetheDataURLForHTML(LetheBookmarksPageHTML()).UTF8String);
}

#pragma mark - Privacy

- (void)clearBrowsingData:(id)sender {
    (void)sender;
    CefRefPtr<CefCookieManager> cookies =
        CefRequestContext::GetGlobalContext()->GetCookieManager(nullptr);
    if (cookies) cookies->DeleteCookies("", "", nullptr);
    CefRequestContext::GetGlobalContext()->ClearHttpAuthCredentials(nullptr);
    CefRequestContext::GetGlobalContext()->ClearCertificateExceptions(nullptr);
    [[LetheHistory shared] clear];
}

- (void)showPermissions:(id)sender {
    (void)sender;
    LetheCefChromeShowSettings();
}

#pragma mark - Window and help

- (void)selectNextTab:(id)sender {
    (void)sender;
    [NSApp.keyWindow selectNextTab:nil];
}

- (void)selectPreviousTab:(id)sender {
    (void)sender;
    [NSApp.keyWindow selectPreviousTab:nil];
}

- (void)openHelp:(id)sender {
    (void)sender;
    LetheCefChromeLoadActive("https://github.com/acotech/lethe#readme");
}

#pragma mark - Validation

- (BOOL)validateMenuItem:(NSMenuItem*)item {
    const SEL action = item.action;
    CefRefPtr<CefBrowser> browser = LetheCefActiveBrowser();
    if (action == @selector(goBack:)) return browser && browser->CanGoBack();
    if (action == @selector(goForward:)) return browser && browser->CanGoForward();
    if (action == @selector(findNext:) || action == @selector(findPrevious:))
        return self.findField.stringValue.length > 0;
    if (action == @selector(closeTab:) || action == @selector(printPage:) ||
        action == @selector(stopLoading:) || action == @selector(toggleReader:) ||
        action == @selector(zoomIn:) || action == @selector(zoomOut:) ||
        action == @selector(zoomActual:) || action == @selector(showDevTools:) ||
        action == @selector(toggleBookmark:) || action == @selector(hardReload:)) {
        return browser != nullptr;
    }
    return YES;
}

@end

void LetheCefInstallMenuBar(LetheCefAppDelegate* delegate) {
    static LetheCefMenuActions* actions = nil;
    if (!actions) actions = [[LetheCefMenuActions alloc] init];
    actions.delegate = delegate;

    const NSEventModifierFlags cmd = NSEventModifierFlagCommand;
    const NSEventModifierFlags cmdShift = cmd | NSEventModifierFlagShift;
    const NSEventModifierFlags cmdOpt = cmd | NSEventModifierFlagOption;
    const NSEventModifierFlags cmdCtrl = cmd | NSEventModifierFlagControl;
    const NSEventModifierFlags ctrl = NSEventModifierFlagControl;

    NSMenu* bar = [[NSMenu alloc] initWithTitle:@"Main Menu"];

    NSMenu* app = AddSubmenu(bar, @"Lethe");
    AddItem(app, @"About Lethe", @selector(orderFrontStandardAboutPanel:), @"", 0, nil);
    [app addItem:[NSMenuItem separatorItem]];
    AddItem(app, @"Settings…", @selector(showSettings:), @",", cmd, actions);
    AddItem(app, @"Security Status…", @selector(showSecurityStatus:), @"i", cmdShift, actions);
    [app addItem:[NSMenuItem separatorItem]];
    AddItem(app, @"Hide Lethe", @selector(hide:), @"h", cmd, nil);
    AddItem(app, @"Hide Others", @selector(hideOtherApplications:), @"h", cmdOpt, nil);
    AddItem(app, @"Show All", @selector(unhideAllApplications:), @"", 0, nil);
    [app addItem:[NSMenuItem separatorItem]];
    AddItem(app, @"Quit Lethe", @selector(terminate:), @"q", cmd, nil);

    NSMenu* file = AddSubmenu(bar, @"File");
    AddItem(file, @"New Tab", @selector(newTab:), @"t", cmd, actions);
    AddItem(file, @"New Oblivion Window", @selector(newOblivionWindow:), @"n", cmdShift, actions);
    AddItem(file, @"Open Location…", @selector(focusAddress:), @"l", cmd, actions);
    [file addItem:[NSMenuItem separatorItem]];
    AddItem(file, @"Close Tab", @selector(closeTab:), @"w", cmd, actions);
    AddItem(file, @"Close Window", @selector(closeWindow:), @"w", cmdShift, actions);
    [file addItem:[NSMenuItem separatorItem]];
    AddItem(file, @"Downloads", @selector(openDownloads:), @"j", cmdShift, actions);
    AddItem(file, @"Print…", @selector(printPage:), @"p", cmd, actions);

    NSMenu* edit = AddSubmenu(bar, @"Edit");
    AddItem(edit, @"Undo", @selector(undo:), @"z", cmd, actions);
    AddItem(edit, @"Redo", @selector(redo:), @"z", cmdShift, actions);
    [edit addItem:[NSMenuItem separatorItem]];
    AddItem(edit, @"Cut", @selector(cut:), @"x", cmd, actions);
    AddItem(edit, @"Copy", @selector(copy:), @"c", cmd, actions);
    AddItem(edit, @"Paste", @selector(paste:), @"v", cmd, actions);
    AddItem(edit, @"Select All", @selector(selectAll:), @"a", cmd, actions);
    [edit addItem:[NSMenuItem separatorItem]];
    AddItem(edit, @"Find…", @selector(showFindBar:), @"f", cmd, actions);
    AddItem(edit, @"Find Next", @selector(findNext:), @"g", cmd, actions);
    AddItem(edit, @"Find Previous", @selector(findPrevious:), @"g", cmdShift, actions);

    NSMenu* view = AddSubmenu(bar, @"View");
    AddItem(view, @"Reload Page", @selector(reloadPage:), @"r", cmd, actions);
    AddItem(view, @"Reload Ignoring Cache", @selector(hardReload:), @"r", cmdShift, actions);
    AddItem(view, @"Stop", @selector(stopLoading:), @".", cmd, actions);
    [view addItem:[NSMenuItem separatorItem]];
    AddItem(view, @"Reader View", @selector(toggleReader:), @"r", cmdOpt, actions);
    [view addItem:[NSMenuItem separatorItem]];
    AddItem(view, @"Actual Size", @selector(zoomActual:), @"0", cmd, actions);
    AddItem(view, @"Zoom In", @selector(zoomIn:), @"=", cmd, actions);
    AddItem(view, @"Zoom Out", @selector(zoomOut:), @"-", cmd, actions);
    [view addItem:[NSMenuItem separatorItem]];
    AddItem(view, @"Show Web Inspector", @selector(showDevTools:), @"i", cmdOpt, actions);
    AddItem(view, @"Enter Full Screen", @selector(toggleFullScreen:), @"f", cmdCtrl, nil);

    NSMenu* history = AddSubmenu(bar, @"History");
    AddItem(history, @"Back", @selector(goBack:), @"[", cmd, actions);
    AddItem(history, @"Forward", @selector(goForward:), @"]", cmd, actions);
    [history addItem:[NSMenuItem separatorItem]];
    AddItem(history, @"Home", @selector(goHome:), @"h", cmdShift, actions);
    [history addItem:[NSMenuItem separatorItem]];
    AddItem(history, @"Show All History…", @selector(showHistory:), @"y", cmd, actions);
    AddItem(history, @"Clear History", @selector(clearHistory:), @"", 0, actions);

    NSMenu* bookmarks = AddSubmenu(bar, @"Bookmarks");
    AddItem(bookmarks, @"Toggle Bookmark", @selector(toggleBookmark:), @"d", cmd, actions);
    AddItem(bookmarks, @"Show All Bookmarks…", @selector(showBookmarks:), @"", 0, actions);

    NSMenu* privacy = AddSubmenu(bar, @"Privacy");
    AddItem(privacy, @"Clear Browsing Data", @selector(clearBrowsingData:), @"", 0, actions);
    AddItem(privacy, @"Site Permissions…", @selector(showPermissions:), @"", 0, actions);

    NSMenu* window = AddSubmenu(bar, @"Window");
    AddItem(window, @"Minimize", @selector(performMiniaturize:), @"m", cmd, nil);
    AddItem(window, @"Zoom", @selector(performZoom:), @"", 0, nil);
    [window addItem:[NSMenuItem separatorItem]];
    AddItem(window, @"Show Previous Tab", @selector(selectPreviousTab:), @"\t",
            ctrl | NSEventModifierFlagShift, actions);
    AddItem(window, @"Show Next Tab", @selector(selectNextTab:), @"\t", ctrl, actions);
    AddItem(window, @"Merge All Windows", @selector(mergeAllWindows:), @"", 0, nil);
    [window addItem:[NSMenuItem separatorItem]];
    AddItem(window, @"Bring All to Front", @selector(arrangeInFront:), @"", 0, nil);
    [NSApp setWindowsMenu:window];

    NSMenu* help = AddSubmenu(bar, @"Help");
    AddItem(help, @"Lethe Help", @selector(openHelp:), @"?", cmd, actions);
    [NSApp setHelpMenu:help];

    [NSApp setMainMenu:bar];
}
