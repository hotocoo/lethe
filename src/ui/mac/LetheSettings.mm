// LetheSettings.mm - the unified Settings window. See LetheSettings.h
// for the design. Each category is a NSView subclass below; the sidebar
// is an NSTableView with the category names.

#import "ui/mac/LetheSettings.h"
#import "ui/mac/LetheShell.h"
#import "ui/mac/LethePreferences.h"
#import "ui/mac/LethePermissions.h"

NSString* const LetheSettingsDidCloseNotification = @"LetheSettingsDidCloseNotification";

#pragma mark - Helpers

static NSButton* makeCheckbox(NSView* parent, NSString* title, BOOL on, SEL action, id target) {
    NSButton* cb = [NSButton buttonWithTitle:title target:target action:action];
    cb.buttonType = NSSwitchButton;
    cb.state = on ? NSControlStateValueOn : NSControlStateValueOff;
    [parent addSubview:cb];
    return cb;
}

static NSButton* placeCheckbox(NSButton* cb, CGFloat x, CGFloat y, CGFloat w) {
    cb.frame = NSMakeRect(x, y, w, 22);
    cb.autoresizingMask = NSViewMaxXMargin | NSViewMinYMargin;
    return cb;
}

static NSTextField* sectionHeader(NSView* parent, NSString* text, CGFloat y) {
    NSTextField* h = [NSTextField labelWithString:text];
    h.font = [NSFont systemFontOfSize:11 weight:NSFontWeightSemibold];
    h.textColor = [NSColor secondaryLabelColor];
    h.frame = NSMakeRect(20, y, 540, 16);
    [parent addSubview:h];
    return h;
}

static NSTextField* helpText(NSView* parent, NSString* text, CGFloat y, CGFloat w) {
    NSTextField* t = [NSTextField labelWithString:text];
    t.font = [NSFont systemFontOfSize:11];
    t.textColor = [NSColor tertiaryLabelColor];
    t.frame = NSMakeRect(36, y, w, 14);
    [parent addSubview:t];
    return t;
}

#pragma mark - Category: General

@interface LetheSettingsGeneral : NSView
@property (nonatomic) NSTextField* homePageField;
@property (nonatomic) NSTextField* downloadsField;
@property (nonatomic) NSPopUpButton* searchEnginePopup;
@property (nonatomic) NSTextField* customSearchField;
@property (nonatomic) NSPopUpButton* languagePopup;
@property (nonatomic) NSPopUpButton* themePopup;
@end

@implementation LetheSettingsGeneral
- (instancetype)initWithFrame:(NSRect)frame {
    if ((self = [super initWithFrame:frame])) {
        LethePreferences* p = [LethePreferences shared];
        CGFloat y = frame.size.height - 40;
        sectionHeader(self, @"HOME PAGE", y); y -= 24;
        NSTextField* h = [NSTextField labelWithString:@"URL to load when a new tab is opened. Empty = built-in new-tab page."];
        h.font = [NSFont systemFontOfSize:11]; h.textColor = [NSColor tertiaryLabelColor];
        h.frame = NSMakeRect(36, y, 540, 14); [self addSubview:h]; y -= 22;
        _homePageField = [[NSTextField alloc] initWithFrame:NSMakeRect(20, y, 540, 24)];
        _homePageField.stringValue = p.homePage ?: @"";
        _homePageField.bezelStyle = NSTextFieldRoundedBezel;
        _homePageField.placeholderString = @"https://example.com/  (or leave empty for new-tab page)";
        [self addSubview:_homePageField]; y -= 36;

        sectionHeader(self, @"DOWNLOADS", y); y -= 24;
        NSTextField* d = [NSTextField labelWithString:@"Where downloaded files are saved by default."];
        d.font = [NSFont systemFontOfSize:11]; d.textColor = [NSColor tertiaryLabelColor];
        d.frame = NSMakeRect(36, y, 540, 14); [self addSubview:d]; y -= 22;
        _downloadsField = [[NSTextField alloc] initWithFrame:NSMakeRect(20, y, 540, 24)];
        _downloadsField.stringValue = p.downloadsFolder ?: @"";
        _downloadsField.bezelStyle = NSTextFieldRoundedBezel;
        [self addSubview:_downloadsField]; y -= 36;

        sectionHeader(self, @"SEARCH ENGINE", y); y -= 24;
        _searchEnginePopup = [[NSPopUpButton alloc] initWithFrame:NSMakeRect(20, y, 260, 26)];
        [_searchEnginePopup addItemsWithTitles:@[@"DuckDuckGo", @"Startpage", @"Brave Search", @"Ecosia", @"Custom…"]];
        NSInteger selIdx = 0;
        switch (p.searchEngine) {
            case LetheSearchEngineDuckDuckGo: selIdx = 0; break;
            case LetheSearchEngineStartpage:  selIdx = 1; break;
            case LetheSearchEngineBrave:      selIdx = 2; break;
            case LetheSearchEngineEcosia:     selIdx = 3; break;
            case LetheSearchEngineCustom:     selIdx = 4; break;
        }
        [_searchEnginePopup selectItemAtIndex:selIdx];
        [self addSubview:_searchEnginePopup]; y -= 30;
        _customSearchField = [[NSTextField alloc] initWithFrame:NSMakeRect(20, y, 540, 24)];
        _customSearchField.stringValue = p.customSearchURL ?: @"";
        _customSearchField.bezelStyle = NSTextFieldRoundedBezel;
        _customSearchField.placeholderString = @"https://my-search.example/?q={q}";
        [self addSubview:_customSearchField]; y -= 36;

        sectionHeader(self, @"APPEARANCE", y); y -= 24;
        _themePopup = [[NSPopUpButton alloc] initWithFrame:NSMakeRect(20, y, 200, 26)];
        [_themePopup addItemsWithTitles:@[@"Follow System", @"Light", @"Dark"]];
        [_themePopup selectItemAtIndex:p.theme];
        [self addSubview:_themePopup]; y -= 30;
        NSTextField* th = [NSTextField labelWithString:@"Light or dark applies even when the system is in the other mode."];
        th.font = [NSFont systemFontOfSize:11]; th.textColor = [NSColor tertiaryLabelColor];
        th.frame = NSMakeRect(36, y, 540, 14); [self addSubview:th]; y -= 30;

        sectionHeader(self, @"LANGUAGE", y); y -= 24;
        _languagePopup = [[NSPopUpButton alloc] initWithFrame:NSMakeRect(20, y, 200, 26)];
        [_languagePopup addItemsWithTitles:@[@"English (en)", @"中文 (zh)", @"日本語 (ja)", @"Deutsch (de)", @"Español (es)", @"Français (fr)"]];
        NSString* langs[] = {@"en", @"zh", @"ja", @"de", @"es", @"fr"};
        NSInteger langIdx = 0;
        for (int i = 0; i < 6; i++) if ([p.language isEqualToString:langs[i]]) langIdx = i;
        [_languagePopup selectItemAtIndex:langIdx];
        [self addSubview:_languagePopup];
    }
    return self;
}
- (void)saveToPreferences:(LethePreferences*)p {
    p.homePage = _homePageField.stringValue ?: @"";
    p.downloadsFolder = _downloadsField.stringValue ?: @"";
    switch (_searchEnginePopup.indexOfSelectedItem) {
        case 0: p.searchEngine = LetheSearchEngineDuckDuckGo; break;
        case 1: p.searchEngine = LetheSearchEngineStartpage; break;
        case 2: p.searchEngine = LetheSearchEngineBrave; break;
        case 3: p.searchEngine = LetheSearchEngineEcosia; break;
        case 4: p.searchEngine = LetheSearchEngineCustom; break;
    }
    p.customSearchURL = _customSearchField.stringValue ?: @"";
    switch (_themePopup.indexOfSelectedItem) {
        case 1: p.theme = LetheThemeLight; break;
        case 2: p.theme = LetheThemeDark; break;
        default: p.theme = LetheThemeSystem; break;
    }
    NSString* langs[] = {@"en", @"zh", @"ja", @"de", @"es", @"fr"};
    p.language = langs[_languagePopup.indexOfSelectedItem] ?: @"en";
}
@end

#pragma mark - Category: Privacy

@interface LetheSettingsPrivacy : NSView
@property (nonatomic) NSMutableDictionary<NSString*, NSButton*>* boxes;
@end

@implementation LetheSettingsPrivacy
- (instancetype)initWithFrame:(NSRect)frame {
    if ((self = [super initWithFrame:frame])) {
        _boxes = [NSMutableDictionary dictionary];
        LethePreferences* p = [LethePreferences shared];
        CGFloat y = frame.size.height - 40;
        sectionHeader(self, @"PROTECTIONS", y); y -= 24;
        NSDictionary* desc = @{
            @"trackerBlocking": @"Block known third-party trackers (built-in curated list).",
            @"httpsFirst": @"Try https:// before falling back to http://.",
            @"httpsOnly": @"Refuse plain http:// entirely. No fallback prompt.",
            @"stealthUA": @"Replace the User-Agent with a fixed low-entropy profile.",
            @"doNotTrack": @"Send DNT=1 on every request. Honored by respectful sites.",
            @"blockFingerprinting": @"Reduce canvas / font / audio-context entropy.",
            @"blockThirdPartyCookies": @"Reject cookies set by sites other than the one in the URL bar.",
            @"blockReferer": @"Strip the Referer header on cross-origin navigations.",
            @"blockWebRTC": @"Block WebRTC. WebRTC can leak local network addresses even over VPN.",
            @"persistentCookies": @"Keep cookies and site data between launches. Off = incognito.",
        };
        NSArray* keys = @[@"trackerBlocking", @"httpsFirst", @"httpsOnly", @"stealthUA",
                          @"doNotTrack", @"blockFingerprinting", @"blockThirdPartyCookies",
                          @"blockReferer", @"blockWebRTC", @"persistentCookies"];
        NSArray* titles = @[@"Block third-party trackers",
                            @"HTTPS-first",
                            @"HTTPS-only (refuse plain http)",
                            @"Stealth user agent",
                            @"Send Do Not Track",
                            @"Block fingerprinting",
                            @"Block third-party cookies",
                            @"Strip Referer on cross-origin",
                            @"Block WebRTC",
                            @"Persistent cookies (kept between launches)"];
        for (NSUInteger i = 0; i < keys.count; i++) {
            NSString* k = keys[i];
            BOOL on = NO;
            id v = [p valueForKey:k];
            if ([v respondsToSelector:@selector(boolValue)]) on = [v boolValue];
            NSButton* cb = makeCheckbox(self, titles[i], on, @selector(noop:), nil);
            placeCheckbox(cb, 20, y - 22, 540);
            _boxes[k] = cb;
            helpText(self, desc[k], y - 36, 540);
            y -= 56;
        }
        sectionHeader(self, @"PRIVACY OF LETHE ITSELF", y); y -= 24;
        NSButton* tele = makeCheckbox(self, @"Send anonymous usage telemetry", p.telemetry, @selector(noop:), nil);
        placeCheckbox(tele, 20, y - 22, 540);
        _boxes[@"telemetry"] = tele;
        helpText(self, @"Off by default. When on, sends a daily ping with no page URLs or identifiers.", y - 36, 540);
        y -= 56;
        NSButton* crash = makeCheckbox(self, @"Send crash reports", p.crashReports, @selector(noop:), nil);
        placeCheckbox(crash, 20, y - 22, 540);
        _boxes[@"crashReports"] = crash;
        helpText(self, @"Off by default. When on, sends stack traces without personally identifiable information.", y - 36, 540);
    }
    return self;
}
- (void)saveToPreferences:(LethePreferences*)p {
    for (NSString* k in _boxes) {
        BOOL on = _boxes[k].state == NSControlStateValueOn;
        [p setValue:@(on) forKey:k];
    }
}
- (void)noop:(id)sender { (void)sender; }
@end

#pragma mark - Category: Permissions

@interface LetheSettingsPermissions : NSView
@property (nonatomic) NSTableView* table;
@property (nonatomic) NSMutableArray* rows;
@end

@implementation LetheSettingsPermissions
- (instancetype)initWithFrame:(NSRect)frame {
    if ((self = [super initWithFrame:frame])) {
        _rows = [NSMutableArray array];
        [self reloadRows];
        NSTextField* h = [NSTextField labelWithString:@"Per-site decisions you have made. Use Allow / Deny / Ask to change a row. Clear removes the stored decision (back to Ask). Clear All wipes every stored decision."];
        h.font = [NSFont systemFontOfSize:11];
        h.textColor = [NSColor tertiaryLabelColor];
        h.frame = NSMakeRect(20, frame.size.height - 50, 540, 32);
        h.lineBreakMode = NSLineBreakByWordWrapping;
        h.maximumNumberOfLines = 2;
        [self addSubview:h];

        NSScrollView* sv = [[NSScrollView alloc] initWithFrame:NSMakeRect(20, 60, 540, frame.size.height - 110)];
        sv.hasVerticalScroller = YES;
        sv.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
        _table = [[NSTableView alloc] initWithFrame:sv.bounds];
        _table.headerView = nil;
        NSTableColumn* col = [[NSTableColumn alloc] initWithIdentifier:@"d"];
        col.title = @"Decision"; col.width = 524; col.resizingMask = NSTableColumnAutoresizingMask;
        [_table addTableColumn:col];
        sv.documentView = _table;
        [self addSubview:sv];

        NSButton* clear = [NSButton buttonWithTitle:@"Clear All"
                                            target:self action:@selector(clearAll:)];
        clear.bezelStyle = NSBezelStyleRounded;
        clear.frame = NSMakeRect(20, 20, 110, 28);
        [self addSubview:clear];
        NSButton* reload = [NSButton buttonWithTitle:@"Reload"
                                             target:self action:@selector(reload:)];
        reload.bezelStyle = NSBezelStyleRounded;
        reload.frame = NSMakeRect(140, 20, 90, 28);
        [self addSubview:reload];
    }
    return self;
}
- (void)reloadRows {
    [_rows removeAllObjects];
    NSString* path = [[NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory,
                                                          NSUserDomainMask, YES).firstObject
                       stringByAppendingPathComponent:@"Lethe"]
                      stringByAppendingPathComponent:@"permissions.json"];
    NSDictionary* dict = [NSDictionary dictionaryWithContentsOfFile:path];
    if (![dict isKindOfClass:[NSDictionary class]]) { [_table reloadData]; return; }
    NSArray* keys = [dict.allKeys sortedArrayUsingSelector:@selector(compare:)];
    for (NSString* k in keys) {
        NSDictionary* d = dict[k];
        if (![d isKindOfClass:[NSDictionary class]]) continue;
        for (NSString* type in @[@"camera", @"microphone", @"geolocation"]) {
            id v = d[type];
            if (![v isKindOfClass:[NSString class]]) continue;
            [_rows addObject:@{ @"host": k, @"type": type,
                                @"decision": [v isEqualToString:@"allow"] ? @"Allow" : @"Deny" }];
        }
    }
    [_table reloadData];
}
- (void)reload:(id)sender { (void)sender; [self reloadRows]; }
- (void)clearAll:(id)sender {
    (void)sender;
    [[LethePermissions shared] clearAll];
    [self reloadRows];
}
- (NSInteger)numberOfRowsInTableView:(NSTableView*)tv { return (NSInteger)_rows.count; }
- (NSView*)tableView:(NSTableView*)tv viewForTableColumn:(NSTableColumn*)col row:(NSInteger)row {
    NSDictionary* r = _rows[row];
    NSTableCellView* cell = [[NSTableCellView alloc] initWithFrame:NSMakeRect(0, 0, 524, 28)];
    NSTextField* label = [NSTextField labelWithString:[NSString stringWithFormat:@"%@ — %@ (%@)",
                                                       r[@"host"], r[@"type"], r[@"decision"]]];
    label.font = [NSFont systemFontOfSize:13];
    label.frame = NSMakeRect(8, 6, 380, 18);
    [cell addSubview:label];
    NSInteger tag = 100 + row;
    NSButton* allow = [NSButton buttonWithTitle:@"Allow" target:self action:@selector(allow:)];
    allow.bezelStyle = NSBezelStyleSmallSquare; allow.tag = tag; allow.frame = NSMakeRect(390, 4, 40, 22);
    [cell addSubview:allow];
    NSButton* deny = [NSButton buttonWithTitle:@"Deny" target:self action:@selector(deny:)];
    deny.bezelStyle = NSBezelStyleSmallSquare; deny.tag = tag; deny.frame = NSMakeRect(432, 4, 40, 22);
    [cell addSubview:deny];
    NSButton* ask = [NSButton buttonWithTitle:@"Ask" target:self action:@selector(ask:)];
    ask.bezelStyle = NSBezelStyleSmallSquare; ask.tag = tag; ask.frame = NSMakeRect(474, 4, 40, 22);
    [cell addSubview:ask];
    return cell;
}
- (void)allow:(NSButton*)sender {
    NSDictionary* r = _rows[sender.tag - 100];
    [[LethePermissions shared] setDecision:LethePermissionAllow forHost:r[@"host"] type:r[@"type"] remember:YES];
    [self reloadRows];
}
- (void)deny:(NSButton*)sender {
    NSDictionary* r = _rows[sender.tag - 100];
    [[LethePermissions shared] setDecision:LethePermissionDeny forHost:r[@"host"] type:r[@"type"] remember:YES];
    [self reloadRows];
}
- (void)ask:(NSButton*)sender {
    NSDictionary* r = _rows[sender.tag - 100];
    [[LethePermissions shared] clearforHost:r[@"host"] type:r[@"type"]];
    [self reloadRows];
}
@end

#pragma mark - Category: Network

@interface LetheSettingsNetwork : NSView
@property (nonatomic) NSTextField* dnsField;
@property (nonatomic) NSButton* dohCacheBox;
@property (nonatomic) NSButton* dohPoolBox;
@property (nonatomic) NSButton* policyProxyBox;
@property (nonatomic) NSButton* isolatePrivateBox;
@property (nonatomic) NSTextField* proxyAllowField;
@end

@implementation LetheSettingsNetwork
- (instancetype)initWithFrame:(NSRect)frame {
    if ((self = [super initWithFrame:frame])) {
        LethePreferences* p = [LethePreferences shared];
        CGFloat y = frame.size.height - 40;
        sectionHeader(self, @"DNS", y); y -= 24;
        NSTextField* h = [NSTextField labelWithString:@"DNS-over-HTTPS provider. Default is Cloudflare. Other reasonable choices: Quad9, Adguard, Mullvad."];
        h.font = [NSFont systemFontOfSize:11]; h.textColor = [NSColor tertiaryLabelColor];
        h.frame = NSMakeRect(36, y, 540, 14); [self addSubview:h]; y -= 22;
        _dnsField = [[NSTextField alloc] initWithFrame:NSMakeRect(20, y, 540, 24)];
        _dnsField.stringValue = p.dnsProvider ?: @"";
        _dnsField.bezelStyle = NSTextFieldRoundedBezel;
        _dnsField.placeholderString = @"https://cloudflare-dns.com/dns-query";
        [self addSubview:_dnsField]; y -= 36;
        _dohCacheBox = makeCheckbox(self, @"DoH shared cache (one answer shared by gate, reader, proxy)", p.dohSharedCache, @selector(noop:), nil);
        placeCheckbox(_dohCacheBox, 20, y - 22, 540);
        y -= 28;
        _dohPoolBox = makeCheckbox(self, @"DoH keep-alive pool (reuses TLS to the provider)", p.dohPool, @selector(noop:), nil);
        placeCheckbox(_dohPoolBox, 20, y - 22, 540);
        y -= 36;

        sectionHeader(self, @"PROXY", y); y -= 24;
        _policyProxyBox = makeCheckbox(self, @"Route engine traffic through the local policy proxy", p.policyProxy, @selector(noop:), nil);
        placeCheckbox(_policyProxyBox, 20, y - 22, 540);
        helpText(self, @"Required for subresource enforcement. Disabling reduces protection to navigation-gate only.", y - 36, 540);
        y -= 56;
        _isolatePrivateBox = makeCheckbox(self, @"Isolate private network ranges (SSRF prevention)", p.isolatePrivateNetworks, @selector(noop:), nil);
        placeCheckbox(_isolatePrivateBox, 20, y - 22, 540);
        y -= 28;
        NSTextField* pl = [NSTextField labelWithString:@"Comma-separated host:port pairs that may bypass private-network isolation."];
        pl.font = [NSFont systemFontOfSize:11]; pl.textColor = [NSColor tertiaryLabelColor];
        pl.frame = NSMakeRect(20, y, 540, 14); [self addSubview:pl]; y -= 22;
        _proxyAllowField = [[NSTextField alloc] initWithFrame:NSMakeRect(20, y, 540, 24)];
        _proxyAllowField.stringValue = p.proxyAllow ?: @"";
        _proxyAllowField.bezelStyle = NSTextFieldRoundedBezel;
        _proxyAllowField.placeholderString = @"router.local:80, 192.168.1.0/24:8080";
        [self addSubview:_proxyAllowField];
    }
    return self;
}
- (void)saveToPreferences:(LethePreferences*)p {
    p.dnsProvider = _dnsField.stringValue ?: @"";
    p.dohSharedCache = _dohCacheBox.state == NSControlStateValueOn;
    p.dohPool = _dohPoolBox.state == NSControlStateValueOn;
    p.policyProxy = _policyProxyBox.state == NSControlStateValueOn;
    p.isolatePrivateNetworks = _isolatePrivateBox.state == NSControlStateValueOn;
    p.proxyAllow = _proxyAllowField.stringValue ?: @"";
}
- (void)noop:(id)sender { (void)sender; }
@end

#pragma mark - Category: Engine

@interface LetheSettingsEngine : NSView
@property (nonatomic) NSButton* jsBox;
@property (nonatomic) NSButton* hwBox;
@end

@implementation LetheSettingsEngine
- (instancetype)initWithFrame:(NSRect)frame {
    if ((self = [super initWithFrame:frame])) {
        LethePreferences* p = [LethePreferences shared];
        CGFloat y = frame.size.height - 40;
        sectionHeader(self, @"ENGINE", y); y -= 24;
        _jsBox = makeCheckbox(self, @"JavaScript", p.javaScript, @selector(noop:), nil);
        placeCheckbox(_jsBox, 20, y - 22, 540);
        helpText(self, @"Disable to break most modern sites. Use only for known-bad pages or untrusted content.", y - 36, 540);
        y -= 56;
        _hwBox = makeCheckbox(self, @"Hardware acceleration", p.hardwareAcceleration, @selector(noop:), nil);
        placeCheckbox(_hwBox, 20, y - 22, 540);
        helpText(self, @"Off = software rendering. Useful for debugging GPU-related rendering bugs; large perf cost on real pages.", y - 36, 540);
        y -= 56;
        sectionHeader(self, @"ENGINE CHOICE", y); y -= 24;
        NSTextField* h = [NSTextField labelWithString:@"v0.1.1 ships the system WebKit (AppKit + WKWebView) only. The CEF (Chromium / Blink) shell lands in v1.0; this setting will then pick which engine Lethe uses on launch."];
        h.font = [NSFont systemFontOfSize:11]; h.textColor = [NSColor tertiaryLabelColor];
        h.frame = NSMakeRect(20, y, 540, 40);
        h.lineBreakMode = NSLineBreakByWordWrapping;
        h.maximumNumberOfLines = 3;
        [self addSubview:h];
    }
    return self;
}
- (void)saveToPreferences:(LethePreferences*)p {
    p.javaScript = _jsBox.state == NSControlStateValueOn;
    p.hardwareAcceleration = _hwBox.state == NSControlStateValueOn;
}
- (void)noop:(id)sender { (void)sender; }
@end

#pragma mark - Category: Shortcuts

@interface LetheSettingsShortcuts : NSTextView
@end

@implementation LetheSettingsShortcuts
- (instancetype)initWithFrame:(NSRect)frame {
    NSTextView* tv = [[NSTextView alloc] initWithFrame:frame];
    if ((self = (LetheSettingsShortcuts*)tv)) {
        tv.editable = NO; tv.selectable = YES; tv.backgroundColor = [NSColor textBackgroundColor];
        tv.font = [NSFont userFixedPitchFontOfSize:12] ?: [NSFont systemFontOfSize:12];
        tv.textContainerInset = NSMakeSize(16, 16);
        tv.string = [self shortcutList];
    }
    return self;
}
- (NSString*)shortcutList {
    return @"Keyboard shortcuts (v0.1.1):\n\n"
           @"  Tabs and windows\n"
           @"    Cmd+T            New tab\n"
           @"    Cmd+W            Close current tab / window\n"
           @"    Cmd+Shift+N      New Oblivion window\n"
           @"    Cmd+L            Focus address bar\n"
           @"    Cmd+\\           Find in Tabs\n"
           @"    Ctrl+Tab         Next tab\n"
           @"    Ctrl+Shift+Tab   Previous tab\n\n"
           @"  Page\n"
           @"    Cmd+R            Reload\n"
           @"    Cmd+.            Stop loading\n"
           @"    Cmd+Shift+R      Reader View\n"
           @"    Cmd+D            Toggle bookmark on the current page\n"
           @"    Cmd+F            Find in page\n"
           @"    Cmd+Y            Show all history\n"
           @"    Cmd+Shift+I      Show Web Inspector\n\n"
           @"  Privacy and data\n"
           @"    Cmd+,            Settings\n"
           @"    Privacy menu     Site permissions / clear data / VPN\n\n"
           @"  Window\n"
           @"    Cmd+M            Minimize\n"
           @"    Cmd+Ctrl+F       Enter full screen\n"
           @"    Cmd+0            Actual size\n"
           @"    Cmd+= / Cmd+-    Zoom in / out\n";
}
@end

#pragma mark - Category: About

@interface LetheSettingsAbout : NSView
@end

@implementation LetheSettingsAbout
- (instancetype)initWithFrame:(NSRect)frame {
    if ((self = [super initWithFrame:frame])) {
        CGFloat y = frame.size.height - 40;
        NSTextField* t = [NSTextField labelWithString:@"Lethe"];
        t.font = [NSFont systemFontOfSize:36 weight:NSFontWeightSemibold];
        t.frame = NSMakeRect(20, y - 40, 540, 44); [self addSubview:t]; y -= 60;
        NSTextField* v = [NSTextField labelWithString:[NSString stringWithFormat:@"Version %s  (system WebKit)", LETHE_VERSION]];
        v.font = [NSFont systemFontOfSize:13];
        v.textColor = [NSColor secondaryLabelColor];
        v.frame = NSMakeRect(20, y - 18, 540, 18); [self addSubview:v]; y -= 40;
        NSString* blurb = @"A privacy-hardened network stack wrapped in a native macOS browser shell.\n\nWhat it does:\n  - DoH-only DNS, shared cache, keep-alive pool\n  - HTTPS-first; optional HTTPS-only\n  - Local policy proxy routes engine traffic so subresources are policy-checked\n  - Private-network isolation (SSRF prevention)\n  - Built-in third-party tracker rules\n  - Built-in WireGuard-style VPN with fail-closed routing\n  - Per-site permission decisions (camera, mic, geolocation)\n  - Oblivion windows: in-memory data store wiped on close\n\nNo analytics, no telemetry, no crash reports are sent by default.\nSource: github.com/hotocoo/lethe";
        NSTextField* b = [NSTextField labelWithString:blurb];
        b.font = [NSFont systemFontOfSize:12];
        b.frame = NSMakeRect(20, 20, 540, y - 30);
        b.lineBreakMode = NSLineBreakByWordWrapping;
        b.maximumNumberOfLines = 0;
        b.autoresizingMask = NSViewHeightSizable | NSViewWidthSizable;
        [self addSubview:b];
    }
    return self;
}
@end

#pragma mark - Window controller

@interface LetheSettings () <NSTableViewDataSource, NSTableViewDelegate>
@property (nonatomic) NSWindow* window;
@property (nonatomic) NSTableView* sidebar;
@property (nonatomic) NSView* contentContainer;
@property (nonatomic) NSArray* categories;
@property (nonatomic) NSMutableArray* contentViews;
@property (nonatomic) NSView* currentContent;
@end

@implementation LetheSettings

+ (instancetype)shared {
    static LetheSettings* s; static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [[LetheSettings alloc] init]; });
    return s;
}

- (instancetype)init {
    if ((self = [super init])) {
        _categories = @[ @"General", @"Privacy", @"Permissions",
                         @"Network", @"Engine", @"Shortcuts", @"About" ];
        _contentViews = [NSMutableArray array];
    }
    return self;
}

- (void)show { [self showCategory:@"General"]; }

- (void)showCategory:(NSString*)category {
    if (!self.window) [self buildWindow];
    NSInteger idx = [_categories indexOfObject:category];
    if (idx == NSNotFound) idx = 0;
    [_sidebar selectRowIndexes:[NSIndexSet indexSetWithIndex:idx] byExtendingSelection:NO];
    [self swapToCategory:idx];
    [self.window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];
}

- (void)buildWindow {
    NSRect frame = NSMakeRect(0, 0, 800, 520);
    _window = [[NSWindow alloc] initWithContentRect:frame
        styleMask:NSWindowStyleMaskTitled | NSWindowStyleMaskClosable | NSWindowStyleMaskMiniaturizable
        backing:NSBackingStoreBuffered defer:NO];
    _window.title = @"Settings";
    _window.releasedWhenClosed = NO;
    _window.minSize = NSMakeSize(720, 460);
    [_window center];
    [_window setFrameAutosaveName:@"LetheSettingsWindow"];

    NSView* root = _window.contentView;

    NSTextField* title = [NSTextField labelWithString:@"Settings"];
    title.font = [NSFont systemFontOfSize:18 weight:NSFontWeightSemibold];
    title.frame = NSMakeRect(20, frame.size.height - 40, 200, 26);
    title.autoresizingMask = NSViewMinYMargin;
    [root addSubview:title];

    NSScrollView* sideSv = [[NSScrollView alloc] initWithFrame:NSMakeRect(20, 20, 180, frame.size.height - 80)];
    sideSv.hasVerticalScroller = YES;
    sideSv.autoresizingMask = NSViewHeightSizable | NSViewMaxXMargin;
    [root addSubview:sideSv];
    _sidebar = [[NSTableView alloc] initWithFrame:sideSv.bounds];
    _sidebar.headerView = nil;
    _sidebar.dataSource = self;
    _sidebar.delegate = self;
    _sidebar.rowHeight = 28;
    _sidebar.allowsEmptySelection = NO;
    NSTableColumn* c = [[NSTableColumn alloc] initWithIdentifier:@"name"];
    c.title = @"Category"; c.width = 160; c.resizingMask = NSTableColumnAutoresizingMask;
    [_sidebar addTableColumn:c];
    sideSv.documentView = _sidebar;

    _contentContainer = [[NSView alloc] initWithFrame:NSMakeRect(220, 60, frame.size.width - 240, frame.size.height - 80)];
    _contentContainer.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
    [root addSubview:_contentContainer];

    NSButton* save = [NSButton buttonWithTitle:@"Save"
                                        target:self action:@selector(saveAll:)];
    save.bezelStyle = NSBezelStyleRounded;
    save.frame = NSMakeRect(frame.size.width - 200, 16, 80, 28);
    save.autoresizingMask = NSViewMinXMargin | NSViewMaxYMargin;
    save.keyEquivalent = @"\r";
    [root addSubview:save];
    NSButton* cancel = [NSButton buttonWithTitle:@"Cancel"
                                          target:self action:@selector(cancel:)];
    cancel.bezelStyle = NSBezelStyleRounded;
    cancel.frame = NSMakeRect(frame.size.width - 110, 16, 80, 28);
    cancel.autoresizingMask = NSViewMinXMargin | NSViewMaxYMargin;
    cancel.keyEquivalent = [NSString stringWithFormat:@"%c", 27];
    [root addSubview:cancel];

    NSRect cr = _contentContainer.bounds;
    [_contentViews addObject:[[LetheSettingsGeneral alloc] initWithFrame:cr]];
    [_contentViews addObject:[[LetheSettingsPrivacy alloc] initWithFrame:cr]];
    [_contentViews addObject:[[LetheSettingsPermissions alloc] initWithFrame:cr]];
    [_contentViews addObject:[[LetheSettingsNetwork alloc] initWithFrame:cr]];
    [_contentViews addObject:[[LetheSettingsEngine alloc] initWithFrame:cr]];
    [_contentViews addObject:[[LetheSettingsShortcuts alloc] initWithFrame:cr]];
    [_contentViews addObject:[[LetheSettingsAbout alloc] initWithFrame:cr]];

    [[NSNotificationCenter defaultCenter] addObserver:self
        selector:@selector(windowWillClose:)
        name:NSWindowWillCloseNotification object:_window];
}

- (void)windowWillClose:(NSNotification*)n {
    (void)n;
    [[NSNotificationCenter defaultCenter] postNotificationName:LetheSettingsDidCloseNotification object:self];
}

- (void)swapToCategory:(NSInteger)idx {
    if (_currentContent) [_currentContent removeFromSuperview];
    NSView* v = _contentViews[idx];
    v.frame = _contentContainer.bounds;
    v.autoresizingMask = NSViewWidthSizable | NSViewHeightSizable;
    [_contentContainer addSubview:v];
    _currentContent = v;
}

- (NSInteger)numberOfRowsInTableView:(NSTableView*)tv { return (NSInteger)_categories.count; }

- (NSView*)tableView:(NSTableView*)tv viewForTableColumn:(NSTableColumn*)col row:(NSInteger)row {
    NSTableCellView* cell = [[NSTableCellView alloc] initWithFrame:NSMakeRect(0, 0, 160, 28)];
    NSTextField* t = [NSTextField labelWithString:_categories[row]];
    t.font = [NSFont systemFontOfSize:13];
    t.frame = NSMakeRect(8, 6, 144, 18);
    [cell addSubview:t];
    return cell;
}

- (void)tableViewSelectionDidChange:(NSNotification*)n {
    (void)n;
    NSInteger row = _sidebar.selectedRow;
    if (row < 0) return;
    [self swapToCategory:row];
}

- (void)saveAll:(id)sender {
    (void)sender;
    LethePreferences* p = [LethePreferences shared];
    for (NSView* v in _contentViews) {
        if ([v respondsToSelector:@selector(saveToPreferences:)]) {
            [(id) v saveToPreferences:p];
        }
    }
    [p save];
    [self.window close];
}

- (void)cancel:(id)sender {
    (void)sender;
    [self.window close];
}

- (void)dealloc {
    [[NSNotificationCenter defaultCenter] removeObserver:self];
}
@end
