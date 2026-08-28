// LethePreferences.h - user-facing settings, persisted to JSON.
//
// Every property is keyed in the on-disk JSON. New properties get a
// default in -init and a fallback in -load (missing key = default). The
// JSON is forward-compatible: an older file loaded by a newer binary
// keeps its keys; a newer file loaded by an older binary is ignored
// for unknown keys (NSDictionary's -objectForKey: returns nil).
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString* const LethePreferencesDidChangeNotification;

// Theme values.
typedef NS_ENUM(NSInteger, LetheTheme) {
    LetheThemeSystem = 0,
    LetheThemeLight = 1,
    LetheThemeDark = 2,
};

// Search engines the address bar uses for non-URL input. The URL
// template is "{q}" for the search query; bare hostname ("duckduckgo")
// means HTTPS at the host root.
typedef NS_ENUM(NSInteger, LetheSearchEngine) {
    LetheSearchEngineDuckDuckGo = 0,  // https://duckduckgo.com/?q={q}
    LetheSearchEngineStartpage = 1,   // https://www.startpage.com/do/search?q={q}
    LetheSearchEngineBrave = 2,       // https://search.brave.com/search?q={q}
    LetheSearchEngineEcosia = 3,      // https://www.ecosia.org/search?q={q}
    LetheSearchEngineCustom = 4,      // user-defined template in customSearchURL
};

@interface LethePreferences : NSObject

// Privacy & Security
@property (nonatomic) BOOL trackerBlocking;       // built-in 3rd-party rule list
@property (nonatomic) BOOL httpsFirst;            // upgrade http -> https at nav time
@property (nonatomic) BOOL httpsOnly;             // refuse http entirely (no fallback)
@property (nonatomic) BOOL stealthUA;             // fixed low-entropy UA on every webview
@property (nonatomic) BOOL doNotTrack;            // send DNT=1 header on every request
@property (nonatomic) BOOL blockFingerprinting;   // canvas / font / audio context entropy
@property (nonatomic) BOOL blockThirdPartyCookies; // default YES; only relevant when persistent
@property (nonatomic) BOOL blockReferer;          // strip Referer on cross-origin nav
@property (nonatomic) BOOL blockWebRTC;           // WebRTC exposes local IPs; leak prevention

// Data
@property (nonatomic) BOOL persistentCookies;      // keep cookies/site data between runs
@property (nonatomic, copy) NSString* downloadsFolder; // default: ~/Downloads
@property (nonatomic, copy) NSString* homePage;    // empty = built-in new-tab page

// Network
@property (nonatomic, copy) NSString* dnsProvider; // URL template, default Cloudflare DoH
@property (nonatomic) BOOL dohSharedCache;         // one DoH answer cache for the browser
@property (nonatomic) BOOL dohPool;                // keep-alive resolver pool
@property (nonatomic) BOOL policyProxy;            // --no-proxy when NO (less safe, less load)
@property (nonatomic) BOOL isolatePrivateNetworks; // SSRF / private-range isolation
@property (nonatomic, copy) NSString* proxyAllow;  // comma-separated host:port allowlist

// Engine
@property (nonatomic) BOOL javaScript;             // default YES; pure UX (some users turn off)
@property (nonatomic) BOOL hardwareAcceleration;   // default YES on macOS; set NO to debug
@property (nonatomic) LetheTheme theme;           // system / light / dark
@property (nonatomic) LetheSearchEngine searchEngine;
@property (nonatomic, copy) NSString* customSearchURL; // used when searchEngine == Custom
@property (nonatomic, copy) NSString* language;    // BCP-47; default "en"

// Privacy of Lethe itself
@property (nonatomic) BOOL telemetry;              // default NO; we do not phone home
@property (nonatomic) BOOL crashReports;           // default NO; off by default

+ (instancetype)shared;
- (void)load;
- (void)save;
- (NSString*)summaryText;
// Search engine -> URL template ({q} substituted). Empty if engine is Custom
// and customSearchURL is empty.
- (NSString*)searchURLTemplate;
@end

NS_ASSUME_NONNULL_END
