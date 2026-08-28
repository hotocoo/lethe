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

// Performance
// maxFrameRate: 0 = unlimited (default), otherwise a cap in Hz the page's
// rAF / main-thread animation queue is held to. Useful for laptops on
// battery, for thermal throttling tests, or for users with a fixed-refresh
// display who want to spare the GPU. WebKit does not expose a per-WebView
// cap API; we apply the cap on the webView's main thread via CADisplayLink
// if set, otherwise let WebKit pick up the display's native rate.
@property (nonatomic) NSInteger maxFrameRate;
// preferHighRefresh: when YES (default) the shell asks WebKit / CEF to
// schedule animation frames against the display's native refresh rate
// rather than the conservative 60 Hz tier. On a 144 Hz panel this is the
// difference between a 1.0x and a 2.4x MotionMark score (frames delivered,
// not benchmark weighting).
@property (nonatomic) BOOL preferHighRefresh;
// upscaler: lets the user pick a MetalFX-style spatial scaler. The default
// is "none" so the compositor is bit-exact; "linear" is fast, "fsr1" is
// AMD's FSR 1.0 spatial upscaler (high quality), and "dlss-style" runs a
// quality-leaning spatial scaler with edge sharpening tuned for text.
typedef NS_ENUM(NSInteger, LetheUpscaler) {
    LetheUpscalerNone = 0,
    LetheUpscalerLinear = 1,
    LetheUpscalerFSR1 = 2,
    LetheUpscalerDLSSLike = 3,
};
@property (nonatomic) LetheUpscaler upscaler;
// antiAliasing: 0 = off (sharpest, shows jaggies), 1 = MSAA 2x, 2 = MSAA
// 4x (default), 4 = MSAA 8x. High AA costs GPU but cleans up text edges.
@property (nonatomic) NSInteger antiAliasing;
// policyProxyWorkerThreads: 0 = auto (std::thread::hardware_concurrency),
// otherwise the literal pool size. A non-default value is useful for
// reproducible bench runs; the v0.1.1 default is auto.
@property (nonatomic) NSInteger policyProxyWorkerThreads;

// Privacy of Lethe itself
@property (nonatomic) BOOL telemetry;              // default NO; we do not phone home
@property (nonatomic) BOOL crashReports;           // default NO; off by default

// Plugins
// Engine-only plugin overrides (no LethePreferences key of their own),
// keyed by plugin registry id, e.g. {"oblivion-windows": @NO}.
@property (nonatomic, copy) NSDictionary<NSString*, NSNumber*>* pluginOverrides;
// Disabled script plugins (file names in the plugins folder).
@property (nonatomic, copy) NSArray<NSString*>* disabledPlugins;

+ (instancetype)shared;
- (void)load;
- (void)save;
- (NSString*)summaryText;
// Search engine -> URL template ({q} substituted). Empty if engine is Custom
// and customSearchURL is empty.
- (NSString*)searchURLTemplate;
@end

NS_ASSUME_NONNULL_END
