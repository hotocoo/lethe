// LethePreferences.mm - user-facing settings, persisted to JSON.
//
// On-disk schema: see -load / -save. Every property is optional in the
// file (missing = default from -init). Unknown keys in an older binary
// are silently ignored.

#import "ui/mac/LethePreferences.h"

NSString* const LethePreferencesDidChangeNotification = @"LethePreferencesDidChangeNotification";

@implementation LethePreferences {
    NSString* _path;
}

+ (instancetype)shared {
    static LethePreferences* s; static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [[LethePreferences alloc] init]; });
    return s;
}

- (instancetype)init {
    if ((self = [super init])) {
        // Privacy & Security - all safe by default.
        _trackerBlocking = YES;
        _httpsFirst = YES;
        _httpsOnly = NO;
        _stealthUA = NO;
        _doNotTrack = YES;
        _blockFingerprinting = YES;
        _blockThirdPartyCookies = YES;
        _blockReferer = YES;
        _blockWebRTC = YES;

        // Data.
        _persistentCookies = NO;
        NSArray* dl = NSSearchPathForDirectoriesInDomains(NSDownloadsDirectory,
                                                          NSUserDomainMask, YES);
        _downloadsFolder = [dl.firstObject copy] ?: @"~/Downloads";
        _homePage = @"";

        // Network - matches default Config in core/engine.
        _dnsProvider = @"https://cloudflare-dns.com/dns-query";
        _dohSharedCache = YES;
        _dohPool = YES;
        _policyProxy = YES;
        _isolatePrivateNetworks = YES;
        _proxyAllow = @"";

        // Engine.
        _javaScript = YES;
        _hardwareAcceleration = YES;
        _theme = LetheThemeSystem;
        _searchEngine = LetheSearchEngineDuckDuckGo;
        _customSearchURL = @"";
        _language = @"en";

        // Privacy of Lethe itself.
        _telemetry = NO;
        _crashReports = NO;

        NSArray* dirs = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory,
                                                           NSUserDomainMask, YES);
        NSString* root = [dirs.firstObject stringByAppendingPathComponent:@"Lethe"];
        [[NSFileManager defaultManager] createDirectoryAtPath:root
                                  withIntermediateDirectories:YES attributes:nil error:nil];
        _path = [root stringByAppendingPathComponent:@"preferences.json"];
        [self load];
    }
    return self;
}

- (void)load {
    NSData* d = [NSData dataWithContentsOfFile:_path];
    if (!d) return;
    NSError* err = nil;
    NSDictionary* dict = [NSJSONSerialization JSONObjectWithData:d options:0 error:&err];
    if (![dict isKindOfClass:[NSDictionary class]]) return;
    id v;
    NSArray<NSString*>* boolKeys = @[
        @"trackerBlocking", @"httpsFirst", @"httpsOnly", @"stealthUA",
        @"doNotTrack", @"blockFingerprinting", @"blockThirdPartyCookies",
        @"blockReferer", @"blockWebRTC",
        @"persistentCookies",
        @"dohSharedCache", @"dohPool", @"policyProxy", @"isolatePrivateNetworks",
        @"javaScript", @"hardwareAcceleration",
        @"telemetry", @"crashReports",
    ];
    for (NSString* k in boolKeys) {
        if ((v = dict[k]) && [v respondsToSelector:@selector(boolValue)]) {
            [self setValue:@([v boolValue]) forKey:k];
        }
    }
    if ((v = dict[@"downloadsFolder"]) && [v isKindOfClass:[NSString class]])
        _downloadsFolder = v;
    if ((v = dict[@"homePage"]) && [v isKindOfClass:[NSString class]])
        _homePage = v;
    if ((v = dict[@"dnsProvider"]) && [v isKindOfClass:[NSString class]])
        _dnsProvider = v;
    if ((v = dict[@"proxyAllow"]) && [v isKindOfClass:[NSString class]])
        _proxyAllow = v;
    if ((v = dict[@"customSearchURL"]) && [v isKindOfClass:[NSString class]])
        _customSearchURL = v;
    if ((v = dict[@"language"]) && [v isKindOfClass:[NSString class]])
        _language = v;
    if ((v = dict[@"theme"]) && [v respondsToSelector:@selector(integerValue)])
        _theme = (LetheTheme)[v integerValue];
    if ((v = dict[@"searchEngine"]) && [v respondsToSelector:@selector(integerValue)])
        _searchEngine = (LetheSearchEngine)[v integerValue];
}

- (void)save {
    NSMutableDictionary* d = [NSMutableDictionary dictionary];
    NSArray<NSString*>* boolKeys = @[
        @"trackerBlocking", @"httpsFirst", @"httpsOnly", @"stealthUA",
        @"doNotTrack", @"blockFingerprinting", @"blockThirdPartyCookies",
        @"blockReferer", @"blockWebRTC",
        @"persistentCookies",
        @"dohSharedCache", @"dohPool", @"policyProxy", @"isolatePrivateNetworks",
        @"javaScript", @"hardwareAcceleration",
        @"telemetry", @"crashReports",
    ];
    for (NSString* k in boolKeys) [d setObject:[self valueForKey:k] forKey:k];
    [d setObject:_downloadsFolder ?: @"" forKey:@"downloadsFolder"];
    [d setObject:_homePage ?: @"" forKey:@"homePage"];
    [d setObject:_dnsProvider ?: @"" forKey:@"dnsProvider"];
    [d setObject:_proxyAllow ?: @"" forKey:@"proxyAllow"];
    [d setObject:_customSearchURL ?: @"" forKey:@"customSearchURL"];
    [d setObject:_language ?: @"en" forKey:@"language"];
    [d setObject:@(_theme) forKey:@"theme"];
    [d setObject:@(_searchEngine) forKey:@"searchEngine"];
    [d writeToFile:_path atomically:YES];
    [[NSNotificationCenter defaultCenter]
        postNotificationName:LethePreferencesDidChangeNotification object:self];
}

- (NSString*)searchURLTemplate {
    switch (_searchEngine) {
        case LetheSearchEngineDuckDuckGo: return @"https://duckduckgo.com/?q={q}";
        case LetheSearchEngineStartpage:  return @"https://www.startpage.com/do/search?q={q}";
        case LetheSearchEngineBrave:      return @"https://search.brave.com/search?q={q}";
        case LetheSearchEngineEcosia:     return @"https://www.ecosia.org/search?q={q}";
        case LetheSearchEngineCustom:     return _customSearchURL ?: @"";
    }
    return @"";
}

- (NSString*)summaryText {
    return [NSString stringWithFormat:
        @"Tracker blocking: %@\nHTTPS-first: %@\nHTTPS-only: %@\n"
        @"Stealth UA: %@\nDo Not Track: %@\nBlock fingerprinting: %@\n"
        @"Block 3rd-party cookies: %@\nBlock Referer: %@\nBlock WebRTC: %@\n\n"
        @"Persistent cookies: %@\nDownloads: %@\nHome page: %@\n\n"
        @"DNS provider: %@\nDoH shared cache: %@\nDoH pool: %@\n"
        @"Policy proxy: %@\nPrivate network isolation: %@\n\n"
        @"JavaScript: %@\nHardware accel: %@\nTheme: %@\n"
        @"Search engine: %@\nLanguage: %@\n\n"
        @"Telemetry: %@\nCrash reports: %@",
        _trackerBlocking ? @"on" : @"off",
        _httpsFirst ? @"on" : @"off",
        _httpsOnly ? @"on (refuse http)" : @"off (allow with fallback)",
        _stealthUA ? @"on" : @"off",
        _doNotTrack ? @"on" : @"off",
        _blockFingerprinting ? @"on" : @"off",
        _blockThirdPartyCookies ? @"on" : @"off",
        _blockReferer ? @"on" : @"off",
        _blockWebRTC ? @"on" : @"off",
        _persistentCookies ? @"on (kept between runs)" : @"off (cleared on quit)",
        _downloadsFolder ?: @"~",
        _homePage.length ? _homePage : @"built-in new-tab page",
        _dnsProvider ?: @"(none)",
        _dohSharedCache ? @"on" : @"off",
        _dohPool ? @"on" : @"off",
        _policyProxy ? @"on" : @"off",
        _isolatePrivateNetworks ? @"on" : @"off",
        _javaScript ? @"on" : @"off",
        _hardwareAcceleration ? @"on" : @"off",
        _theme == LetheThemeDark ? @"dark" :
            _theme == LetheThemeLight ? @"light" : @"system",
        _searchEngine == LetheSearchEngineDuckDuckGo ? @"DuckDuckGo" :
            _searchEngine == LetheSearchEngineStartpage ? @"Startpage" :
            _searchEngine == LetheSearchEngineBrave ? @"Brave" :
            _searchEngine == LetheSearchEngineEcosia ? @"Ecosia" : @"Custom",
        _language ?: @"en",
        _telemetry ? @"on" : @"off (default)",
        _crashReports ? @"on" : @"off (default)"];
}
@end
