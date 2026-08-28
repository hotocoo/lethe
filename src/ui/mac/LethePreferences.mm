// LethePreferences.mm
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
        _trackerBlocking = YES;
        _httpsFirst = YES;
        _persistentCookies = NO;
        _stealthUA = NO;
        NSArray* dirs = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
        NSString* root = [dirs.firstObject stringByAppendingPathComponent:@"Lethe"];
        [[NSFileManager defaultManager] createDirectoryAtPath:root withIntermediateDirectories:YES attributes:nil error:nil];
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
    if ((v = dict[@"trackerBlocking"]) && [v respondsToSelector:@selector(boolValue)]) _trackerBlocking = [v boolValue];
    if ((v = dict[@"httpsFirst"]) && [v respondsToSelector:@selector(boolValue)]) _httpsFirst = [v boolValue];
    if ((v = dict[@"persistentCookies"]) && [v respondsToSelector:@selector(boolValue)]) _persistentCookies = [v boolValue];
    if ((v = dict[@"stealthUA"]) && [v respondsToSelector:@selector(boolValue)]) _stealthUA = [v boolValue];
}

- (void)save {
    NSDictionary* d = @{
        @"trackerBlocking": @(_trackerBlocking),
        @"httpsFirst": @(_httpsFirst),
        @"persistentCookies": @(_persistentCookies),
        @"stealthUA": @(_stealthUA),
    };
    [d writeToFile:_path atomically:YES];
    [[NSNotificationCenter defaultCenter] postNotificationName:LethePreferencesDidChangeNotification object:self];
}

- (NSString*)summaryText {
    return [NSString stringWithFormat:
        @"Tracker protection: %@\nHTTPS-first: %@\nPersistent cookies: %@\nStealth user agent: %@",
        _trackerBlocking ? @"on" : @"off",
        _httpsFirst ? @"on" : @"off",
        _persistentCookies ? @"on (kept between runs)" : @"off (cleared on quit)",
        _stealthUA ? @"on (fixed low-entropy profile)" : @"off (WebKit default)"];
}
@end
