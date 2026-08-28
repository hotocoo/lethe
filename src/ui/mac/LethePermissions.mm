// LethePermissions.mm
#import "ui/mac/LethePermissions.h"

NSString* const LethePermissionsDidChangeNotification = @"LethePermissionsDidChangeNotification";

@implementation LethePermissionRequest
- (instancetype)initWithHost:(NSString*)host type:(NSString*)type detail:(nullable NSString*)detail {
    if ((self = [super init])) {
        _host = [host copy];
        _type = [type copy];
        _detail = [detail copy];
    }
    return self;
}
@end

@implementation LethePermissions {
    NSMutableDictionary<NSString*, NSNumber*>* _store;
    NSString* _path;
}

+ (instancetype)shared {
    static LethePermissions* s; static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [[LethePermissions alloc] init]; });
    return s;
}

- (instancetype)init {
    if ((self = [super init])) {
        _store = [NSMutableDictionary dictionary];
        NSArray* dirs = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
        NSString* root = [dirs.firstObject stringByAppendingPathComponent:@"Lethe"];
        [[NSFileManager defaultManager] createDirectoryAtPath:root withIntermediateDirectories:YES attributes:nil error:nil];
        _path = [root stringByAppendingPathComponent:@"permissions.json"];
        [self load];
    }
    return self;
}

- (NSString*)keyForHost:(NSString*)host type:(NSString*)type {
    return [NSString stringWithFormat:@"%@|%@", host.lowercaseString ?: @"", type ?: @""];
}

- (LethePermissionValue)decisionForHost:(NSString*)host type:(NSString*)type {
    NSNumber* v = _store[[self keyForHost:host type:type]];
    if (!v) return LethePermissionAsk;
    return (LethePermissionValue)v.integerValue;
}

- (void)setDecision:(LethePermissionValue)decision
           forHost:(NSString*)host type:(NSString*)type remember:(BOOL)remember {
    NSString* k = [self keyForHost:host type:type];
    if (remember && (decision == LethePermissionAllow || decision == LethePermissionDeny)) {
        _store[k] = @(decision);
        [self save];
    } else {
        [_store removeObjectForKey:k];
        [self save];
    }
    [[NSNotificationCenter defaultCenter] postNotificationName:LethePermissionsDidChangeNotification object:self];
}

- (void)clearforHost:(NSString*)host type:(NSString*)type {
    [_store removeObjectForKey:[self keyForHost:host type:type]];
    [self save];
    [[NSNotificationCenter defaultCenter] postNotificationName:LethePermissionsDidChangeNotification object:self];
}

- (void)clearAll {
    [_store removeAllObjects];
    [self save];
    [[NSNotificationCenter defaultCenter] postNotificationName:LethePermissionsDidChangeNotification object:self];
}

- (void)load {
    NSData* d = [NSData dataWithContentsOfFile:_path];
    if (!d) return;
    NSError* err = nil;
    NSDictionary* dict = [NSJSONSerialization JSONObjectWithData:d options:0 error:&err];
    if (![dict isKindOfClass:[NSDictionary class]]) return;
    for (NSString* k in dict) {
        id v = dict[k];
        if ([v respondsToSelector:@selector(integerValue)]) _store[k] = @([v integerValue]);
    }
}

- (void)save {
    [_store writeToFile:_path atomically:YES];
}

- (NSString*)humanType:(NSString*)type {
    if ([type isEqualToString:@"camera"]) return @"camera";
    if ([type isEqualToString:@"microphone"]) return @"microphone";
    if ([type isEqualToString:@"geolocation"]) return @"location";
    return type ?: @"this permission";
}

- (void)promptForRequest:(LethePermissionRequest*)req
              fromWindow:(nullable NSWindow*)window
              remember:(BOOL)remember
                 allow:(void (^)(BOOL))handler {
    LethePermissionValue stored = [self decisionForHost:req.host type:req.type];
    if (stored == LethePermissionAllow) { handler(YES); return; }
    if (stored == LethePermissionDeny) { handler(NO); return; }
    NSString* title = [NSString stringWithFormat:@"%@ wants to use your %@",
                       req.host.length ? req.host : @"This site",
                       [self humanType:req.detail.length ? req.detail : req.type]];
    NSAlert* alert = [[NSAlert alloc] init];
    alert.messageText = title;
    alert.informativeText = remember
        ? @"Lethe can remember this choice for future visits."
        : @"Choose whether to allow this request.";
    [alert addButtonWithTitle:@"Allow"];
    [alert addButtonWithTitle:@"Deny"];
    if (remember) {
        [alert setShowsSuppressionButton:YES];
        alert.suppressionButton.title = @"Remember this decision";
    }
    void (^done)(NSModalResponse) = ^(NSModalResponse r) {
        BOOL allow = (r == NSAlertFirstButtonReturn);
        BOOL persist = remember && (alert.suppressionButton.state == NSControlStateValueOn);
        [self setDecision:(allow ? LethePermissionAllow : LethePermissionDeny)
               forHost:req.host type:req.type remember:persist];
        if (handler) handler(allow);
    };
    if (window) {
        [alert beginSheetModalForWindow:window completionHandler:done];
    } else {
        done([alert runModal]);
    }
}
@end
