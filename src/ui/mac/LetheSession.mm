// LetheSession.mm
#import "ui/mac/LetheSession.h"

@implementation LetheSession {
    NSString* _path;
}

+ (instancetype)shared {
    static LetheSession* s; static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [[LetheSession alloc] init]; });
    return s;
}

- (instancetype)init {
    if ((self = [super init])) {
        NSArray* dirs = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
        NSString* root = [dirs.firstObject stringByAppendingPathComponent:@"Lethe"];
        [[NSFileManager defaultManager] createDirectoryAtPath:root withIntermediateDirectories:YES attributes:nil error:nil];
        _path = [root stringByAppendingPathComponent:@"session.json"];
    }
    return self;
}

- (NSArray<NSDictionary*>*)load {
    NSData* d = [NSData dataWithContentsOfFile:_path];
    if (!d) return @[];
    NSError* err = nil;
    id obj = [NSJSONSerialization JSONObjectWithData:d options:0 error:&err];
    if (![obj isKindOfClass:[NSArray class]]) return @[];
    return (NSArray*)obj;
}

- (void)saveWindows:(NSArray<NSDictionary*>*)windows {
    if (windows.count == 0) {
        [[NSFileManager defaultManager] removeItemAtPath:_path error:nil];
        return;
    }
    NSError* err = nil;
    NSData* d = [NSJSONSerialization dataWithJSONObject:windows options:0 error:&err];
    if (d) [d writeToFile:_path atomically:YES];
}
@end
