// LetheBookmarks.mm - persist to ~/Library/Application Support/Lethe/bookmarks.json
#import "ui/mac/LetheBookmarks.h"

NSString* const LetheBookmarksDidChangeNotification = @"LetheBookmarksDidChangeNotification";

@implementation LetheBookmark
- (instancetype)initWithURL:(NSString*)url title:(NSString*)title {
    if ((self = [super init])) { _url = [url copy]; _title = [title copy]; _addedAt = [NSDate date]; }
    return self;
}
@end

@implementation LetheBookmarks {
    NSMutableArray<LetheBookmark*>* _items;
    NSString* _path;
}

+ (instancetype)shared {
    static LetheBookmarks* s; static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [[LetheBookmarks alloc] init]; });
    return s;
}

- (instancetype)init {
    if ((self = [super init])) {
        NSArray* dirs = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
        NSString* root = [dirs.firstObject stringByAppendingPathComponent:@"Lethe"];
        [[NSFileManager defaultManager] createDirectoryAtPath:root withIntermediateDirectories:YES attributes:nil error:nil];
        _path = [root stringByAppendingPathComponent:@"bookmarks.json"];
        _items = [NSMutableArray array];
        [self load];
    }
    return self;
}

- (NSString*)normalise:(NSString*)url {
    if (url.length == 0) return @"";
    NSString* s = url;
    if ([s hasSuffix:@"/"] && s.length > 8) s = [s substringToIndex:s.length - 1];
    return s.lowercaseString;
}

- (void)load {
    NSData* d = [NSData dataWithContentsOfFile:_path];
    if (!d) return;
    NSError* err = nil;
    NSArray* arr = [NSJSONSerialization JSONObjectWithData:d options:0 error:&err];
    if (![arr isKindOfClass:[NSArray class]]) return;
    for (NSDictionary* e in arr) {
        if (![e isKindOfClass:[NSDictionary class]]) continue;
        LetheBookmark* b = [[LetheBookmark alloc] initWithURL:e[@"url"] title:e[@"title"] ?: e[@"url"]];
        b.addedAt = e[@"addedAt"] ? [NSDate dateWithTimeIntervalSince1970:[e[@"addedAt"] doubleValue]] : [NSDate date];
        [_items addObject:b];
    }
}

- (void)save {
    NSMutableArray* out = [NSMutableArray array];
    for (LetheBookmark* b in _items) {
        [out addObject:@{ @"url": b.url, @"title": b.title ?: @"", @"addedAt": @([b.addedAt timeIntervalSince1970]) }];
    }
    [out writeToFile:_path atomically:YES];
}

- (NSArray<LetheBookmark*>*)all { return [_items copy]; }

- (BOOL)containsURL:(NSString*)url {
    NSString* n = [self normalise:url];
    for (LetheBookmark* b in _items) if ([[self normalise:b.url] isEqualToString:n]) return YES;
    return NO;
}

- (BOOL)toggleURL:(NSString*)url title:(NSString*)title {
    if (url.length == 0) return NO;
    if ([self containsURL:url]) { [self removeURL:url]; return NO; }
    LetheBookmark* b = [[LetheBookmark alloc] initWithURL:url title:title.length ? title : url];
    [_items insertObject:b atIndex:0];
    [self save];
    [[NSNotificationCenter defaultCenter] postNotificationName:LetheBookmarksDidChangeNotification object:self];
    return YES;
}

- (void)removeURL:(NSString*)url {
    NSString* n = [self normalise:url];
    NSUInteger i = 0;
    for (; i < _items.count; i++) if ([[self normalise:_items[i].url] isEqualToString:n]) break;
    if (i == _items.count) return;
    [_items removeObjectAtIndex:i];
    [self save];
    [[NSNotificationCenter defaultCenter] postNotificationName:LetheBookmarksDidChangeNotification object:self];
}
@end
