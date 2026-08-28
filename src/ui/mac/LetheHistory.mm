// LetheHistory.mm - persists to ~/Library/Application Support/Lethe/history.json
#import "ui/mac/LetheHistory.h"

@implementation LetheHistoryEntry
- (instancetype)initWithURL:(NSString*)url title:(NSString*)title {
    if ((self = [super init])) { _url = [url copy]; _title = [title copy]; _visitedAt = [NSDate date]; }
    return self;
}
@end

static NSString* const kMax = @"maxEntries";

@implementation LetheHistory {
    NSMutableArray<LetheHistoryEntry*>* _items;
    NSString* _path;
    NSUInteger _max;
}

+ (instancetype)shared {
    static LetheHistory* s; static dispatch_once_t once;
    dispatch_once(&once, ^{ s = [[LetheHistory alloc] init]; });
    return s;
}

- (instancetype)init {
    if ((self = [super init])) {
        _max = 5000;
        NSArray* dirs = NSSearchPathForDirectoriesInDomains(NSApplicationSupportDirectory, NSUserDomainMask, YES);
        NSString* root = [dirs.firstObject stringByAppendingPathComponent:@"Lethe"];
        [[NSFileManager defaultManager] createDirectoryAtPath:root withIntermediateDirectories:YES attributes:nil error:nil];
        _path = [root stringByAppendingPathComponent:@"history.json"];
        _items = [NSMutableArray array];
        [self load];
    }
    return self;
}

- (NSString*)normalise:(NSString*)url {
    NSString* s = url ?: @"";
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
        LetheHistoryEntry* h = [[LetheHistoryEntry alloc] initWithURL:e[@"url"] title:e[@"title"] ?: e[@"url"]];
        h.visitedAt = [NSDate dateWithTimeIntervalSince1970:[e[@"v"] doubleValue]];
        [_items addObject:h];
    }
}

- (void)save {
    NSMutableArray* out = [NSMutableArray array];
    for (LetheHistoryEntry* h in _items) {
        [out addObject:@{ @"url": h.url, @"title": h.title ?: @"", @"v": @([h.visitedAt timeIntervalSince1970]) }];
    }
    [out writeToFile:_path atomically:YES];
}

- (void)recordVisit:(NSString*)url title:(NSString*)title {
    if (url.length == 0) return;
    if (![url hasPrefix:@"http"]) return;  // ignore internal/about:blank
    // Coalesce with existing entry for same URL: bump timestamp instead of duplicating.
    NSString* n = [self normalise:url];
    LetheHistoryEntry* existing = nil;
    for (LetheHistoryEntry* h in _items) {
        if ([[self normalise:h.url] isEqualToString:n]) { existing = h; break; }
    }
    if (existing) {
        existing.visitedAt = [NSDate date];
        if (title.length) existing.title = title;
        [_items removeObject:existing];
        [_items insertObject:existing atIndex:0];
    } else {
        LetheHistoryEntry* h = [[LetheHistoryEntry alloc] initWithURL:url title:title.length ? title : url];
        [_items insertObject:h atIndex:0];
    }
    while (_items.count > _max) [_items removeLastObject];
    [self save];
}

- (NSArray<LetheHistoryEntry*>*)allEntries { return [_items copy]; }

- (NSArray<LetheHistoryEntry*>*)search:(NSString*)q {
    if (q.length == 0) return [self allEntries];
    NSString* ql = q.lowercaseString;
    NSMutableArray* out = [NSMutableArray array];
    for (LetheHistoryEntry* h in _items) {
        if ([h.url.lowercaseString containsString:ql] || [h.title.lowercaseString containsString:ql]) [out addObject:h];
    }
    return out;
}

- (void)clear {
    [_items removeAllObjects];
    [self save];
}
@end
