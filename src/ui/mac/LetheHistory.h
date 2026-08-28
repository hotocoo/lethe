// LetheHistory.h - browser history storage (persisted JSON).
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface LetheHistoryEntry : NSObject
@property (nonatomic, copy) NSString* url;
@property (nonatomic, copy) NSString* title;
@property (nonatomic, copy) NSDate* visitedAt;
- (instancetype)initWithURL:(NSString*)url title:(NSString*)title;
@end

@interface LetheHistory : NSObject
+ (instancetype)shared;
// Record a visit (called by the navigation delegate on successful load).
- (void)recordVisit:(NSString*)url title:(NSString*)title;
// All entries, newest first.
- (NSArray<LetheHistoryEntry*>*)allEntries;
// Entries matching a query string (substring on url/title), newest first.
- (NSArray<LetheHistoryEntry*>*)search:(NSString*)q;
// Clear all.
- (void)clear;
@end

NS_ASSUME_NONNULL_END
