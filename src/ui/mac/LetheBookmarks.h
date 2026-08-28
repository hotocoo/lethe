// LetheBookmarks.h - Bookmark storage (persisted JSON in Application Support).
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface LetheBookmark : NSObject
@property (nonatomic, copy) NSString* url;
@property (nonatomic, copy) NSString* title;
@property (nonatomic, copy) NSDate* addedAt;
- (instancetype)initWithURL:(NSString*)url title:(NSString*)title;
@end

extern NSString* const LetheBookmarksDidChangeNotification;

@interface LetheBookmarks : NSObject
+ (instancetype)shared;
// All bookmarks, newest first.
- (NSArray<LetheBookmark*>*)all;
// True iff url (or its normalised form) is bookmarked.
- (BOOL)containsURL:(NSString*)url;
// Toggle bookmark for the given URL/title. Returns the new state (YES=added).
- (BOOL)toggleURL:(NSString*)url title:(NSString*)title;
// Remove a bookmark by URL.
- (void)removeURL:(NSString*)url;
@end

NS_ASSUME_NONNULL_END
