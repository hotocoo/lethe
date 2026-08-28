// LetheSession.h - persist/restore open tabs across launches.
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface LetheSession : NSObject
+ (instancetype)shared;
// Array of { url, title } per window, ordered by recency.
- (NSArray<NSDictionary*>*)load;
- (void)saveWindows:(NSArray<NSDictionary*>*)windows;
@end

NS_ASSUME_NONNULL_END
