// LetheTabSearch.h - quick search across all open tabs.
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface LetheTabSearch : NSObject
+ (instancetype)shared;
// Show the tab search panel.
- (void)show;
@end

NS_ASSUME_NONNULL_END
