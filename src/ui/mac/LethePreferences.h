// LethePreferences.h - user-facing settings, persisted to JSON.
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString* const LethePreferencesDidChangeNotification;

@interface LethePreferences : NSObject
@property (nonatomic) BOOL trackerBlocking;
@property (nonatomic) BOOL httpsFirst;
@property (nonatomic) BOOL persistentCookies;
@property (nonatomic) BOOL stealthUA;
+ (instancetype)shared;
- (void)load;
- (void)save;
// Human-readable summary for the preferences dialog.
- (NSString*)summaryText;
@end

NS_ASSUME_NONNULL_END
