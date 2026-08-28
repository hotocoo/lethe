// LetheSettings.h - the unified Settings window.
//
// One window, sidebar of categories on the left, content on the right.
// Categories:
//   General, Privacy, Permissions, Network, Engine, Shortcuts, About.
//
// Each category is a small view class that knows how to render itself
// against the current LethePreferences and write back. The settings
// window observes LethePreferencesDidChangeNotification and re-applies
// engine state on every save.

#import <Cocoa/Cocoa.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString* const LetheSettingsDidCloseNotification;

@interface LetheSettings : NSObject
+ (instancetype)shared;
// Bring the settings window to front. If it doesn't exist, create it.
- (void)show;
// Programmatic open to a specific category (for the View menu links).
- (void)showCategory:(NSString*)category;
@end

NS_ASSUME_NONNULL_END
