// LethePluginLoader.h - user script plugins ("everything can be a plugin").
//
// A plugin is a .js file dropped into
//   ~/Library/Application Support/Lethe/plugins/
// with an optional manifest header in comments:
//
//   // ==LethePlugin==
//   // @name Dark Reader-ish
//   // @description Inverts bright pages at night
//   // @match example.com        (host suffix; omit or * for all sites)
//   // ==/LethePlugin==
//
// Enabled plugins are injected at document start into every matching main
// frame, wrapped in an IIFE so plugins cannot see each other's variables.
// Script plugins run with the page's own privileges - they are the user's
// own code by construction (the folder is user-writable only), the same
// trust model as Safari userscripts. The Plugins settings pane and
// lethe://plugins list them; disabling is a persisted preference.
#import <Foundation/Foundation.h>
#import <WebKit/WebKit.h>

NS_ASSUME_NONNULL_BEGIN

extern NSString* const LethePluginsFolderChangedNotification;

@interface LethePluginScript : NSObject
@property (nonatomic, copy) NSString* fileName;   // "my-plugin.js"
@property (nonatomic, copy) NSString* name;       // @name or file name
@property (nonatomic, copy) NSString* pluginDescription;
@property (nonatomic, copy) NSString* matchHost;  // suffix match; @"*" = all
@property (nonatomic) BOOL enabled;               // not in the disabled set
@end

@interface LethePluginLoader : NSObject
+ (instancetype)shared;
// The plugins folder, created on first access.
+ (NSString*)pluginsFolder;
// Scan the folder and annotate each plugin with its enabled state from
// [LethePreferences shared].disabledPlugins.
- (NSArray<LethePluginScript*>*)scanPlugins;
// (Re)install every enabled plugin into the shared user content controller.
// Safe to call repeatedly: removes previously installed plugin scripts first.
- (void)installInto:(WKUserContentController*)ucc;
@end

NS_ASSUME_NONNULL_END
