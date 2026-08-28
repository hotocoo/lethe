// LethePermissions.h - per-origin permission decisions.
#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, LethePermissionValue) {
    LethePermissionAsk,      // no stored decision - prompt
    LethePermissionAllow,     // stored allow
    LethePermissionDeny,      // stored deny
    LethePermissionSessionAllow,  // allow for this session (not persisted)
    LethePermissionSessionDeny,
};

@interface LethePermissionRequest : NSObject
@property (nonatomic, copy) NSString* host;          // securityOrigin.host (no scheme/port)
@property (nonatomic, copy) NSString* type;          // "camera", "microphone", "geolocation"
@property (nonatomic, copy, nullable) NSString* detail; // "camera + microphone" etc.
- (instancetype)initWithHost:(NSString*)host type:(NSString*)type detail:(nullable NSString*)detail;
@end

extern NSString* const LethePermissionsDidChangeNotification;

@interface LethePermissions : NSObject
+ (instancetype)shared;
// Stored decision (Allow / Deny) or Ask if none.
- (LethePermissionValue)decisionForHost:(NSString*)host type:(NSString*)type;
// Persist a decision; pass YES to remember across sessions, NO for session-only.
- (void)setDecision:(LethePermissionValue)decision
           forHost:(NSString*)host type:(NSString*)type remember:(BOOL)remember;
// Clear a stored decision (back to Ask).
- (void)clearforHost:(NSString*)host type:(NSString*)type;
// Clear every stored decision.
- (void)clearAll;
// Show the system prompt (NSAlert) for a permission request and invoke the
// decision handler with the user's choice. remember=YES persists the
// decision; otherwise it's session-scoped only.
- (void)promptForRequest:(LethePermissionRequest*)req
              fromWindow:(nullable NSWindow*)window
              remember:(BOOL)remember
                 allow:(void (^)(BOOL allow))handler;
@end

NS_ASSUME_NONNULL_END
