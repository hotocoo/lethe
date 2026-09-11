// LetheGuard.h - shell-side surface for Lethe's built-in threat scanners
//
// The scanners themselves are engine-agnostic C++ (security/file_scanner.h,
// security/site_reputation.h). This layer is what the two macOS shells share:
// preference gating, the session allow-list a user builds by overriding a
// warning, quarantine handling, and the alerts that present a verdict.
//
// Everything here is local. No URL, hash or file byte is sent anywhere.

#ifndef LETHE_UI_MAC_LETHE_GUARD_H
#define LETHE_UI_MAC_LETHE_GUARD_H

#import <Cocoa/Cocoa.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, LetheThreatLevel) {
    LetheThreatLevelClean = 0,
    LetheThreatLevelNotice,
    LetheThreatLevelSuspicious,
    LetheThreatLevelDangerous,
    LetheThreatLevelMalicious,
};

@interface LetheScanResult : NSObject
@property (nonatomic) LetheThreatLevel level;
@property (nonatomic) NSInteger score;            // 0-100
@property (nonatomic, copy) NSString* subject;    // URL or path scanned
@property (nonatomic, copy) NSString* typeLabel;  // sniffed content type
@property (nonatomic, copy) NSArray<NSString*>* reasons;
@property (nonatomic, readonly) BOOL blocked;     // dangerous or worse
@property (nonatomic, readonly) NSString* headline;
@end

@interface LetheGuard : NSObject

// Local risk assessment of a top-level navigation target.
+ (LetheScanResult*)assessURL:(NSString*)url;

// Scan a file on disk that was downloaded from \p sourceURL.
+ (LetheScanResult*)scanFileAtPath:(NSString*)path source:(nullable NSString*)sourceURL;

// True when the user already chose to proceed to this host in this session.
+ (BOOL)isHostAllowed:(NSString*)host;
+ (void)allowHost:(NSString*)host;

// Presents the navigation warning. Returns YES when the user chose to
// continue, in which case the host is added to the session allow-list.
// Never called for clean results.
+ (BOOL)presentNavigationWarning:(LetheScanResult*)result
                          forURL:(NSString*)url
                          window:(nullable NSWindow*)window;

// Called when a download finishes. Scans (when downloadGuard is on),
// quarantines a blocked file (when quarantineThreats is on) and tells the
// user what was found. Returns the scan result, or nil when scanning is off.
+ (nullable LetheScanResult*)handleFinishedDownloadAtPath:(NSString*)path
                                                   source:(nullable NSString*)sourceURL
                                                   window:(nullable NSWindow*)window;

// Where quarantined downloads are moved to.
+ (NSString*)quarantineDirectory;

@end

NS_ASSUME_NONNULL_END

#endif  // LETHE_UI_MAC_LETHE_GUARD_H
