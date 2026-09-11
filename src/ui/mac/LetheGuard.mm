// LetheGuard.mm - see LetheGuard.h

#import "ui/mac/LetheGuard.h"

#import "ui/mac/LethePreferences.h"

#include <string>
#include <vector>

#include "security/file_scanner.h"
#include "security/site_reputation.h"

namespace {

LetheThreatLevel levelFor(lethe::ThreatSeverity severity) {
    switch (severity) {
        case lethe::ThreatSeverity::Clean: return LetheThreatLevelClean;
        case lethe::ThreatSeverity::Notice: return LetheThreatLevelNotice;
        case lethe::ThreatSeverity::Suspicious: return LetheThreatLevelSuspicious;
        case lethe::ThreatSeverity::Dangerous: return LetheThreatLevelDangerous;
        case lethe::ThreatSeverity::Malicious: return LetheThreatLevelMalicious;
    }
    return LetheThreatLevelClean;
}

LetheScanResult* wrap(const lethe::ThreatReport& report) {
    LetheScanResult* result = [[LetheScanResult alloc] init];
    result.level = levelFor(report.severity);
    result.score = report.score;
    result.subject = [NSString stringWithUTF8String:report.subject.c_str()] ?: @"";
    result.typeLabel = [NSString stringWithUTF8String:report.identifiedType.c_str()] ?: @"";
    NSMutableArray<NSString*>* reasons = [NSMutableArray array];
    for (const lethe::ThreatFinding& finding : report.findings) {
        NSString* text = [NSString stringWithUTF8String:finding.detail.c_str()];
        if (text.length) [reasons addObject:text];
    }
    result.reasons = reasons;
    return result;
}

NSString* hostOf(NSString* url) {
    NSURL* parsed = [NSURL URLWithString:url];
    return parsed.host ?: @"";
}

}  // namespace

@implementation LetheScanResult

- (BOOL)blocked {
    return self.level >= LetheThreatLevelDangerous;
}

- (NSString*)headline {
    switch (self.level) {
        case LetheThreatLevelClean: return @"No risk indicators found";
        case LetheThreatLevelNotice: return @"Minor risk indicators";
        case LetheThreatLevelSuspicious: return @"This looks suspicious";
        case LetheThreatLevelDangerous: return @"This is dangerous";
        case LetheThreatLevelMalicious: return @"Known malicious content";
    }
    return @"";
}

@end

@implementation LetheGuard

+ (NSMutableSet<NSString*>*)allowedHosts {
    static NSMutableSet<NSString*>* hosts;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ hosts = [NSMutableSet set]; });
    return hosts;
}

+ (BOOL)isHostAllowed:(NSString*)host {
    if (!host.length) return NO;
    @synchronized([self allowedHosts]) {
        return [[self allowedHosts] containsObject:host.lowercaseString];
    }
}

+ (void)allowHost:(NSString*)host {
    if (!host.length) return;
    @synchronized([self allowedHosts]) {
        [[self allowedHosts] addObject:host.lowercaseString];
    }
}

+ (LetheScanResult*)assessURL:(NSString*)url {
    lethe::SiteReputationOptions options;
    @synchronized([self allowedHosts]) {
        for (NSString* host in [self allowedHosts])
            options.allowedHosts.push_back(host.UTF8String ?: "");
    }
    const lethe::ThreatReport report =
        lethe::assessUrl(url.UTF8String ?: "", options);
    return wrap(report);
}

+ (LetheScanResult*)scanFileAtPath:(NSString*)path source:(NSString*)sourceURL {
    const lethe::ThreatReport report =
        lethe::scanDownloadFile(path.UTF8String ?: "",
                                sourceURL.UTF8String ?: "");
    LetheScanResult* result = wrap(report);
    result.subject = path;
    return result;
}

+ (NSString*)quarantineDirectory {
    NSString* support = [NSSearchPathForDirectoriesInDomains(
        NSApplicationSupportDirectory, NSUserDomainMask, YES) firstObject];
    NSString* dir = [[support stringByAppendingPathComponent:@"Lethe"]
                        stringByAppendingPathComponent:@"Quarantine"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir
                              withIntermediateDirectories:YES
                                               attributes:@{NSFilePosixPermissions : @0700}
                                                    error:nil];
    return dir;
}

+ (NSAlert*)alertForResult:(LetheScanResult*)result title:(NSString*)title {
    NSAlert* alert = [[NSAlert alloc] init];
    alert.alertStyle = result.blocked ? NSAlertStyleCritical : NSAlertStyleWarning;
    alert.messageText = title;
    NSMutableString* body = [NSMutableString string];
    [body appendFormat:@"%@\n", result.headline];
    if (result.typeLabel.length) [body appendFormat:@"Content: %@\n", result.typeLabel];
    [body appendString:@"\n"];
    for (NSString* reason in result.reasons) [body appendFormat:@"• %@\n", reason];
    alert.informativeText = body;
    return alert;
}

+ (BOOL)presentNavigationWarning:(LetheScanResult*)result
                          forURL:(NSString*)url
                          window:(NSWindow*)window {
    (void)window;
    NSAlert* alert = [self alertForResult:result
                                    title:[NSString stringWithFormat:@"Lethe blocked %@",
                                                                     hostOf(url).length
                                                                         ? hostOf(url)
                                                                         : url]];
    [alert addButtonWithTitle:@"Go Back"];
    // Known-malicious content gets no one-click override: the user can still
    // reach it by disabling the guard in Settings, which is a deliberate act
    // rather than a reflex click on a dialog.
    if (result.level < LetheThreatLevelMalicious)
        [alert addButtonWithTitle:@"Continue Anyway"];
    const NSModalResponse response = [alert runModal];
    const BOOL proceed = response == NSAlertSecondButtonReturn &&
                         result.level < LetheThreatLevelMalicious;
    if (proceed) [self allowHost:hostOf(url)];
    return proceed;
}

+ (LetheScanResult*)handleFinishedDownloadAtPath:(NSString*)path
                                          source:(NSString*)sourceURL
                                          window:(NSWindow*)window {
    (void)window;
    if (!path.length) return nil;
    if (![[LethePreferences shared] downloadGuard]) return nil;

    LetheScanResult* result = [self scanFileAtPath:path source:sourceURL];
    if (result.level <= LetheThreatLevelNotice) return result;

    NSString* finalPath = path;
    BOOL quarantined = NO;
    if (result.blocked && [[LethePreferences shared] quarantineThreats]) {
        NSString* target = [[self quarantineDirectory]
            stringByAppendingPathComponent:path.lastPathComponent];
        NSFileManager* fm = [NSFileManager defaultManager];
        for (int i = 1; [fm fileExistsAtPath:target] && i < 1000; ++i) {
            target = [[self quarantineDirectory]
                stringByAppendingPathComponent:
                    [NSString stringWithFormat:@"%d-%@", i, path.lastPathComponent]];
        }
        NSError* error = nil;
        if ([fm moveItemAtPath:path toPath:target error:&error]) {
            // Remove the executable bit so a stray double-click in Finder
            // cannot run a quarantined payload.
            [fm setAttributes:@{NSFilePosixPermissions : @0600}
                 ofItemAtPath:target
                        error:nil];
            finalPath = target;
            quarantined = YES;
        }
    }

    NSString* title = result.blocked
                          ? [NSString stringWithFormat:@"Dangerous download: %@",
                                                       path.lastPathComponent]
                          : [NSString stringWithFormat:@"Check this download: %@",
                                                       path.lastPathComponent];
    NSAlert* alert = [self alertForResult:result title:title];
    if (quarantined) {
        alert.informativeText = [alert.informativeText
            stringByAppendingFormat:@"\nMoved to quarantine:\n%@", finalPath];
        [alert addButtonWithTitle:@"Delete"];
        [alert addButtonWithTitle:@"Keep in Quarantine"];
        [alert addButtonWithTitle:@"Reveal"];
    } else {
        [alert addButtonWithTitle:@"Keep"];
        [alert addButtonWithTitle:@"Delete"];
        [alert addButtonWithTitle:@"Reveal"];
    }
    const NSModalResponse response = [alert runModal];
    const BOOL deleteRequested = quarantined ? (response == NSAlertFirstButtonReturn)
                                             : (response == NSAlertSecondButtonReturn);
    if (deleteRequested) {
        [[NSFileManager defaultManager] removeItemAtPath:finalPath error:nil];
    } else if (response == NSAlertThirdButtonReturn) {
        [[NSWorkspace sharedWorkspace]
            activateFileViewerSelectingURLs:@[ [NSURL fileURLWithPath:finalPath] ]];
    }
    return result;
}

@end
