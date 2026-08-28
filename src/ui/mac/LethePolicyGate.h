// LethePolicyGate.h - lethe_core policy checks and reader-mode fetches off
// the main thread. Engine-agnostic: used by both macOS shells (CEF, WebKit).
#ifndef LETHE_UI_MAC_LETHE_POLICY_GATE_H
#define LETHE_UI_MAC_LETHE_POLICY_GATE_H

#import <Foundation/Foundation.h>

#include "browser/shell_context.h"

// Policy + reader fetches, off the main thread. One instance per app.
@interface LethePolicyGate : NSObject
- (instancetype)initWithContext:(const lethe::ShellContext&)ctx;
// Completion runs on the main queue: "" when allowed, else the refusal.
- (void)checkURL:(NSString*)url completion:(void (^)(NSString* reason))completion;
// Fetches through lethe_core (DoH, HSTS, pins, cookies) and hands back the
// extracted reader page HTML plus the final URL; error text on failure.
- (void)fetchReaderForURL:(NSString*)url
               completion:(void (^)(NSString* html, NSString* finalUrl,
                                    NSString* error))completion;
@end

#endif // LETHE_UI_MAC_LETHE_POLICY_GATE_H
