// LetheUIAudit.h - reachability audit for native chrome controls
//
// Every clickable control in the shell (toolbar items, menu items, buttons
// in the window hierarchy) is only useful if AppKit can route its action to
// a live target. A control whose target was deallocated, whose selector was
// renamed, or that sits outside the responder chain still draws normally and
// still highlights on click - it simply does nothing. That failure mode is
// invisible to screenshot tests, so the shell exposes it as data instead.
//
// The audit resolves each control the same way AppKit does at click time and
// reports whether the action would reach an implementation.

#ifndef LETHE_UI_MAC_LETHE_UI_AUDIT_H
#define LETHE_UI_MAC_LETHE_UI_AUDIT_H

#import <Cocoa/Cocoa.h>

// Audit entry keys.
extern NSString* const kLetheUIAuditKind;    // @"toolbar" | @"menu" | @"button"
extern NSString* const kLetheUIAuditName;    // human-facing label / menu path
extern NSString* const kLetheUIAuditAction;  // selector name, or @"" when none
extern NSString* const kLetheUIAuditTarget;  // resolved target class name
extern NSString* const kLetheUIAuditOK;      // NSNumber<BOOL>
extern NSString* const kLetheUIAuditReason;  // why it is dead, when not OK

@interface LetheUIAudit : NSObject

// Audits the toolbar and control hierarchy of \p window plus the application
// main menu. Separator items, disabled-by-design system items and controls
// without an action (labels, plain views) are skipped.
+ (NSArray<NSDictionary*>*)auditWindow:(NSWindow*)window;

// One line per entry, stable ordering, suitable for a test transcript.
+ (NSArray<NSString*>*)describeEntries:(NSArray<NSDictionary*>*)entries;

// Clicks the control whose name (or identifier) matches \p name, using the
// same dispatch AppKit uses. Returns NO and fills \p error when no control
// matches or the action cannot be routed.
+ (BOOL)clickControlNamed:(NSString*)name
                 inWindow:(NSWindow*)window
                    error:(NSString**)error;

@end

#endif  // LETHE_UI_MAC_LETHE_UI_AUDIT_H
