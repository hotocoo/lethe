// LetheUIAudit.mm - see LetheUIAudit.h

#import "ui/mac/LetheUIAudit.h"

NSString* const kLetheUIAuditKind = @"kind";
NSString* const kLetheUIAuditName = @"name";
NSString* const kLetheUIAuditAction = @"action";
NSString* const kLetheUIAuditTarget = @"target";
NSString* const kLetheUIAuditOK = @"ok";
NSString* const kLetheUIAuditReason = @"reason";

namespace {

NSString* SelectorName(SEL sel) {
    return sel ? NSStringFromSelector(sel) : @"";
}

// Resolves the object that would receive \p action if the user clicked a
// control with target \p target right now. Mirrors AppKit's own lookup:
// an explicit target is used verbatim, a nil target walks the responder
// chain from the key window through the application delegate.
id ResolveTarget(SEL action, id target, id sender, NSWindow* window) {
    if (!action) return nil;
    if (target) return [target respondsToSelector:action] ? target : nil;
    if (id resolved = [NSApp targetForAction:action to:nil from:sender]) return resolved;
    // A command issued from the menu bar resolves against the key window. An
    // audit can run while the app is in the background (a scripted run never
    // steals focus), so retry against the window being audited: that is the
    // window that would be key at click time.
    for (NSResponder* responder = window.firstResponder ?: (NSResponder*)window;
         responder != nil; responder = responder.nextResponder) {
        if ([responder respondsToSelector:action]) return responder;
    }
    if (window && [window respondsToSelector:action]) return window;
    if ([window.delegate respondsToSelector:action]) return window.delegate;
    if ([NSApp.delegate respondsToSelector:action]) return NSApp.delegate;
    return [NSApp respondsToSelector:action] ? NSApp : nil;
}

NSDictionary* MakeEntry(NSString* kind, NSString* name, SEL action, id resolved,
                        BOOL ok, NSString* reason) {
    return @{
        kLetheUIAuditKind : kind,
        kLetheUIAuditName : name ?: @"",
        kLetheUIAuditAction : SelectorName(action),
        kLetheUIAuditTarget : resolved ? NSStringFromClass([resolved class]) : @"-",
        kLetheUIAuditOK : @(ok),
        kLetheUIAuditReason : reason ?: @"",
    };
}

// Asks the resolved target whether the item is currently enabled. A NO here
// is a legitimate state (Back with empty history), not a wiring defect, so
// it is reported separately from reachability.
BOOL ValidatedEnabled(id resolved, id item) {
    if (!resolved) return NO;
    if ([item isKindOfClass:[NSMenuItem class]] &&
        [resolved respondsToSelector:@selector(validateMenuItem:)]) {
        return [resolved validateMenuItem:(NSMenuItem*)item];
    }
    if ([item isKindOfClass:[NSToolbarItem class]] &&
        [resolved respondsToSelector:@selector(validateToolbarItem:)]) {
        return [resolved validateToolbarItem:(NSToolbarItem*)item];
    }
    if ([resolved respondsToSelector:@selector(validateUserInterfaceItem:)] &&
        [item conformsToProtocol:@protocol(NSValidatedUserInterfaceItem)]) {
        return [resolved validateUserInterfaceItem:item];
    }
    return YES;
}

void CollectMenu(NSMenu* menu, NSString* prefix,
                 NSMutableArray<NSDictionary*>* out, NSWindow* window) {
    for (NSMenuItem* item in menu.itemArray) {
        if (item.isSeparatorItem) continue;
        NSString* path = prefix.length
                             ? [NSString stringWithFormat:@"%@ > %@", prefix, item.title]
                             : item.title;
        if (item.hasSubmenu) {
            CollectMenu(item.submenu, path, out, window);
            continue;
        }
        // AppKit injects section headers (Window > Move & Resize > Halves)
        // as action-less items. They are labels, not commands.
        if (!item.action) continue;
        id resolved = ResolveTarget(item.action, item.target, item, window);
        if (!resolved) {
            [out addObject:MakeEntry(@"menu", path, item.action, nil, NO,
                                     @"no target implements the action")];
            continue;
        }
        NSString* reason = ValidatedEnabled(resolved, item) ? @"" : @"disabled (state)";
        [out addObject:MakeEntry(@"menu", path, item.action, resolved, YES, reason)];
    }
}

void CollectControls(NSView* view, NSMutableArray<NSDictionary*>* out,
                     NSWindow* window) {
    for (NSView* sub in view.subviews) {
        if ([sub isKindOfClass:[NSControl class]]) {
            NSControl* control = (NSControl*)sub;
            SEL action = control.action;
            // Text fields, labels and custom drawing views legitimately have
            // no action; only clickable controls are audited.
            const BOOL clickable = [control isKindOfClass:[NSButton class]] ||
                                   [control isKindOfClass:[NSSegmentedControl class]] ||
                                   [control isKindOfClass:[NSPopUpButton class]];
            if (action && clickable) {
                // Prefer the names a user (or VoiceOver) would say: the
                // accessibility identity first, then the visible title, then
                // the tooltip that icon-only chrome buttons carry.
                NSString* name = control.accessibilityIdentifier.length
                                     ? control.accessibilityIdentifier
                                     : (control.accessibilityLabel.length
                                            ? control.accessibilityLabel
                                            : ([control isKindOfClass:[NSButton class]]
                                                   ? (((NSButton*)control).toolTip.length
                                                          ? ((NSButton*)control).toolTip
                                                          : ((NSButton*)control).title)
                                                   : control.description));
                id resolved = ResolveTarget(action, control.target, control, window);
                if (!resolved) {
                    [out addObject:MakeEntry(@"button", name, action, nil, NO,
                                             @"no target implements the action")];
                } else {
                    NSString* reason = control.isEnabled ? @"" : @"disabled (state)";
                    [out addObject:MakeEntry(@"button", name, action, resolved, YES, reason)];
                }
            }
        }
        CollectControls(sub, out, window);
    }
}

void CollectToolbar(NSWindow* window, NSMutableArray<NSDictionary*>* out) {
    NSToolbar* toolbar = window.toolbar;
    for (NSToolbarItem* item in toolbar.items) {
        // A view-hosting toolbar item (the address pill, the CEF chrome row)
        // keeps its controls inside that view, which is not reachable from
        // contentView: AppKit parents it under the titlebar instead.
        if (item.view) CollectControls(item.view, out, window);
        if (item.action == nullptr) continue;
        NSString* name = item.label.length ? item.label : item.itemIdentifier;
        id resolved = ResolveTarget(item.action, item.target, item, window);
        if (!resolved) {
            [out addObject:MakeEntry(@"toolbar", name, item.action, nil, NO,
                                     @"no target implements the action")];
            continue;
        }
        NSString* reason = ValidatedEnabled(resolved, item) ? @"" : @"disabled (state)";
        [out addObject:MakeEntry(@"toolbar", name, item.action, resolved, YES, reason)];
    }
}

BOOL NameMatches(NSString* candidate, NSString* wanted) {
    if (!candidate.length) return NO;
    return [candidate caseInsensitiveCompare:wanted] == NSOrderedSame;
}

}  // namespace

@interface LetheUIAudit ()
+ (NSMenuItem*)menuItemForPath:(NSString*)path in:(NSMenu*)menu prefix:(NSString*)prefix;
@end

@implementation LetheUIAudit

+ (NSArray<NSDictionary*>*)auditWindow:(NSWindow*)window {
    NSMutableArray<NSDictionary*>* out = [NSMutableArray array];
    if (window) {
        CollectToolbar(window, out);
        CollectControls(window.contentView, out, window);
    }
    CollectMenu([NSApp mainMenu], @"", out, window);
    return out;
}

+ (NSArray<NSString*>*)describeEntries:(NSArray<NSDictionary*>*)entries {
    NSMutableArray<NSString*>* lines = [NSMutableArray array];
    for (NSDictionary* e in entries) {
        NSString* status = [e[kLetheUIAuditOK] boolValue] ? @"ok" : @"DEAD";
        NSString* reason = e[kLetheUIAuditReason];
        [lines addObject:[NSString stringWithFormat:@"%@ %-7s \"%@\" action=%@ target=%@%@",
                                                    status,
                                                    [e[kLetheUIAuditKind] UTF8String],
                                                    e[kLetheUIAuditName], e[kLetheUIAuditAction],
                                                    e[kLetheUIAuditTarget],
                                                    reason.length
                                                        ? [@" " stringByAppendingString:reason]
                                                        : @""]];
    }
    return lines;
}

+ (BOOL)clickControlNamed:(NSString*)name
                 inWindow:(NSWindow*)window
                    error:(NSString**)error {
    // Toolbar first: those are the controls a user reaches for most.
    for (NSToolbarItem* item in window.toolbar.items) {
        if (!NameMatches(item.label, name) && !NameMatches(item.itemIdentifier, name)) continue;
        if (!item.action) {
            if (error) *error = [NSString stringWithFormat:@"toolbar item '%@' has no action", name];
            return NO;
        }
        id resolved = ResolveTarget(item.action, item.target, item, window);
        if (!resolved) {
            if (error) *error = [NSString stringWithFormat:@"toolbar item '%@' has no live target", name];
            return NO;
        }
        [NSApp sendAction:item.action to:resolved from:item];
        return YES;
    }

    NSButton* match = nil;
    NSMutableArray<NSView*>* stack = [NSMutableArray arrayWithObject:window.contentView];
    // Chrome controls hosted inside a toolbar item live under the titlebar,
    // not under contentView, so seed the search with those views too.
    for (NSToolbarItem* item in window.toolbar.items) {
        if (item.view) [stack addObject:item.view];
    }
    while (stack.count && !match) {
        NSView* view = stack.lastObject;
        [stack removeLastObject];
        for (NSView* sub in view.subviews) [stack addObject:sub];
        if (![view isKindOfClass:[NSButton class]]) continue;
        NSButton* button = (NSButton*)view;
        if (NameMatches(button.accessibilityIdentifier, name) ||
            NameMatches(button.accessibilityLabel, name) ||
            NameMatches(button.title, name) || NameMatches(button.toolTip, name)) {
            match = button;
        }
    }
    if (match) {
        if (!match.isEnabled) {
            if (error) *error = [NSString stringWithFormat:@"button '%@' is disabled", name];
            return NO;
        }
        [match performClick:nil];
        return YES;
    }

    // Menu items last, matched on either the leaf title or the full path.
    NSMutableArray<NSDictionary*>* menuEntries = [NSMutableArray array];
    CollectMenu([NSApp mainMenu], @"", menuEntries, window);
    for (NSDictionary* entry in menuEntries) {
        NSString* path = entry[kLetheUIAuditName];
        NSString* leaf = [path componentsSeparatedByString:@" > "].lastObject;
        if (!NameMatches(path, name) && !NameMatches(leaf, name)) continue;
        if (![entry[kLetheUIAuditOK] boolValue]) {
            if (error) *error = [NSString stringWithFormat:@"menu item '%@' is dead: %@", name,
                                                           entry[kLetheUIAuditReason]];
            return NO;
        }
        SEL action = NSSelectorFromString(entry[kLetheUIAuditAction]);
        NSMenuItem* item = [self menuItemForPath:path in:[NSApp mainMenu] prefix:@""];
        // Dispatch exactly the way AppKit would when the user picks the item:
        // an explicit target receives the action directly, a nil target goes
        // through the responder chain. Substituting the audit's fallback
        // target here would exercise a path the real click never takes.
        if (![NSApp sendAction:action to:item.target from:item ?: (id)self]) {
            if (error) *error = [NSString stringWithFormat:@"menu item '%@' was not handled", name];
            return NO;
        }
        return YES;
    }

    if (error) *error = [NSString stringWithFormat:@"no control named '%@'", name];
    return NO;
}

+ (NSMenuItem*)menuItemForPath:(NSString*)path in:(NSMenu*)menu prefix:(NSString*)prefix {
    for (NSMenuItem* item in menu.itemArray) {
        if (item.isSeparatorItem) continue;
        NSString* full = prefix.length
                             ? [NSString stringWithFormat:@"%@ > %@", prefix, item.title]
                             : item.title;
        if (item.hasSubmenu) {
            NSMenuItem* found = [self menuItemForPath:path in:item.submenu prefix:full];
            if (found) return found;
            continue;
        }
        if ([full isEqualToString:path]) return item;
    }
    return nil;
}

@end
