// LetheDesign.h - the "Lethe Quiet" design language.
//
// One source of truth for the browser chrome's visual system. The rules:
//
//   1. Content first. The chrome is a flat, quiet strip - no bezels, no
//      textures, no vibrancy, no shadows. Every compositing layer we do
//      not create is frame time the renderer keeps.
//   2. Ink on paper. One foreground (ink), one background (paper), one
//      hairline between regions. Color appears exactly twice: the accent
//      (focus and interactive states) and the security glyph (status).
//   3. The window title is not rendered in the window. The page is the
//      title; macOS tab titles and the Window menu still carry it.
//   4. Hairlines, not boxes. Regions are separated by 1px lines, never
//      by nested backgrounds or cards.
//   5. Type does the work. SF Pro at two sizes (13 body / 11 quiet),
//      medium weight for hierarchy - no small-caps, no letterspacing.
//
// The internal HTML pages (new tab, block/error, reader) mirror these
// tokens in src/renderer/page_templates.cc (kQuietStyle) - keep both in
// sync when changing values.

#import <AppKit/AppKit.h>

// --- Metrics -------------------------------------------------------------

// Chrome strip height. One row, nothing stacked.
static const CGFloat kLetheChromeHeight = 44.0;
// Square ghost-button edge. 28 = comfortable 44pt-row hit target.
static const CGFloat kLetheGhostSize = 28.0;
// Pill radius for the address field and find field.
static const CGFloat kLethePillRadius = 6.0;
// Hairline thickness in points (drawn at 1 physical pixel via layer).
static const CGFloat kLetheHairline = 1.0;

// --- Color ---------------------------------------------------------------

static inline NSColor *LethePaperColor(void) {
    // Chrome background: plain window background. In dark appearance this
    // resolves to the true dark window gray.
    return [NSColor windowBackgroundColor];
}

static inline NSColor *LetheInkColor(void) {
    return [NSColor labelColor];
}

static inline NSColor *LetheQuietColor(void) {
    return [NSColor secondaryLabelColor];
}

static inline NSColor *LetheHairlineColor(void) {
    return [NSColor separatorColor];
}

static inline NSColor *LetheAccentColor(void) {
    // "River water": a desaturated cold blue. Calmer than systemBlue,
    // distinct from every platform chrome, the single accent of the UI.
    return [NSColor colorWithName:@"LetheRiverWater"
                  dynamicProvider:^NSColor *(NSAppearance *appearance) {
        NSString *match = [appearance bestMatchFromAppearancesWithNames:
            @[ NSAppearanceNameAqua, NSAppearanceNameDarkAqua ]];
        if ([match isEqualToString:NSAppearanceNameDarkAqua]) {
            return [NSColor colorWithSRGBRed:0.55 green:0.73 blue:0.84 alpha:1.0];
        }
        return [NSColor colorWithSRGBRed:0.16 green:0.34 blue:0.44 alpha:1.0];
    }];
}

// --- Components ----------------------------------------------------------

// Borderless monochrome icon button: the only button style in the chrome.
static inline NSButton *LetheGhostButton(NSString *symbol,
                                         NSString *label,
                                         SEL action,
                                         id target) {
    NSImage *img = [NSImage imageWithSystemSymbolName:symbol
                             accessibilityDescription:label];
    NSButton *b = [NSButton buttonWithImage:img target:target action:action];
    b.bezelStyle = NSBezelStyleTexturedRounded;
    b.bordered = NO;                       // ghost: glyph only, no bezel
    b.contentTintColor = [NSColor secondaryLabelColor];
    b.imageScaling = NSImageScaleProportionallyDown;
    b.toolTip = label;
    [b.widthAnchor constraintEqualToConstant:kLetheGhostSize].active = YES;
    [b.heightAnchor constraintEqualToConstant:kLetheGhostSize].active = YES;
    return b;
}

// 1px separator drawn by a layer: cheaper than NSBox (no cell, no view
// traversal) and pixel-crisp on both retina scales.
static inline NSView *LetheHairlineView(void) {
    NSView *v = [[NSView alloc] initWithFrame:NSZeroRect];
    v.wantsLayer = YES;
    v.translatesAutoresizingMaskIntoConstraints = NO;
    v.layer.backgroundColor = [NSColor separatorColor].CGColor;
    return v;
}

// Flat address field: no bezel. The pill comes from the surrounding view's
// layer; the field itself contributes nothing but type.
static inline NSTextField *LetheAddressField(void) {
    NSTextField *f = [[NSTextField alloc] initWithFrame:NSZeroRect];
    f.placeholderString = @"Search or enter address";
    f.bezelStyle = NSTextFieldSquareBezel;
    f.bordered = NO;
    f.drawsBackground = NO;
    f.focusRingType = NSFocusRingTypeNone;
    f.font = [NSFont systemFontOfSize:13.0];
    f.delegate = nil;  // wired by the owner
    f.cell.usesSingleLineMode = YES;
    f.cell.scrollable = YES;
    f.cell.lineBreakMode = NSLineBreakByTruncatingTail;
    f.cell.wraps = NO;
    return f;
}
