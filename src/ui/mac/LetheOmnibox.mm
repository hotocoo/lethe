// LetheOmnibox.mm - see LetheOmnibox.h

#import "ui/mac/LetheOmnibox.h"

NSAttributedString* LetheOmniboxAttributedAddress(NSString* url, NSFont* font) {
    if (!url.length) return nil;
    NSURL* parsed = [NSURL URLWithString:url];
    NSString* host = parsed.host;
    NSString* scheme = parsed.scheme.lowercaseString;
    if (!host.length || !([scheme isEqualToString:@"https"] ||
                          [scheme isEqualToString:@"http"])) {
        return nil;
    }

    // The registrable domain is approximated as the last two labels. A public
    // suffix list would be exact for co.uk and friends; the approximation
    // only decides emphasis, never policy, so an occasional "co.uk" bolded
    // one label short costs nothing.
    NSArray<NSString*>* labels = [host componentsSeparatedByString:@"."];
    NSString* registrable = host;
    if (labels.count >= 2) {
        registrable = [NSString stringWithFormat:@"%@.%@",
                                                 labels[labels.count - 2],
                                                 labels[labels.count - 1]];
    }

    NSFont* base = font ?: [NSFont systemFontOfSize:13.0];
    NSFont* strong = [NSFontManager.sharedFontManager convertFont:base
                                                      toHaveTrait:NSBoldFontMask];
    NSDictionary* dim = @{
        NSFontAttributeName : base,
        NSForegroundColorAttributeName : [NSColor secondaryLabelColor],
    };
    NSDictionary* bright = @{
        NSFontAttributeName : strong ?: base,
        NSForegroundColorAttributeName : [NSColor labelColor],
    };

    NSMutableAttributedString* out = [[NSMutableAttributedString alloc] init];
    // Scheme: shown only when it is not the expected https, so the ordinary
    // case is quiet and the exceptional case is visible.
    if ([scheme isEqualToString:@"http"]) {
        [out appendAttributedString:
                 [[NSAttributedString alloc] initWithString:@"http://"
                                                 attributes:@{
                                                     NSFontAttributeName : base,
                                                     NSForegroundColorAttributeName :
                                                         [NSColor systemOrangeColor],
                                                 }]];
    }
    const NSRange registrableRange = [host rangeOfString:registrable
                                                 options:NSBackwardsSearch];
    if (registrableRange.location != NSNotFound && registrableRange.location > 0) {
        [out appendAttributedString:
                 [[NSAttributedString alloc]
                     initWithString:[host substringToIndex:registrableRange.location]
                         attributes:dim]];
    }
    [out appendAttributedString:[[NSAttributedString alloc] initWithString:registrable
                                                                attributes:bright]];
    NSString* tail = parsed.path ?: @"";
    if (parsed.query.length) tail = [tail stringByAppendingFormat:@"?%@", parsed.query];
    if ([tail isEqualToString:@"/"]) tail = @"";
    if (tail.length) {
        [out appendAttributedString:[[NSAttributedString alloc] initWithString:tail
                                                                    attributes:dim]];
    }
    return out;
}
