// LetheOmnibox.h - how an address is rendered in the address bar
//
// A URL shown as one flat string of low-contrast text tells the user nothing
// about where they are, which is exactly the condition phishing depends on.
// Both shells therefore render the registrable domain at full contrast and
// dim the scheme, subdomains, path and query around it.

#ifndef LETHE_UI_MAC_LETHE_OMNIBOX_H
#define LETHE_UI_MAC_LETHE_OMNIBOX_H

#import <Cocoa/Cocoa.h>

NS_ASSUME_NONNULL_BEGIN

// Attributed form of \p url for display in a non-editing address field.
// Returns nil when \p url is not a http(s) URL, in which case the caller
// should show the plain string.
NSAttributedString* _Nullable LetheOmniboxAttributedAddress(NSString* url,
                                                            NSFont* font);

NS_ASSUME_NONNULL_END

#endif  // LETHE_UI_MAC_LETHE_OMNIBOX_H
