// LetheInternalPages.h - HTML for Lethe's own pages (history, bookmarks)
//
// Both shells present the same internal pages: the WebKit shell loads them
// into its WKWebView, the CEF shell loads them as a data URL. Keeping the
// markup in one place is what stops the two engines from drifting into two
// different-looking browsers.

#ifndef LETHE_UI_MAC_LETHE_INTERNAL_PAGES_H
#define LETHE_UI_MAC_LETHE_INTERNAL_PAGES_H

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// Shared stylesheet for every internal page, including the <style> element.
extern NSString* LetheInternalPageStyle(void);

// Full documents.
extern NSString* LetheHistoryPageHTML(void);
extern NSString* LetheBookmarksPageHTML(void);

// data: URL wrapper for engines that cannot be handed a string directly.
extern NSString* LetheDataURLForHTML(NSString* html);

NS_ASSUME_NONNULL_END

#endif  // LETHE_UI_MAC_LETHE_INTERNAL_PAGES_H
