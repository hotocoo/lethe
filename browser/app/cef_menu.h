// cef_menu.h - native macOS menu bar for the CEF (Blink) shell.
//
// The WebKit shell ships a full browser menu bar; the CEF shell used to ship
// four items, so most commands a macOS user expects (Quit, Copy, Close Tab,
// Back, zoom, history) simply did not exist there. This installs the same
// command surface on top of CEF, routed to the active CefBrowser.

#ifndef LETHE_BROWSER_APP_CEF_MENU_H
#define LETHE_BROWSER_APP_CEF_MENU_H

#import <Cocoa/Cocoa.h>

@class LetheCefAppDelegate;

// Installs the application menu bar. \p delegate receives the commands that
// need the application-level client (new tab, new Oblivion window).
void LetheCefInstallMenuBar(LetheCefAppDelegate* delegate);

#endif  // LETHE_BROWSER_APP_CEF_MENU_H
