#ifndef LETHE_BROWSER_APP_CEF_CHROME_H
#define LETHE_BROWSER_APP_CEF_CHROME_H

#include "include/cef_browser.h"
#include <string>

std::string LetheCefNewTabDataUrl();

// Attach Lethe's native browser chrome to the CEF-created macOS window.
// The CEF browser remains the page renderer; this layer owns the address bar
// and navigation controls that CEF does not provide itself.
void LetheCefChromeAttach(CefRefPtr<CefBrowser> browser);
void LetheCefChromeUpdate(CefRefPtr<CefBrowser> browser);
void LetheCefChromeSetAddress(CefRefPtr<CefBrowser> browser, const std::string& url);
void LetheCefChromeFocusAddress(CefRefPtr<CefBrowser> browser);
void LetheCefChromeDetach(CefRefPtr<CefBrowser> browser);

#endif
