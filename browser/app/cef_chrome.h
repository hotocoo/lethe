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
void LetheCefChromeSetTitle(CefRefPtr<CefBrowser> browser, const std::string& title);
void LetheCefChromeSetAddress(CefRefPtr<CefBrowser> browser, const std::string& url);
void LetheCefChromeSetLoading(CefRefPtr<CefBrowser> browser, bool loading);
void LetheCefChromeSetLoadingProgress(CefRefPtr<CefBrowser> browser, double progress);
void LetheCefChromeFocusAddress(CefRefPtr<CefBrowser> browser);
void LetheCefChromeFocusActiveAddress();
void LetheCefChromeReloadActive();
void LetheCefChromeDetach(CefRefPtr<CefBrowser> browser);
void LetheCefChromeShowSettings();

// Active-window accessors used by the native menu bar. The active browser is
// the one hosting the key (or main) window, which is what a menu command
// issued from the keyboard or menu bar should act on.
CefRefPtr<CefBrowser> LetheCefActiveBrowser();
void LetheCefChromeToggleReaderActive();
void LetheCefChromeToggleBookmarkActive();
void LetheCefChromeLoadActive(const std::string& url);

#endif
