#ifndef LETHE_BROWSER_URL_INPUT_H
#define LETHE_BROWSER_URL_INPUT_H

// url_input.h - Address-bar text -> navigable URL
//
// Shared by every shell (macOS, GTK, Windows). Rules, in order:
//   1. Explicit http:// https:// about: URLs are kept (scheme lowercased).
//   2. Host-looking input (no spaces; has a dot, a port, or is an IP /
//      "localhost") gets a scheme: http:// for loopback, https:// otherwise
//      (HSTS-first; plaintext is never the default for remote hosts).
//   3. Anything else - including javascript:/data:/file: and other schemes
//      Lethe refuses - becomes a search-engine query. Fail closed.

#include <string>

namespace lethe {

constexpr const char kDefaultSearchTemplate[] = "https://duckduckgo.com/?q={}";

// RFC 3986 percent-encoding of a query component (unreserved chars kept).
std::string percentEncodeQueryComponent(const std::string& in);

// "" for blank input.
std::string normalizeAddressInput(
    const std::string& input,
    const std::string& searchTemplate = kDefaultSearchTemplate);

} // namespace lethe

#endif // LETHE_BROWSER_URL_INPUT_H
