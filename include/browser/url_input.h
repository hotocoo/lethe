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

// HTTPS-first (Chrome "HTTPS-First Mode" semantics, on by default): for a
// top-level http:// navigation return the https:// URL to try instead, or
// "" when no upgrade applies (already https, IP literal, localhost/.local,
// explicit non-80 port, or the host was allow-listed for plaintext).
std::string httpsUpgradeCandidate(const std::string& url);

// Internal action link placed on the error page after an upgrade failed:
// clicking it allow-lists the host for plaintext and loads the http URL.
constexpr const char kHttpFallbackScheme[] = "lethe-action";
std::string httpFallbackActionUrl(const std::string& httpUrl);
// Parse an action URL back into the http URL ("" when it is not one).
std::string parseHttpFallbackActionUrl(const std::string& actionUrl);

// Host part of a URL (lowercased, without port); "" when unparsable.
std::string urlHost(const std::string& url);

// "" for blank input.
std::string normalizeAddressInput(
    const std::string& input,
    const std::string& searchTemplate = kDefaultSearchTemplate);

} // namespace lethe

#endif // LETHE_BROWSER_URL_INPUT_H
