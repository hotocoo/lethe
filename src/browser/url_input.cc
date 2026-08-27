// url_input.cc - Address-bar text -> navigable URL (see header)

#include "browser/url_input.h"

#include <cctype>
#include <cstdio>

namespace lethe {

namespace {

std::string trim(const std::string& s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return s.substr(b, e - b);
}

std::string lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Leading "<scheme>:" per RFC 3986 (ALPHA *( ALPHA / DIGIT / + / - / . )).
// Returns the scheme (lowercased) or "" when the input has none.
std::string leadingScheme(const std::string& s) {
    if (s.empty() || !std::isalpha(static_cast<unsigned char>(s[0]))) return "";
    size_t i = 1;
    while (i < s.size()) {
        const unsigned char c = static_cast<unsigned char>(s[i]);
        if (std::isalnum(c) || c == '+' || c == '-' || c == '.') { ++i; continue; }
        break;
    }
    if (i < s.size() && s[i] == ':') return lower(s.substr(0, i));
    return "";
}

bool isDigits(const std::string& s) {
    if (s.empty()) return false;
    for (char c : s) if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    return true;
}

// Authority part of scheme-less input: up to first '/', '?' or '#'.
std::string authorityOf(const std::string& s) {
    const size_t end = s.find_first_of("/?#");
    return end == std::string::npos ? s : s.substr(0, end);
}

// Split "host[:port]" (bracketed IPv6 aware). Returns false on garbage.
bool splitHostPort(const std::string& authority, std::string& host,
                   std::string& port) {
    if (authority.empty()) return false;
    if (authority[0] == '[') {
        const size_t close = authority.find(']');
        if (close == std::string::npos) return false;
        host = authority.substr(0, close + 1);
        const std::string rest = authority.substr(close + 1);
        if (rest.empty()) { port.clear(); return true; }
        if (rest[0] != ':') return false;
        port = rest.substr(1);
        return isDigits(port);
    }
    const size_t colon = authority.rfind(':');
    if (colon == std::string::npos) { host = authority; port.clear(); return true; }
    host = authority.substr(0, colon);
    port = authority.substr(colon + 1);
    return !host.empty() && isDigits(port);
}

bool isIPv4Literal(const std::string& h) {
    int dots = 0;
    std::string part;
    for (size_t i = 0; i <= h.size(); ++i) {
        if (i == h.size() || h[i] == '.') {
            if (!isDigits(part) || part.size() > 3) return false;
            if (std::stoi(part) > 255) return false;
            part.clear();
            if (i < h.size()) ++dots;
        } else {
            part += h[i];
        }
    }
    return dots == 3;
}

bool isLoopbackHost(const std::string& hostLower) {
    if (hostLower == "localhost" || hostLower == "[::1]") return true;
    if (hostLower.size() > 10 && hostLower.compare(hostLower.size() - 10, 10,
                                                    ".localhost") == 0)
        return true;
    return hostLower.rfind("127.", 0) == 0 && isIPv4Literal(hostLower);
}

// Hostname characters only (letters, digits, '-', '.', and '_' which real
// DNS tolerates). Anything else means "not a host".
bool looksLikeHostname(const std::string& h) {
    if (h.empty() || h.front() == '.' || h.back() == '.' || h.front() == '-')
        return false;
    for (char c : h) {
        const unsigned char u = static_cast<unsigned char>(c);
        if (!(std::isalnum(u) || c == '-' || c == '.' || c == '_')) return false;
    }
    return true;
}

std::string toSearch(const std::string& q, const std::string& tmpl) {
    const std::string enc = percentEncodeQueryComponent(q);
    const size_t pos = tmpl.find("{}");
    if (pos == std::string::npos) return tmpl + enc;
    return tmpl.substr(0, pos) + enc + tmpl.substr(pos + 2);
}

} // namespace

std::string percentEncodeQueryComponent(const std::string& in) {
    std::string out;
    out.reserve(in.size() * 3);
    for (unsigned char c : in) {
        if (std::isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
            out += static_cast<char>(c);
        } else {
            char buf[4];
            std::snprintf(buf, sizeof(buf), "%%%02X", c);
            out += buf;
        }
    }
    return out;
}

std::string normalizeAddressInput(const std::string& input,
                                  const std::string& searchTemplate) {
    const std::string text = trim(input);
    if (text.empty()) return "";

    std::string scheme = leadingScheme(text);
    // "host:8080" is a port, not a scheme: a digit right after the colon
    // means authority syntax (schemes are never followed by a bare number).
    if (!scheme.empty() && scheme.size() + 1 < text.size() &&
        std::isdigit(static_cast<unsigned char>(text[scheme.size() + 1]))) {
        scheme.clear();
    }
    if (!scheme.empty()) {
        if (scheme == "http" || scheme == "https") {
            return scheme + text.substr(scheme.size());
        }
        if (scheme == "about") return "about:blank";
        // javascript:, data:, file:, ftp:, ... - never navigate.
        return toSearch(text, searchTemplate);
    }

    if (text.find_first_of(" \t\r\n") != std::string::npos) {
        return toSearch(text, searchTemplate);
    }

    std::string host, port;
    if (!splitHostPort(authorityOf(text), host, port)) {
        return toSearch(text, searchTemplate);
    }
    const std::string hostLower = lower(host);
    const bool bracketedV6 = host.size() > 2 && host.front() == '[';
    const bool hostLike =
        bracketedV6 || isIPv4Literal(hostLower) || isLoopbackHost(hostLower) ||
        (looksLikeHostname(hostLower) &&
         (hostLower.find('.') != std::string::npos || !port.empty()));
    if (!hostLike) return toSearch(text, searchTemplate);

    const char* prefix = isLoopbackHost(hostLower) ? "http://" : "https://";
    return prefix + text;
}


std::string urlHost(const std::string& url) {
    const size_t scheme = url.find("://");
    if (scheme == std::string::npos) return "";
    size_t start = scheme + 3;
    const size_t at = url.find('@', start);
    const size_t slash = url.find_first_of("/?#", start);
    if (at != std::string::npos && (slash == std::string::npos || at < slash)) start = at + 1;
    std::string authority = url.substr(start, slash == std::string::npos ? std::string::npos : slash - start);
    if (!authority.empty() && authority[0] == '[') {
        const size_t close = authority.find(']');
        return close == std::string::npos ? "" : lower(authority.substr(0, close + 1));
    }
    const size_t colon = authority.rfind(':');
    if (colon != std::string::npos) authority = authority.substr(0, colon);
    return lower(authority);
}

std::string httpsUpgradeCandidate(const std::string& url) {
    if (url.size() < 8 || lower(url.substr(0, 7)) != "http://") return "";
    const std::string host = urlHost(url);
    if (host.empty() || host == "localhost" || host[0] == '[') return "";
    if (host.size() > 6 && host.compare(host.size() - 6, 6, ".local") == 0) return "";
    if (host.find_first_not_of("0123456789.") == std::string::npos) return "";  // IPv4 literal
    // Explicit port: keep plaintext unless it is the http default.
    const size_t start = 7;
    size_t authorityEnd = url.find_first_of("/?#", start);
    if (authorityEnd == std::string::npos) authorityEnd = url.size();
    std::string authority = url.substr(start, authorityEnd - start);
    const size_t at = authority.find('@');
    if (at != std::string::npos) authority = authority.substr(at + 1);
    const size_t colon = authority.rfind(':');
    if (colon != std::string::npos) {
        const std::string port = authority.substr(colon + 1);
        if (port != "80") return "";
        authority = authority.substr(0, colon);
    }
    return "https://" + authority + url.substr(authorityEnd);
}

std::string httpFallbackActionUrl(const std::string& httpUrl) {
    return std::string(kHttpFallbackScheme) + "://allow-http?u=" + percentEncodeQueryComponent(httpUrl);
}

std::string parseHttpFallbackActionUrl(const std::string& actionUrl) {
    const std::string prefix = std::string(kHttpFallbackScheme) + "://allow-http?u=";
    if (actionUrl.rfind(prefix, 0) != 0) return "";
    const std::string enc = actionUrl.substr(prefix.size());
    std::string out;
    for (size_t i = 0; i < enc.size(); i++) {
        if (enc[i] == '%') {
            if (i + 2 >= enc.size()) return "";   // truncated escape
            auto hex = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            const int hi = hex(enc[i + 1]), lo = hex(enc[i + 2]);
            if (hi < 0 || lo < 0) return "";
            out.push_back(static_cast<char>(hi * 16 + lo));
            i += 2;
        } else {
            out.push_back(enc[i]);
        }
    }
    if (out.rfind("http://", 0) != 0) return "";
    return out;
}

} // namespace lethe
