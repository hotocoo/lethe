// cookie_jar.cc - Partitioned, memory-only cookie storage.
//
// Implements the privacy claims documented in README ("Cookie
// partitioning", "Incognito by default"): per-top-level-site isolation,
// strict scoping, and in-memory-only state that Engine purges on shutdown.

#include "security/cookie_jar.h"

#include <algorithm>
#include <cctype>
#include <ctime>
#include <sstream>

namespace lethe {

namespace {

std::string trimCopy(const std::string& s) {
    size_t b = s.find_first_not_of(" \t");
    if (b == std::string::npos) return "";
    size_t e = s.find_last_not_of(" \t");
    return s.substr(b, e - b + 1);
}

std::string toLowerCopy(const std::string& s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

// Case-insensitive attribute name match.
bool attrIs(const std::string& rawName, const char* attr) {
    return toLowerCopy(rawName) == toLowerCopy(attr);
}

struct UrlParts {
    std::string scheme;
    std::string host;
    std::string path;
    int port = 0;
};

UrlParts splitUrl(const std::string& url) {
    UrlParts p;
    const size_t schemeEnd = url.find("://");
    if (schemeEnd == std::string::npos) return p;
    p.scheme = toLowerCopy(url.substr(0, schemeEnd));

    std::string rest = url.substr(schemeEnd + 3);
    // Drop query/fragment, then userinfo.
    rest = rest.substr(0, rest.find_first_of("?#"));
    const size_t at = rest.find('@');
    if (at != std::string::npos) rest = rest.substr(at + 1);

    size_t pathStart = rest.find('/');
    if (pathStart == std::string::npos) {
        p.path = "/";
    } else {
        p.path = rest.substr(pathStart);
        rest = rest.substr(0, pathStart);
    }

    const size_t colon = rest.rfind(':');
    if (colon != std::string::npos && rest.find(']') == std::string::npos) {
        p.host = toLowerCopy(rest.substr(0, colon));
        try {
            p.port = std::stoi(rest.substr(colon + 1));
        } catch (...) {
            p.port = 0;
        }
    } else {
        p.host = toLowerCopy(rest);
    }
    return p;
}

} // namespace

namespace detail {
inline std::chrono::steady_clock::time_point steadyFromEpoch(time_t epoch) {
    // Both clocks share the same duration type resolution we care about
    // (seconds); converting through their epochs keeps expiry arithmetic
    // on one timeline inside the jar.
    const auto sysSince = std::chrono::system_clock::now().time_since_epoch();
    const auto stlNow = std::chrono::duration_cast<std::chrono::seconds>(sysSince);
    const auto delta = std::chrono::seconds(epoch) - stlNow;
    return std::chrono::steady_clock::now() + delta;
}
} // namespace detail

static std::chrono::steady_clock::time_point parseExpiry(const std::string& value,
                                                         bool& ok) {
    ok = false;
    static const char* months[12] = {"jan", "feb", "mar", "apr", "may", "jun",
                                     "jul", "aug", "sep", "oct", "nov", "dec"};
    const std::string lowered = toLowerCopy(value);

    int monthIdx = -1;
    for (int i = 0; i < 12; i++) {
        if (lowered.find(months[i]) != std::string::npos) { monthIdx = i; break; }
    }
    if (monthIdx < 0) return {};

    int day = -1, year = -1, hour = -1, minute = -1, second = -1;
    std::istringstream iss(lowered);
    std::string tok;
    while (iss >> tok) {
        tok.erase(std::remove_if(tok.begin(), tok.end(),
                                 [](char c) { return c == ',' || c == '-'; }),
                  tok.end());
        if (tok.empty() ||
            !std::all_of(tok.begin(), tok.end(),
                         [](unsigned char c) { return std::isdigit(c); })) continue;
        const int v = std::atoi(tok.c_str());
        if (tok.size() >= 4 && v >= 1600 && year < 0) { year = v; }
        else if (v >= 70 && v <= 99 && year < 0) { year = 1900 + v; }
        else if (v >= 1 && v <= 31 && day < 0) { day = v; }
        else if (v >= 0 && v <= 9999 && year < 0 && tok.size() < 4) { year = v; }
    }
    const size_t c1 = lowered.find(':');
    if (c1 != std::string::npos && c1 >= 2 && c1 + 5 < lowered.size()) {
        auto twoAt = [&](size_t pos) -> int {
            if (pos + 1 >= lowered.size()) return -1;
            if (!std::isdigit(static_cast<unsigned char>(lowered[pos])) ||
                !std::isdigit(static_cast<unsigned char>(lowered[pos + 1]))) return -1;
            return std::atoi(lowered.substr(pos, 2).c_str());
        };
        hour = twoAt(c1 - 2);
        minute = twoAt(c1 + 1);
        second = twoAt(c1 + 4);
    }
    if (day < 0 || year < 0 || hour < 0 || minute < 0 || second < 0) return {};
    if (year < 100) year += (year < 70 ? 2000 : 1900);

    ::tm tmv{};
    tmv.tm_year = year - 1900;
    tmv.tm_mon = monthIdx;
    tmv.tm_mday = day;
    tmv.tm_hour = hour;
    tmv.tm_min = minute;
    tmv.tm_sec = second;
#if defined(_WIN32)
    const time_t epoch = _mkgmtime(&tmv);
#else
    const time_t epoch = ::timegm(&tmv);
#endif
    if (epoch < 0) return {};
    ok = true;
    return detail::steadyFromEpoch(epoch);
}

// --- CookieJar ----------------------------------------------------------------

std::string CookieJar::topLevelSiteFor(const std::string& url) {
    const UrlParts p = splitUrl(url);
    if (p.scheme.empty() || p.host.empty()) return "";
    std::string site = p.scheme + "://" + p.host;
    if ((p.scheme == "https" && p.port != 0 && p.port != 443) ||
        (p.scheme == "http" && p.port != 0 && p.port != 80)) {
        site += ":" + std::to_string(p.port);
    }
    return site;
}

bool CookieJar::domainMatches(const std::string& host, const std::string& domain) {
    if (host == domain) return true;
    if (host.size() > domain.size() &&
        host.compare(host.size() - domain.size(), domain.size(), domain) == 0 &&
        host[host.size() - domain.size() - 1] == '.') {
        return true;
    }
    return false;
}

std::string CookieJar::directoryOf(const std::string& path) {
    const size_t lastSlash = path.find_last_of('/');
    if (lastSlash == std::string::npos) return "/";
    return path.substr(0, lastSlash + 1);
}

bool CookieJar::pathMatches(const std::string& requestPath,
                            const std::string& cookiePath) {
    if (requestPath == cookiePath) return true;
    if (requestPath.size() < cookiePath.size()) return false;
    if (requestPath.compare(0, cookiePath.size(), cookiePath) != 0) return false;
    return cookiePath.back() == '/' ||
           (requestPath.size() > cookiePath.size() &&
            requestPath[cookiePath.size()] == '/');
}

void CookieJar::evictOne() {
    // Drop the entry expiring soonest; session cookies (max expiry) count
    // as latest so fresh data survives before old sessions do.
    auto it = cookies_.begin();
    auto victim = it;
    for (; it != cookies_.end(); ++it) {
        if (it->second.expiry < victim->second.expiry) victim = it;
    }
    if (victim != cookies_.end()) cookies_.erase(victim);
}

void CookieJar::store(const std::string& topLevelSite,
                      const std::string& requestUrl,
                      const std::string& setCookieValue) {
    if (setCookieValue.empty()) return;
    const std::string firstSemi = setCookieValue.substr(0, setCookieValue.find(';'));
    const size_t eq = firstSemi.find('=');
    if (eq == std::string::npos) return; // not a name=value pair

    StoredCookie c;
    c.name = trimCopy(firstSemi.substr(0, eq));
    c.value = trimCopy(firstSemi.substr(eq + 1));
    if (c.name.empty()) return;

    UrlParts req = splitUrl(requestUrl);
    if (req.host.empty()) return;
    const std::string partition =
        topLevelSite.empty() ? topLevelSiteFor(requestUrl) : topLevelSite;
    if (partition.empty()) return;

    bool hasDomainAttr = false;
    bool hasPathAttr = false;
    bool deleteExisting = false;

    // Attribute walk.
    size_t start = setCookieValue.find(';');
    while (start != std::string::npos) {
        const size_t end = setCookieValue.find(';', start + 1);
        std::string attr =
            setCookieValue.substr(start + 1, end == std::string::npos
                                                ? std::string::npos
                                                : end - (start + 1));
        attr = trimCopy(attr);
        if (!attr.empty()) {
            const size_t aEq = attr.find('=');
            const std::string aName = trimCopy(aEq == std::string::npos
                                                   ? attr
                                                   : attr.substr(0, aEq));
            const std::string aValue = aEq == std::string::npos
                                           ? ""
                                           : trimCopy(attr.substr(aEq + 1));
            if (attrIs(aName, "secure")) {
                c.secure = true;
            } else if (attrIs(aName, "httponly")) {
                c.httpOnly = true;
            } else if (attrIs(aName, "domain")) {
                std::string d = toLowerCopy(aValue);
                if (!d.empty() && d.front() == '.') d.erase(d.begin());
                if (d.empty() || !domainMatches(req.host, d)) {
                    return; // foreign Domain: reject the whole cookie
                }
                c.domain = d;
                c.hostOnly = false;
                hasDomainAttr = true;
            } else if (attrIs(aName, "samesite")) {
                const std::string v = toLowerCopy(aValue);
                if (v == "lax") {
                    c.sameSite = SameSite::Lax;
                } else if (v == "strict") {
                    c.sameSite = SameSite::Strict;
                } else if (v == "none") {
                    c.sameSite = SameSite::None;
                }
                // Unknown values leave Unspecified: the processor ignores
                // attributes it does not recognize (RFC6265bis 5.7.1).
            } else if (attrIs(aName, "path")) {
                if (!aValue.empty() && aValue.front() == '/') {
                    c.path = aValue;
                    hasPathAttr = true;
                }
            } else if (attrIs(aName, "max-age")) {
                try {
                    const long secs = std::stol(aValue);
                    if (secs <= 0) {
                        deleteExisting = true;
                        c.expiry = std::chrono::steady_clock::time_point{};
                    } else {
                        c.expiry = std::chrono::steady_clock::now() +
                                   std::chrono::seconds(secs);
                    }
                } catch (...) {
                    // malformed Max-Age: ignore (Expires may still apply)
                }
            } else if (attrIs(aName, "expires")) {
                bool ok = false;
                auto when = parseExpiry(aValue, ok);
                if (ok) {
                    c.expiry = when;
                    if (when <= std::chrono::steady_clock::now()) deleteExisting = true;
                }
            }
        }
        if (end == std::string::npos) break;
        start = end;
    }

    if (!hasDomainAttr) {
        c.domain = req.host; // host-only cookie
    }
    if (c.path.empty() || c.path.front() != '/') {
        c.path = directoryOf(req.path);
    }

    // RFC6265bis: SameSite=None opts a cookie into CROSS-SITE delivery and
    // is therefore only ever accepted WITH the Secure attribute; without it
    // the whole Set-Cookie is rejected outright.
    if (c.sameSite == SameSite::None && !c.secure) return;

    // Cookie-name prefixes (RFC6265bis 4.1.3), matched case-insensitively.
    const std::string lowerName = toLowerCopy(c.name);
    if (lowerName.rfind("__secure-", 0) == 0 ||
        lowerName.rfind("__host-", 0) == 0) {
        // Both prefixes are security assertions: they demand the Secure
        // attribute and an https:// origin - such a cookie can never be
        // planted over plaintext http.
        if (!c.secure || req.scheme != "https") return;
    }
    if (lowerName.rfind("__host-", 0) == 0) {
        // __Host- additionally pins the cookie to THIS exact host at the
        // site root: host-only (no Domain attribute) and explicit Path=/.
        if (!c.hostOnly || !hasPathAttr || c.path != "/") return;
    }

    Key key{partition, c.domain, c.path, c.name};
    auto existing = cookies_.find(key);
    if (deleteExisting) {
        cookies_.erase(existing);
        return;
    }

    if (existing == cookies_.end() && cookies_.size() >= kMaxCookies) {
        evictOne();
    }
    cookies_[key] = c;
}

std::string CookieJar::headerFor(const std::string& topLevelSite,
                                 const std::string& requestUrl,
                                 const CookieRequestContext& ctx) const {
    const UrlParts req = splitUrl(requestUrl);
    if (req.host.empty()) return "";
    const std::string partition =
        topLevelSite.empty() ? topLevelSiteFor(requestUrl) : topLevelSite;
    if (partition.empty()) return "";

    const auto now = std::chrono::steady_clock::now();
    // SameSite: cross-site when the initiator lives on another site than
    // the request itself (scheme counted; no initiator = never cross-site).
    const bool crossSite =
        !ctx.initiatorUrl.empty() &&
        topLevelSiteFor(ctx.initiatorUrl) != topLevelSiteFor(requestUrl);
    std::string header;
    for (const auto& kv : cookies_) {
        if (kv.first.partition != partition) continue;
        const StoredCookie& c = kv.second;
        if (kv.second.expiry <= now) continue; // lazily skipped; purged elsewhere
        if (c.secure && req.scheme != "https") continue;
        if (c.hostOnly ? (req.host != c.domain)
                       : !domainMatches(req.host, c.domain)) continue;
        if (!pathMatches(req.path.empty() ? "/" : req.path, c.path)) continue;
        // RFC6265bis SameSite delivery filter.
        switch (c.sameSite) {
        case SameSite::Strict:
            if (crossSite) continue; // never crosses sites
            break;
        case SameSite::Lax:
        case SameSite::Unspecified:
            // Lax-by-default: cross-site only on safe-method top-level
            // navigations - the classic link-click allowance.
            if (crossSite && !(ctx.topNavigation && ctx.safeMethod)) continue;
            break;
        case SameSite::None:
            break; // explicit cross-site allowance (Secure was required)
        }
        if (!header.empty()) header += "; ";
        header += c.name + "=" + c.value;
    }
    return header;
}

std::string CookieJar::headerFor(const std::string& topLevelSite,
                                 const std::string& requestUrl) const {
    // Same-site shorthand: the initiator IS the target site, so no
    // matching cookie is withheld by SameSite.
    CookieRequestContext ctx;
    ctx.initiatorUrl = requestUrl;
    ctx.topNavigation = true;
    ctx.safeMethod = true;
    return headerFor(topLevelSite, requestUrl, ctx);
}

size_t CookieJar::size() const {
    const auto now = std::chrono::steady_clock::now();
    size_t n = 0;
    for (const auto& kv : cookies_) {
        if (kv.second.expiry > now) n++;
    }
    return n;
}

void CookieJar::purgeExpired() {
    const auto now = std::chrono::steady_clock::now();
    for (auto it = cookies_.begin(); it != cookies_.end();) {
        if (it->second.expiry <= now) it = cookies_.erase(it);
        else ++it;
    }
}

void CookieJar::purge() { cookies_.clear(); }

} // namespace lethe
