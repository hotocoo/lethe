#ifndef LETHE_SECURITY_COOKIE_JAR_H
#define LETHE_SECURITY_COOKIE_JAR_H

// cookie_jar.h - Partitioned, memory-only cookie storage.
//
// Privacy model (README "Privacy" contract):
//  - Cookie PARTITIONING: every cookie is keyed by the TOP-LEVEL site that
//    is being visited, so a host embedded in two different top-level
//    documents never shares cookie state across those contexts.
//  - SameSite (RFC6265bis): cookies are withheld from cross-site requests
//    unless they explicitly opted in with SameSite=None (+ Secure), and the
//    __Secure-/__Host- name prefixes are enforced at storage time.
//  - INCOGNITO BY DEFAULT: the jar lives only in process memory; Engine
//    purges it on shutdown so nothing about the session survives exit and
//    nothing is ever written to disk.

#include <chrono>
#include <cstddef>
#include <map>
#include <string>

namespace lethe {

// SameSite enforcement level (RFC6265bis "SameSite attribute").
enum class SameSite {
    Unspecified, // no attribute sent: Lax-by-default enforcement applies
    Lax,         // withheld from cross-site requests except top-level
                 // navigations with a safe method
    Strict,      // withheld from every cross-site request, navigations
                 // included
    None,        // explicit cross-site allowance; only ever accepted with
                 // the Secure attribute (rejected otherwise at store time)
};

// Delivery context for ONE request: everything the jar needs to decide
// which of the matching cookies may ride it.
struct CookieRequestContext {
    // URL that triggered this request (the document for subresource/API
    // fetches; the previous hop while following redirects). Empty means
    // "no initiator" (e.g. an address-bar navigation), which is never
    // cross-site.
    std::string initiatorUrl;
    // True for top-level user navigations; false for embedded subresource
    // and API traffic. Only top-level safe-method navigations may carry
    // Lax cookies cross-site.
    bool topNavigation = false;
    // RFC7231-safe method (GET/HEAD/...). Unsafe methods never carry Lax
    // cookies across sites - a cross-site POST is exactly what CSRF and
    // SameSite exist to stop.
    bool safeMethod = true;
};

struct StoredCookie {
    std::string name;
    std::string value;
    std::string domain;   // lowercased domain the cookie is bound to
    std::string path;     // request-path scope (default "/")
    bool hostOnly = true; // no Domain attribute: exact-host match only
    bool secure = false;  // delivered over https:// requests only
    bool httpOnly = false;
    // Session cookies carry the epoch maximum. Steady clock keeps expiries
    // immune to wall-clock jumps.
    std::chrono::steady_clock::time_point expiry =
        std::chrono::steady_clock::time_point::max();
    // SameSite level this cookie was stored with (Unspecified when no
    // attribute arrived - enforced as Lax-by-default at delivery).
    SameSite sameSite = SameSite::Unspecified;
};

class CookieJar {
public:
    // Partition key for a URL: scheme://host[:non-default-port]. Path,
    // query, fragment, and userinfo are dropped so every page of a site
    // shares exactly one partition.
    static std::string topLevelSiteFor(const std::string& url);

    // Parse one Set-Cookie header VALUE (single cookie, no CRLF) observed
    // while requesting \p requestUrl inside top-level site \p topLevelSite,
    // and store or replace it. Cookies whose Domain attribute does not
    // match the request host are rejected (no cross-host writes).
    void store(const std::string& topLevelSite,
               const std::string& requestUrl,
               const std::string& setCookieValue);

    // Compose "name=value; name2=value2" for a request to \p requestUrl
    // under \p topLevelSite, honouring domain/path/secure/expiry scoping.
    // Returns "" when nothing matches. Prunes expired entries on access.
    //
    // SameSite-aware form: \p ctx describes WHO triggered the request
    // (initiator, navigation kind, method safety) so matching cookies are
    // filtered per RFC6265bis - Strict never crosses sites, Lax only rides
    // safe-method top-level navigations, None always goes (it was required
    // to be Secure at store time). The two-argument form below treats the
    // request as same-site (every match delivered).
    std::string headerFor(const std::string& topLevelSite,
                          const std::string& requestUrl,
                          const CookieRequestContext& ctx) const;

    // Same-site shorthand: treats the request as initiated by its own site
    // (every matching cookie delivered - no cross-site filtering).
    std::string headerFor(const std::string& topLevelSite,
                          const std::string& requestUrl) const;

    // Number of live (non-expired) stored cookies.
    size_t size() const;
    bool empty() const { return size() == 0; }

    void purgeExpired();
    // Full wipe - session exit / incognito teardown.
    void purge();

private:
    struct Key {
        std::string partition;
        std::string domain;
        std::string path;
        std::string name;
        bool operator<(const Key& o) const {
            if (partition != o.partition) return partition < o.partition;
            if (domain != o.domain) return domain < o.domain;
            if (path != o.path) return path < o.path;
            return name < o.name;
        }
    };

    std::map<Key, StoredCookie> cookies_;
    static constexpr size_t kMaxCookies = 2048;

    static bool domainMatches(const std::string& host, const std::string& domain);
    static bool pathMatches(const std::string& requestPath, const std::string& cookiePath);
    static std::string directoryOf(const std::string& path);
    void evictOne();
};

} // namespace lethe

#endif // LETHE_SECURITY_COOKIE_JAR_H
