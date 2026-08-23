#ifndef LETHE_SECURITY_COOKIE_JAR_H
#define LETHE_SECURITY_COOKIE_JAR_H

// cookie_jar.h - Partitioned, memory-only cookie storage.
//
// Privacy model (README "Privacy" contract):
//  - Cookie PARTITIONING: every cookie is keyed by the TOP-LEVEL site that
//    is being visited, so a host embedded in two different top-level
//    documents never shares cookie state across those contexts.
//  - INCOGNITO BY DEFAULT: the jar lives only in process memory; Engine
//    purges it on shutdown so nothing about the session survives exit and
//    nothing is ever written to disk.

#include <chrono>
#include <cstddef>
#include <map>
#include <string>

namespace lethe {

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
