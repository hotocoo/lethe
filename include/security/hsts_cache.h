#ifndef LETHE_SECURITY_HSTS_CACHE_H
#define LETHE_SECURITY_HSTS_CACHE_H

#include <chrono>
#include <cstdint>
#include <map>
#include <string>

namespace lethe {

// HstsCache — in-memory HTTP Strict Transport Security (RFC 6797) policy
// store.
//
// Remembers which hosts have declared Strict-Transport-Security over a
// verified HTTPS connection and until when, so later http:// requests to
// those hosts are transparently upgraded to https:// BEFORE any network
// I/O happens — the plaintext request is never even attempted.
//
// Semantics implemented from RFC 6797:
//   - Policy is only honored when received over a secure transport (the
//     HttpClient only records STS on https:// hops; this class additionally
//     refuses IP-literal hosts, which cannot carry an HSTS identity).
//   - "includeSubDomains" extends coverage to every subdomain of the
//     recorded host (but never to a sibling or an unrelated host).
//   - max-age=0 removes an existing policy for that host.
//   - Expired policies stop upgrading immediately.
//
// Like the partitioned cookie jar this cache lives in memory only: nothing
// ever touches disk and everything is dropped on exit.
class HstsCache {
public:
    HstsCache() = default;

    // Parse ONE Strict-Transport-Security field value into maxAge +
    // includeSubDomains. Returns false when the whole header must be
    // ignored (missing or unparsable max-age, RFC 6797 section 11.3);
    // unknown directives are ignored. max-age=0 parses fine (revocation).
    static bool parseStsHeader(const std::string& value,
                               std::chrono::seconds& maxAge,
                               bool& includeSubDomains);

    // Record/refresh the policy for p host learned from one
    // Strict-Transport-Security header received over HTTPS.
    //   maxAge <= 0  -> any existing entry for host is removed (max-age=0).
    //   includeSubDomains -> policy also covers host's subdomains.
    // p now lets tests inject deterministic timestamps; production callers
    // use the steady-clock default.
    void record(const std::string& host,
                std::chrono::seconds maxAge,
                bool includeSubDomains,
                std::chrono::steady_clock::time_point now =
                    std::chrono::steady_clock::now());

    // True when plain-HTTP requests to p host must be upgraded to HTTPS:
    // a live (unexpired) exact match, or an unexpired includeSubDomains
    // match on one of its parent domains. IP literals never upgrade.
    bool shouldUpgrade(const std::string& host,
                       std::chrono::steady_clock::time_point now =
                           std::chrono::steady_clock::now()) const;

    // Number of live entries (expired ones do not count and are pruned).
    size_t size(std::chrono::steady_clock::time_point now =
                    std::chrono::steady_clock::now()) const;

    // Drop every policy (engine shutdown / privacy purge).
    void clear();

private:
    static std::string normalizeHost(const std::string& host);
    static bool isIpLiteral(const std::string& host);
    void pruneExpired(std::chrono::steady_clock::time_point now);
    // Bounded memory: least-recently-recorded policy evicted beyond cap.
    static constexpr size_t kMaxEntries = 512;

    struct Entry {
        std::chrono::steady_clock::time_point expires{};
        bool includeSubDomains = false;
        uint64_t seq = 0;  // insertion sequence; lowest = evicted first
    };

    std::map<std::string, Entry> entries_;
    uint64_t nextSeq_ = 0;
};

} // namespace lethe

#endif // LETHE_SECURITY_HSTS_CACHE_H
