#ifndef LETHE_NETWORK_DOH_CACHE_H
#define LETHE_NETWORK_DOH_CACHE_H

// doh_cache.h - process-wide DNS-over-HTTPS answer cache.
//
// HttpClient is deliberately single-threaded, so the browser mints one
// client per proxy connection, one for the navigation gate and one for
// reader fetches. Without a shared cache every one of them pays a full
// DoH round trip (TCP + TLS to the provider + query) for the same hostname
// - a page with 30 third-party hosts and 6 connections per host resolved
// the same names dozens of times. This cache is the one place every client
// consults first. Only successful answers are stored (failures always retry
// the provider), answers are keyed by provider so a provider change never
// serves stale data, and entries expire after the TTL. Thread-safe.

#include <chrono>
#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace lethe {

class SharedDohCache {
public:
    explicit SharedDohCache(std::chrono::seconds ttl = std::chrono::seconds(300),
                            size_t maxEntries = 4096)
        : ttl_(ttl), maxEntries_(maxEntries) {}

    // Resolved answers ------------------------------------------------
    bool lookup(const std::string& provider, const std::string& host, std::string& outIp);
    void store(const std::string& provider, const std::string& host, const std::string& ip);

    // Provider bootstrap addresses (the provider's own IPs, system-resolved
    // once per TTL instead of once per client).
    bool lookupBootstrap(const std::string& provider, std::vector<std::string>& outIps);
    void storeBootstrap(const std::string& provider, const std::vector<std::string>& ips);

    void clear();
    size_t size() const;

    struct Stats { uint64_t hits = 0; uint64_t misses = 0; };
    Stats stats() const;

    std::chrono::seconds ttl() const { return ttl_; }

private:
    struct Entry {
        std::string ip;
        std::chrono::steady_clock::time_point expires{};
    };
    struct Bootstrap {
        std::vector<std::string> ips;
        std::chrono::steady_clock::time_point expires{};
    };
    static std::string key(const std::string& provider, const std::string& host) {
        return provider + "|" + host;
    }
    void evictExpiredLocked(std::chrono::steady_clock::time_point now);

    mutable std::mutex mu_;
    std::map<std::string, Entry> entries_;
    std::map<std::string, Bootstrap> bootstrap_;
    std::chrono::seconds ttl_;
    size_t maxEntries_;
    Stats stats_;
};

} // namespace lethe

#endif // LETHE_NETWORK_DOH_CACHE_H
