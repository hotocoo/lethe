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

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace lethe {

class SharedDohCache {
public:
    explicit SharedDohCache(std::chrono::seconds ttl = std::chrono::seconds(300),
                            size_t maxEntries = 4096)
        : ttl_(ttl), maxEntries_(maxEntries) {
        entries_.reserve(std::min<size_t>(maxEntries_, size_t{4096}));
    }

    // Resolved answers ------------------------------------------------
    // true when an entry exists. outIp is the address, or "" for a cached
    // NEGATIVE answer (the provider answered and had no A record).
    bool lookup(const std::string& provider, const std::string& host, std::string& outIp);
    void store(const std::string& provider, const std::string& host, const std::string& ip);
    // A provider that answered "no such address" is authoritative for a
    // short while: repeated connection attempts to the same dead host
    // (engines retry) must not each cost a provider round trip. Transport
    // failures are never cached - fail-closed retries stay immediate.
    void storeNegative(const std::string& provider, const std::string& host);
    std::chrono::seconds negativeTtl() const { return negativeTtl_; }

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
    struct DohKey {
        std::string provider;
        std::string host;
    };
    struct DohKeyView {
        std::string_view provider;
        std::string_view host;
    };
    struct DohKeyHash {
        using is_transparent = void;

        static size_t mix(std::string_view value, size_t hash) noexcept {
            for (unsigned char c : value) {
                hash ^= c;
                hash *= (sizeof(size_t) == 8 ? 1099511628211ULL : 16777619U);
            }
            return hash;
        }
        size_t operator()(const DohKeyView& key) const noexcept {
            size_t hash = sizeof(size_t) == 8 ? 1469598103934665603ULL : 2166136261U;
            hash = mix(key.provider, hash);
            hash ^= 0xff;
            hash *= (sizeof(size_t) == 8 ? 1099511628211ULL : 16777619U);
            return mix(key.host, hash);
        }
        size_t operator()(const DohKey& key) const noexcept {
            return (*this)(DohKeyView{key.provider, key.host});
        }
    };
    struct DohKeyEqual {
        using is_transparent = void;
        bool operator()(const DohKeyView& a, const DohKeyView& b) const noexcept {
            return a.provider == b.provider && a.host == b.host;
        }
        bool operator()(const DohKey& a, const DohKeyView& b) const noexcept {
            return a.provider == b.provider && a.host == b.host;
        }
        bool operator()(const DohKeyView& a, const DohKey& b) const noexcept {
            return a.provider == b.provider && a.host == b.host;
        }
        bool operator()(const DohKey& a, const DohKey& b) const noexcept {
            return a.provider == b.provider && a.host == b.host;
        }
    };
    struct Entry {
        std::string ip;
        std::chrono::steady_clock::time_point expires{};
    };
    struct Bootstrap {
        std::vector<std::string> ips;
        std::chrono::steady_clock::time_point expires{};
    };
    void evictExpiredLocked(std::chrono::steady_clock::time_point now);
    size_t totalEntriesLocked() const;

    // DNS lookups are overwhelmingly reads. A single exclusive mutex made
    // otherwise-independent proxy workers serialize on every cache hit. Use
    // shared ownership for the lookup path; expired entries are left for the
    // next writer to reap instead of upgrading a hot read into an exclusive
    // lock. This keeps the cache correctness-neutral (it is only an optional
    // latency optimization) while removing a cross-worker contention point.
    mutable std::shared_mutex mu_;
    // Store provider and hostname separately in the owning key, but expose a
    // transparent view for lookup. This avoids the old provider+"|"+host
    // temporary allocation without paying for two hash-table lookups as the
    // nested-map design did. One table lookup is important under browser
    // fan-out where the same cache is read concurrently by many workers.
    std::unordered_map<DohKey, Entry, DohKeyHash, DohKeyEqual> entries_;
    std::unordered_map<std::string, Bootstrap> bootstrap_;
    std::chrono::seconds ttl_;
    std::chrono::seconds negativeTtl_{30};
    size_t maxEntries_;
    std::atomic<uint64_t> hits_{0};
    std::atomic<uint64_t> misses_{0};
};

} // namespace lethe

#endif // LETHE_NETWORK_DOH_CACHE_H
