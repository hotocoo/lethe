#ifndef LETHE_NETWORK_PERSISTENT_DOH_CACHE_H
#define LETHE_NETWORK_PERSISTENT_DOH_CACHE_H

#include <chrono>
#include <fstream>
#include <map>
#include <mutex>
#include <string>

namespace lethe {

// PersistentDohCache - DNS cache that persists across browser restarts.
//
// This cache stores DNS resolution results in a file on disk, allowing
// the browser to avoid DoH queries for previously resolved domains.
// This significantly reduces the latency for repeat visits to the same
// domains.
//
// The cache is keyed by the domain name and stores the IP address along
// with a timestamp. Entries expire after a configurable TTL (default:
// 5 minutes).
//
// Thread-safe: all public methods are protected by a mutex.
class PersistentDohCache {
public:
    // Constructor: loads the cache from the specified file path.
    // If the file doesn't exist, an empty cache is created.
    explicit PersistentDohCache(const std::string& filePath);

    // Destructor: saves the cache to disk.
    ~PersistentDohCache();

    // Store a DNS resolution result in the cache.
    void store(const std::string& host, const std::string& ip);

    // Lookup a DNS resolution result from the cache.
    // Returns true if found and not expired, false otherwise.
    bool lookup(const std::string& host, std::string& outIp) const;

    // Save the cache to disk.
    void save() const;

    // Load the cache from disk.
    void load();

    // Clear all entries from the cache.
    void clear();

    // Get the number of entries in the cache.
    size_t size() const;

private:
    struct Entry {
        std::string ip;
        std::chrono::steady_clock::time_point expires;
    };

    std::string filePath_;
    mutable std::mutex mu_;
    std::map<std::string, Entry> cache_;

    // TTL for cache entries (5 minutes by default).
    static constexpr std::chrono::minutes kTtl{5};

    // Maximum number of entries in the cache.
    static constexpr size_t kMaxEntries{1000};
};

} // namespace lethe

#endif // LETHE_NETWORK_PERSISTENT_DOH_CACHE_H
