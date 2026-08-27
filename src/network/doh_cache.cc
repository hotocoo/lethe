// doh_cache.cc - process-wide DoH answer cache (see doh_cache.h)

#include "network/doh_cache.h"

namespace lethe {

bool SharedDohCache::lookup(const std::string& provider, const std::string& host,
                            std::string& outIp) {
    if (ttl_.count() <= 0) return false;
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(mu_);
    auto it = entries_.find(key(provider, host));
    if (it == entries_.end()) { stats_.misses++; return false; }
    if (now >= it->second.expires) {
        entries_.erase(it);
        stats_.misses++;
        return false;
    }
    stats_.hits++;
    outIp = it->second.ip;
    return true;
}

void SharedDohCache::store(const std::string& provider, const std::string& host,
                           const std::string& ip) {
    if (ttl_.count() <= 0 || ip.empty()) return;
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(mu_);
    if (entries_.size() >= maxEntries_) {
        evictExpiredLocked(now);
        // A burst that still exceeds the cap starts over rather than
        // growing without bound; correctness never depends on the cache.
        if (entries_.size() >= maxEntries_) entries_.clear();
    }
    entries_[key(provider, host)] = Entry{ip, now + ttl_};
}

bool SharedDohCache::lookupBootstrap(const std::string& provider,
                                     std::vector<std::string>& outIps) {
    if (ttl_.count() <= 0) return false;
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(mu_);
    auto it = bootstrap_.find(provider);
    if (it == bootstrap_.end()) return false;
    if (now >= it->second.expires || it->second.ips.empty()) {
        bootstrap_.erase(it);
        return false;
    }
    outIps = it->second.ips;
    return true;
}

void SharedDohCache::storeBootstrap(const std::string& provider,
                                    const std::vector<std::string>& ips) {
    if (ttl_.count() <= 0 || ips.empty()) return;
    std::lock_guard<std::mutex> lock(mu_);
    bootstrap_[provider] = Bootstrap{ips, std::chrono::steady_clock::now() + ttl_};
}

void SharedDohCache::clear() {
    std::lock_guard<std::mutex> lock(mu_);
    entries_.clear();
    bootstrap_.clear();
}

size_t SharedDohCache::size() const {
    std::lock_guard<std::mutex> lock(mu_);
    return entries_.size();
}

SharedDohCache::Stats SharedDohCache::stats() const {
    std::lock_guard<std::mutex> lock(mu_);
    return stats_;
}

void SharedDohCache::evictExpiredLocked(std::chrono::steady_clock::time_point now) {
    for (auto it = entries_.begin(); it != entries_.end();) {
        if (now >= it->second.expires) it = entries_.erase(it);
        else ++it;
    }
}

} // namespace lethe
