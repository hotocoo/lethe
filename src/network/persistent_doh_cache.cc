#include "network/persistent_doh_cache.h"

#include <algorithm>
#include <iostream>
#include <sstream>

namespace lethe {

PersistentDohCache::PersistentDohCache(const std::string& filePath)
    : filePath_(filePath) {
    load();
}

PersistentDohCache::~PersistentDohCache() {
    if (getenv("LETHE_DEBUG")) {
        std::cout << "[lethe-doh-cache] Saving " << size() << " entries to " << filePath_ << std::endl;
    }
    save();
}

void PersistentDohCache::store(const std::string& host, const std::string& ip) {
    std::lock_guard<std::mutex> lock(mu_);

    // Bound the cache: drop expired entries first; if a pathological burst
    // still exceeds the cap, start over rather than grow without limit.
    if (cache_.size() >= kMaxEntries) {
        const auto now = std::chrono::steady_clock::now();
        for (auto it = cache_.begin(); it != cache_.end();) {
            if (now >= it->second.expires) it = cache_.erase(it);
            else ++it;
        }
        if (cache_.size() >= kMaxEntries) cache_.clear();
    }

    cache_[host] = Entry{ip, std::chrono::steady_clock::now() + kTtl};
}

bool PersistentDohCache::lookup(const std::string& host, std::string& outIp) const {
    std::lock_guard<std::mutex> lock(mu_);

    const auto now = std::chrono::steady_clock::now();
    auto it = cache_.find(host);
    if (it == cache_.end()) return false;
    if (now >= it->second.expires) return false;

    outIp = it->second.ip;
    return true;
}

void PersistentDohCache::save() const {
    std::lock_guard<std::mutex> lock(mu_);

    std::ofstream out(filePath_);
    if (!out.is_open()) return;

    const auto now = std::chrono::steady_clock::now();
    for (const auto& [host, entry] : cache_) {
        if (now >= entry.expires) continue; // Skip expired entries
        const auto remainingMs =
            std::chrono::duration_cast<std::chrono::milliseconds>(
                entry.expires - now)
                .count();
        out << host << " " << entry.ip << " " << remainingMs << "\n";
    }
}

void PersistentDohCache::load() {
    std::lock_guard<std::mutex> lock(mu_);

    std::ifstream in(filePath_);
    if (!in.is_open()) return;

    std::string line;
    const auto now = std::chrono::steady_clock::now();
    while (std::getline(in, line)) {
        std::istringstream iss(line);
        std::string host, ip;
        long long remainingMs;
        if (!(iss >> host >> ip >> remainingMs)) continue;

        if (remainingMs <= 0) continue; // Skip expired entries

        cache_[host] = Entry{ip, now + std::chrono::milliseconds(remainingMs)};
    }
}

void PersistentDohCache::clear() {
    std::lock_guard<std::mutex> lock(mu_);
    cache_.clear();
}

size_t PersistentDohCache::size() const {
    std::lock_guard<std::mutex> lock(mu_);
    return cache_.size();
}

} // namespace lethe
