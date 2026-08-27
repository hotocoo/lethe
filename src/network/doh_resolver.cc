// doh_resolver.cc - shared keep-alive DoH resolver pool (see header)

#include "network/doh_resolver.h"

namespace lethe {

SharedDohResolver::SharedDohResolver(ClientFactory makeClient, size_t poolSize)
    : poolSize_(poolSize == 0 ? 1 : poolSize) {
    for (size_t i = 0; i < poolSize_; i++) {
        auto c = makeClient();
        if (!c) continue;
        c->setDohKeepAlive(true);
        free_.push_back(std::move(c));
    }
    poolSize_ = free_.size();
}

SharedDohResolver::~SharedDohResolver() {
    std::lock_guard<std::mutex> lock(mu_);
    for (auto& c : free_) c->shutdown();
}

bool SharedDohResolver::resolve(const std::string& host, std::string& outIp) {
    std::unique_ptr<HttpClient> client;
    {
        std::unique_lock<std::mutex> lock(mu_);
        stats_.queries++;
        if (free_.empty()) {
            stats_.waits++;
            cv_.wait(lock, [this] { return !free_.empty() || poolSize_ == 0; });
            if (free_.empty()) return false;
        }
        client = std::move(free_.back());
        free_.pop_back();
    }
    const bool ok = client->resolveDoh(host, outIp);
    {
        std::lock_guard<std::mutex> lock(mu_);
        free_.push_back(std::move(client));
    }
    cv_.notify_one();
    return ok;
}

SharedDohResolver::Stats SharedDohResolver::stats() const {
    std::lock_guard<std::mutex> lock(const_cast<std::mutex&>(mu_));
    return stats_;
}

} // namespace lethe
