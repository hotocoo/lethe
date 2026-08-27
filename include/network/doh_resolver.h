#ifndef LETHE_NETWORK_DOH_RESOLVER_H
#define LETHE_NETWORK_DOH_RESOLVER_H

// doh_resolver.h - shared DNS-over-HTTPS resolver pool with keep-alive.
//
// Every HttpClient can resolve on its own, but a client that exists for one
// proxied connection pays TCP + TLS to the provider for every query. This
// pool owns a few dedicated clients that keep their provider connection
// open (dohKeepAlive), hands each query to a free one, and shares answers
// through the SharedDohCache. Thread-safe; callers block briefly when all
// pool members are busy. Fail-closed semantics are unchanged: a failure is
// reported, never worked around with plaintext DNS.

#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "network/http_client.h"

namespace lethe {

class SharedDohResolver {
public:
    using ClientFactory = std::function<std::unique_ptr<HttpClient>()>;

    // \p makeClient must return an initialized client with the DoH provider
    // set (and ideally the shared cache); the pool enables keep-alive on it.
    SharedDohResolver(ClientFactory makeClient, size_t poolSize = 4);
    ~SharedDohResolver();

    SharedDohResolver(const SharedDohResolver&) = delete;
    SharedDohResolver& operator=(const SharedDohResolver&) = delete;

    // Resolve \p host to an IPv4 literal through a pooled client.
    bool resolve(const std::string& host, std::string& outIp);

    struct Stats { uint64_t queries = 0; uint64_t waits = 0; };
    Stats stats() const;
    size_t poolSize() const { return poolSize_; }

private:
    std::mutex mu_;
    std::condition_variable cv_;
    std::vector<std::unique_ptr<HttpClient>> free_;
    size_t poolSize_;
    Stats stats_;
};

} // namespace lethe

#endif // LETHE_NETWORK_DOH_RESOLVER_H
