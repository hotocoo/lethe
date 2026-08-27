// test_doh_resolver.cc - shared keep-alive DoH resolver pool
//
// A mock DoH provider that serves MANY requests per TCP connection counts
// how often it was dialled. Through the pool, N queries from N different
// clients cost one connection; a stale connection is retried transparently.

#include "test_framework.h"

#include "network/doh_resolver.h"
#include "network/http_client.h"
#include "network/tls_config.h"

#include <arpa/inet.h>
#include <atomic>
#include <cstring>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace lethe;

namespace {

class KeepAliveDohServer {
public:
    std::atomic<int> connections{0};
    std::atomic<int> queries{0};
    std::atomic<bool> closeAfterEach{false};
    std::atomic<bool> answerEmpty{false};   // valid response, no A record

    bool start() {
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (::bind(fd_, reinterpret_cast<sockaddr*>(&a), sizeof(a)) || ::listen(fd_, 8)) return false;
        socklen_t l = sizeof(a);
        ::getsockname(fd_, reinterpret_cast<sockaddr*>(&a), &l);
        port_ = ntohs(a.sin_port);
        th_ = std::thread([this] {
            while (running_) {
                int c = ::accept(fd_, nullptr, nullptr);
                if (c < 0) break;
                connections++;
                std::thread([this, c] { serve(c); }).detach();
            }
        });
        return true;
    }
    int port() const { return port_; }
    ~KeepAliveDohServer() {
        running_ = false;
        if (fd_ >= 0) { ::shutdown(fd_, SHUT_RDWR); ::close(fd_); }
        if (th_.joinable()) th_.join();
    }

private:
    void serve(int c) {
        timeval tv{5, 0};
        ::setsockopt(c, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        std::string buf;
        char tmp[2048];
        for (;;) {
            size_t end;
            while ((end = buf.find("\r\n\r\n")) == std::string::npos) {
                ssize_t n = ::recv(c, tmp, sizeof(tmp), 0);
                if (n <= 0) { ::close(c); return; }
                buf.append(tmp, static_cast<size_t>(n));
            }
            const std::string req = buf.substr(0, end + 4);
            buf.erase(0, end + 4);
            queries++;
            // name=<host> -> answer 127.0.0.1 for everything
            const std::string body = answerEmpty
                ? "{\"Status\":3,\"Answer\":[]}"
                : "{\"Status\":0,\"Answer\":[{\"name\":\"x\",\"type\":1,\"data\":\"127.0.0.1\"}]}";
            const std::string resp =
                "HTTP/1.1 200 OK\r\nContent-Type: application/dns-json\r\nContent-Length: " +
                std::to_string(body.size()) + "\r\nConnection: " +
                (closeAfterEach ? "close" : "keep-alive") + "\r\n\r\n" + body;
            ::send(c, resp.data(), resp.size(), 0);
            if (closeAfterEach) { ::shutdown(c, SHUT_RDWR); ::close(c); return; }
        }
    }
    int fd_ = -1;
    int port_ = 0;
    std::atomic<bool> running_{true};
    std::thread th_;
};

std::unique_ptr<HttpClient> makeDohClient(const std::string& provider,
                                          std::shared_ptr<SharedDohCache> cache) {
    TLSConfig tls;
    tls.init_modern_tls_config(0x0304, 0x0305);
    auto c = std::make_unique<HttpClient>();
    c->initialize(tls);
    c->setDohProvider(provider);
    c->setSharedDohCache(cache);
    return c;
}

} // namespace

LETHE_TEST_CASE(DohResolver_PoolReusesOneProviderConnection) {
    KeepAliveDohServer srv;
    CHECK_TRUE(srv.start());
    const std::string provider = "http://127.0.0.1:" + std::to_string(srv.port()) + "/dns-query";
    auto cache = std::make_shared<SharedDohCache>();
    auto pool = std::make_shared<SharedDohResolver>(
        [&] { return makeDohClient(provider, cache); }, /*poolSize=*/1);
    CHECK_EQ(pool->poolSize(), 1u);

    // Three throwaway clients (the way the proxy mints them) resolve three
    // different hosts: three queries, ONE provider connection.
    for (const char* h : {"a.internal", "b.internal", "c.internal"}) {
        auto c = makeDohClient(provider, cache);
        c->setSharedDohResolver(pool);
        std::string ip;
        CHECK_TRUE(c->resolveDoh(h, ip));
        CHECK_EQ(ip, "127.0.0.1");
    }
    CHECK_EQ(srv.queries.load(), 3);
    CHECK_EQ(srv.connections.load(), 1);
    CHECK_EQ(pool->stats().queries, 3u);

    // A repeat host is a cache hit: no query, no connection.
    auto d = makeDohClient(provider, cache);
    d->setSharedDohResolver(pool);
    std::string ip;
    CHECK_TRUE(d->resolveDoh("a.internal", ip));
    CHECK_EQ(srv.queries.load(), 3);
    CHECK_EQ(cache->stats().hits, 1u);
}

LETHE_TEST_CASE(DohResolver_StaleKeepAliveIsRetriedFresh) {
    KeepAliveDohServer srv;
    CHECK_TRUE(srv.start());
    const std::string provider = "http://127.0.0.1:" + std::to_string(srv.port()) + "/dns-query";
    auto cache = std::make_shared<SharedDohCache>(std::chrono::seconds(0)); // no caching
    auto pool = std::make_shared<SharedDohResolver>(
        [&] { return makeDohClient(provider, cache); }, 1);

    std::string ip;
    CHECK_TRUE(pool->resolve("first.internal", ip));
    CHECK_EQ(srv.connections.load(), 1);

    // Provider now closes after every answer (server-side idle policy). The
    // pooled client's next write hits a dead socket: it must dial fresh and
    // still answer - never fail, never fall back to plaintext DNS.
    srv.closeAfterEach = true;
    CHECK_TRUE(pool->resolve("second.internal", ip));
    CHECK_TRUE(pool->resolve("third.internal", ip));
    CHECK_EQ(srv.queries.load(), 3);
    CHECK_GE(srv.connections.load(), 2);
}

LETHE_TEST_CASE(DohResolver_ConcurrentCallersShareThePool) {
    KeepAliveDohServer srv;
    CHECK_TRUE(srv.start());
    const std::string provider = "http://127.0.0.1:" + std::to_string(srv.port()) + "/dns-query";
    auto cache = std::make_shared<SharedDohCache>();
    auto pool = std::make_shared<SharedDohResolver>(
        [&] { return makeDohClient(provider, cache); }, 2);

    std::atomic<int> ok{0};
    std::vector<std::thread> ts;
    for (int i = 0; i < 16; i++) {
        ts.emplace_back([&, i] {
            std::string ip;
            if (pool->resolve("host" + std::to_string(i) + ".internal", ip) && ip == "127.0.0.1") ok++;
        });
    }
    for (auto& t : ts) t.join();
    CHECK_EQ(ok.load(), 16);
    CHECK_EQ(srv.queries.load(), 16);
    CHECK_TRUE(srv.connections.load() <= 2);   // never more than the pool size
    CHECK_EQ(pool->stats().queries, 16u);
}

LETHE_TEST_CASE(DohResolver_NegativeAnswerIsFinalAndCached) {
    KeepAliveDohServer srv;
    CHECK_TRUE(srv.start());
    srv.answerEmpty = true;
    const std::string provider = "http://127.0.0.1:" + std::to_string(srv.port()) + "/dns-query";
    auto cache = std::make_shared<SharedDohCache>();
    auto pool = std::make_shared<SharedDohResolver>(
        [&] { return makeDohClient(provider, cache); }, 1);

    // The engine retries a dead host several times: ONE provider query, one
    // connection, every retry answered from the negative cache, all fail
    // closed (no plaintext DNS, no address).
    for (int i = 0; i < 4; i++) {
        auto c = makeDohClient(provider, cache);
        c->setSharedDohResolver(pool);
        std::string ip = "unchanged";
        CHECK_TRUE(!c->resolveDoh("dead.internal", ip));
    }
    CHECK_EQ(srv.queries.load(), 1);
    CHECK_EQ(srv.connections.load(), 1);
    std::string ip;
    CHECK_TRUE(cache->lookup(provider, "dead.internal", ip));
    CHECK_EQ(ip, std::string());   // negative entry
    // The keep-alive connection survived the negative answer: a positive
    // lookup right after reuses it.
    srv.answerEmpty = false;
    CHECK_TRUE(pool->resolve("alive.internal", ip));
    CHECK_EQ(ip, "127.0.0.1");
    CHECK_EQ(srv.connections.load(), 1);
}
