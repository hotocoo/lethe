// test_http_perf.cc — Network-path performance optimizations, verified
//
// Covers the optimizations that matter for Aletheia workloads:
//   - HTTP keep-alive: repeat fetches ride ONE connection instead of paying
//     TCP (+TLS) setup per request; Connection: close still wins; a stale
//     idle connection is retried transparently exactly once.
//   - VPN policy re-check on REUSED connections: a kept-alive socket can
//     never become a plaintext path around the fail-closed tunnel policy.
//   - DoH answer cache: repeat hostnames resolve once within the TTL.
//   - LLM page/query caches: repeat reads avoid the network entirely while
//     browser navigation keeps fetching fresh documents.
//   - Result quality: entity-decoded titles, extracted snippets, navigation
//     noise filtered out.

#include "test_framework.h"
#include "llm/search_service.h"
#include "network/http_client.h"
#include "network/tls_config.h"
#include "network/vpn/vpn_tunnel.h"

#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace lethe;
using namespace lethe::llm;

namespace {

// Loopback HTTP server that supports persistent connections: each accepted
// socket serves as many requests as arrive, until the handler signals close
// or the peer disconnects. Counts both connections and handled requests.
class KeepAliveServer {
public:
    using Handler = std::function<std::string(const std::string& request)>;

    bool start() {
        listenFd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listenFd_ < 0) return false;
        int reuse = 1;
        ::setsockopt(listenFd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(0);
        if (::bind(listenFd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0 ||
            ::listen(listenFd_, 8) < 0) {
            ::close(listenFd_);
            listenFd_ = -1;
            return false;
        }
        socklen_t len = sizeof(addr);
        ::getsockname(listenFd_, reinterpret_cast<sockaddr*>(&addr), &len);
        port_ = ntohs(addr.sin_port);

        thread_ = std::thread([this]() { runLoop(); });
        return true;
    }

    ~KeepAliveServer() { stop(); }

    void stop() {
        running_.store(false);
        if (listenFd_ >= 0) {
            ::shutdown(listenFd_, SHUT_RDWR);
            ::close(listenFd_);
            listenFd_ = -1;
        }
        if (thread_.joinable()) thread_.join();
    }

    int port() const { return port_; }
    int connections() const { return connections_.load(); }
    int requests() const { return requests_.load(); }

    // When true, every served response ends the connection (simulates
    // servers that hang up immediately - the stale-keep-alive case).
    bool closeAfterEachResponse = false;

    Handler handler_;

private:
    void runLoop() {
        while (running_.load()) {
            int fd = ::accept(listenFd_, nullptr, nullptr);
            if (fd < 0) continue;

            // Bounded receive timeout so stop() cannot strand this thread.
            timeval tv{};
            tv.tv_sec = 0;
            tv.tv_usec = 100 * 1000;
            ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

            connections_.fetch_add(1);

            bool serving = true;
            while (serving && running_.load()) {
                // Read one request head.
                std::string req;
                char buf[4096];
                while (req.find("\r\n\r\n") == std::string::npos) {
                    ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
                    if (n <= 0) { serving = false; break; } // EOF/error
                    req.append(buf, static_cast<size_t>(n));
                }
                if (!serving) break;

                requests_.fetch_add(1);
                const std::string resp = handler_ ? handler_(req) : std::string();
                size_t total = 0;
                while (total < resp.size()) {
                    ssize_t n = ::send(fd, resp.data() + total,
                                       resp.size() - total, 0);
                    if (n <= 0) { serving = false; break; }
                    total += static_cast<size_t>(n);
                }
                if (closeAfterEachResponse) serving = false;
            }
            ::close(fd);
        }
    }

    int listenFd_ = -1;
    int port_ = 0;
    std::atomic<bool> running_{true};
    std::atomic<int> connections_{0};
    std::atomic<int> requests_{0};
    std::thread thread_;
};

// A response that allows the connection to stay open (no close header).
std::string keepAliveResp(int status, const std::string& text,
                          const std::string& body) {
    return "HTTP/1.1 " + std::to_string(status) + " " + text +
           "\r\nContent-Length: " + std::to_string(body.size()) +
           "\r\n\r\n" + body;
}

std::string closeResp(int status, const std::string& text,
                      const std::string& body) {
    return "HTTP/1.1 " + std::to_string(status) + " " + text +
           "\r\nContent-Length: " + std::to_string(body.size()) +
           "\r\nConnection: close\r\n\r\n" + body;
}

HttpClient makePlainClient() {
    TLSConfig tls;
    tls.init_modern_tls_config(0x0304, 0x0305);
    HttpClient client;
    CHECK_TRUE(client.initialize(tls));
    return client;
}

HttpResponse get(HttpClient& client, const std::string& url) {
    HttpRequest req;
    req.url = url;
    return client.sendRequest(req);
}

// Single-shot loopback server (one request per connection), for DoH.
class SimpleServer {
public:
    using Handler = std::function<std::string(const std::string& request)>;
    Handler handler_;
    std::atomic<int> hits{0};

    bool start() {
        listenFd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listenFd_ < 0) return false;
        int reuse = 1;
        ::setsockopt(listenFd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(0);
        if (::bind(listenFd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0 ||
            ::listen(listenFd_, 16) < 0) {
            ::close(listenFd_);
            listenFd_ = -1;
            return false;
        }
        socklen_t len = sizeof(addr);
        ::getsockname(listenFd_, reinterpret_cast<sockaddr*>(&addr), &len);
        port_ = ntohs(addr.sin_port);
        thread_ = std::thread([this]() {
            while (running_.load()) {
                int fd = ::accept(listenFd_, nullptr, nullptr);
                if (fd < 0) continue;
                std::string req;
                char buf[8192];
                while (req.find("\r\n\r\n") == std::string::npos) {
                    ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
                    if (n <= 0) break;
                    req.append(buf, static_cast<size_t>(n));
                }
                hits.fetch_add(1);
                const std::string resp = handler_(req);
                ::send(fd, resp.data(), resp.size(), 0);
                ::shutdown(fd, SHUT_WR);
                ::close(fd);
            }
        });
        return true;
    }

    ~SimpleServer() {
        running_.store(false);
        if (listenFd_ >= 0) { ::shutdown(listenFd_, SHUT_RDWR); ::close(listenFd_); }
        if (thread_.joinable()) thread_.join();
    }

    int port() const { return port_; }

private:
    int listenFd_ = -1;
    int port_ = 0;
    std::atomic<bool> running_{true};
    std::thread thread_;
};

} // namespace

// --- HTTP keep-alive ---------------------------------------------------------

LETHE_TEST_CASE(KeepAlive_ReusesConnectionForRepeatFetches) {
    KeepAliveServer server;
    server.handler_ = [](const std::string& req) {
        const std::string path = req.substr(req.find(' ') + 1);
        if (path.rfind("/doc-", 0) == 0) {
            return keepAliveResp(200, "OK", "<html>payload</html>");
        }
        return keepAliveResp(404, "Not Found", "nope");
    };
    CHECK_TRUE(server.start());

    HttpClient client = makePlainClient();
    const std::string base = "http://127.0.0.1:" + std::to_string(server.port());

    for (int i = 0; i < 3; ++i) {
        HttpResponse r = get(client, base + "/doc-" + std::to_string(i));
        CHECK_TRUE(r.success);
        CHECK_EQ(r.statusCode, 200);
        std::string body(r.body.data(), r.body.size());
        CHECK_TRUE(body.find("payload") != std::string::npos);
    }

    // Three documents, ONE connection: TCP+TLS setup paid once, not three
    // times - this is exactly what repeat LLM page reads look like.
    CHECK_EQ(server.connections(), 1);
    CHECK_EQ(server.requests(), 3);
}

LETHE_TEST_CASE(KeepAlive_ConnectionCloseHeader_DisablesReuse) {
    KeepAliveServer server;
    server.handler_ = [](const std::string&) {
        return closeResp(200, "OK", "<html>closing</html>");
    };
    CHECK_TRUE(server.start());

    HttpClient client = makePlainClient();
    const std::string base = "http://127.0.0.1:" + std::to_string(server.port());
    CHECK_TRUE(get(client, base + "/one").success);
    CHECK_TRUE(get(client, base + "/two").success);

    // The server's explicit Connection: close must be honored: two requests,
    // two connections, no attempt to write into a dead socket.
    CHECK_EQ(server.connections(), 2);
    CHECK_EQ(server.requests(), 2);
}

LETHE_TEST_CASE(KeepAlive_StaleIdleConnection_RetriedTransparently) {
    KeepAliveServer server;
    server.closeAfterEachResponse = true; // hangs up after every response
    server.handler_ = [](const std::string&) {
        return keepAliveResp(200, "OK", "<html>fresh copy</html>");
    };
    CHECK_TRUE(server.start());

    HttpClient client = makePlainClient();
    const std::string base = "http://127.0.0.1:" + std::to_string(server.port());
    CHECK_TRUE(get(client, base + "/first").success);
    // Second request rides the now-stale socket: the write may succeed into
    // a dead peer but the read fails - the client must retry ONCE on a
    // fresh connection and hand back a clean success either way.
    HttpResponse r = get(client, base + "/second");
    CHECK_TRUE(r.success);
    std::string body(r.body.data(), r.body.size());
    CHECK_TRUE(body.find("fresh copy") != std::string::npos);
    CHECK_EQ(server.requests(), 2);
}

LETHE_TEST_CASE(KeepAlive_RedirectHops_StayOnSameConnection) {
    KeepAliveServer server;
    server.handler_ = [](const std::string& req) {
        const std::string path = req.substr(req.find(' ') + 1);
        if (path.rfind("/redir", 0) == 0) {
            // 302 WITHOUT Connection: close -> the hop itself stays reusable.
            return std::string("HTTP/1.1 302 Found\r\nLocation: /final\r\n"
                               "Content-Length: 0\r\n\r\n");
        }
        if (path.rfind("/final", 0) == 0) {
            return keepAliveResp(200, "OK", "<html>landed</html>");
        }
        return keepAliveResp(404, "Not Found", "nope");
    };
    CHECK_TRUE(server.start());

    HttpClient client = makePlainClient();
    HttpResponse r =
        get(client, "http://127.0.0.1:" + std::to_string(server.port()) + "/redir");
    CHECK_TRUE(r.success);
    CHECK_EQ(r.finalUrl,
             std::string("http://127.0.0.1:") + std::to_string(server.port()) + "/final");

    // Both redirect hops rode one connection.
    CHECK_EQ(server.connections(), 1);
    CHECK_EQ(server.requests(), 2);
}

// --- VPN policy vs. reused connections ---------------------------------------

LETHE_TEST_CASE(KeepAlive_TunnelDown_BlocksReusedConnectionFailClosed) {
    // In-process tunnel pair completes a WireGuard-style handshake so the
    // client tunnel is genuinely CONNECTED with full-tunnel CIDRs.
    auto serverPrivKey = [] {
        vpn::Key k{};
        CHECK_TRUE(vpn::generatePrivateKey(k));
        return k;
    }();

    auto clientTunnel = std::make_shared<vpn::VpnTunnel>();
    vpn::VpnConfig cfg;
    cfg.endpointHost = "127.0.0.1";
    cfg.endpointPort = 51820; // unused here: no relay configured
    CHECK_TRUE(vpn::derivePublicKey(serverPrivKey, cfg.serverPublicKey));
    cfg.allowedCidrs = {"0.0.0.0/0"};
    CHECK_TRUE(clientTunnel->configureClient(cfg));

    vpn::VpnTunnel serverTunnel;
    CHECK_TRUE(serverTunnel.configureServer(serverPrivKey));

    vpn::HandshakeMessage init, resp;
    CHECK_TRUE(clientTunnel->createHandshakeInit(init));
    CHECK_TRUE(serverTunnel.processHandshakeInit(init, resp));
    CHECK_TRUE(clientTunnel->processHandshakeResponse(resp));
    CHECK_TRUE(clientTunnel->isConnected());

    KeepAliveServer origin;
    origin.handler_ = [](const std::string& req) {
        const std::string path = req.substr(req.find(' ') + 1);
        if (path.rfind("/a", 0) == 0 || path.rfind("/b", 0) == 0) {
            return keepAliveResp(200, "OK", "<html>tunneled origin</html>");
        }
        return keepAliveResp(404, "Not Found", "nope");
    };
    CHECK_TRUE(origin.start());

    HttpClient client = makePlainClient();
    client.setVpnTunnel(clientTunnel);

    const std::string base = "http://127.0.0.1:" + std::to_string(origin.port());
    // Tunnel up: covered destination, no relay configured -> direct TCP is
    // the documented fallback. Two requests, one keep-alive connection.
    CHECK_TRUE(get(client, base + "/a").success);
    CHECK_TRUE(get(client, base + "/b").success);
    CHECK_EQ(origin.connections(), 1);

    // The session dies (what disable/teardown does): same engine, same
    // kept-alive socket, full-tunnel CIDRs still active.
    clientTunnel->wipeSecrets();
    CHECK_FALSE(clientTunnel->isConnected());

    const int hitsBefore = origin.requests();
    HttpResponse blocked = get(client, base + "/a");
    // FAIL CLOSED: the reusable connection must NOT bypass the tunnel
    // policy - no plaintext byte reaches the covered origin.
    CHECK_FALSE(blocked.success);
    CHECK_TRUE(blocked.error.find("Blocked") != std::string::npos);
    CHECK_EQ(origin.requests(), hitsBefore);
}

// --- DoH answer cache --------------------------------------------------------

LETHE_TEST_CASE(Doh_AnswerCache_ServesRepeatHostnamesWithoutProviderRoundTrip) {
    SimpleServer server;
    std::atomic<int> dohQueries{0};
    server.handler_ = [&dohQueries](const std::string& req) {
        if (req.find("/dns-query?name=") != std::string::npos) {
            dohQueries.fetch_add(1);
            return closeResp(200, "OK",
                "{\"Status\":0,\"Answer\":[{\"name\":\"cache.internal\","
                "\"type\":1,\"data\":\"127.0.0.1\"}]}");
        }
        return closeResp(200, "OK", "<html>doh-cached-origin</html>");
    };
    CHECK_TRUE(server.start());

    HttpClient client = makePlainClient();
    client.setDohProvider(
        "http://127.0.0.1:" + std::to_string(server.port()) + "/dns-query");

    const std::string url =
        "http://cache.internal:" + std::to_string(server.port()) + "/x";
    CHECK_TRUE(get(client, url).success);
    CHECK_TRUE(get(client, url).success);
    CHECK_TRUE(get(client, url).success);

    // Three origin fetches, ONE DoH lookup: repeats resolve from the cache.
    CHECK_EQ(dohQueries.load(), 1);
}

LETHE_TEST_CASE(Doh_AnswerCache_TtlExpiryAndDisable) {
    SimpleServer server;
    std::atomic<int> dohQueries{0};
    server.handler_ = [&dohQueries](const std::string& req) {
        if (req.find("/dns-query?name=") != std::string::npos) {
            dohQueries.fetch_add(1);
            return closeResp(200, "OK",
                "{\"Status\":0,\"Answer\":[{\"name\":\"cache.internal\","
                "\"type\":1,\"data\":\"127.0.0.1\"}]}");
        }
        return closeResp(200, "OK", "<html>x</html>");
    };
    CHECK_TRUE(server.start());

    const std::string provider =
        "http://127.0.0.1:" + std::to_string(server.port()) + "/dns-query";
    const std::string url =
        "http://cache.internal:" + std::to_string(server.port()) + "/x";

    // Expiry: after the TTL lapses the provider is consulted again.
    HttpClient client = makePlainClient();
    client.setDohProvider(provider);
    client.setDohCacheTtl(std::chrono::seconds(1));
    CHECK_TRUE(get(client, url).success);
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    CHECK_TRUE(get(client, url).success);
    CHECK_EQ(dohQueries.load(), 2);

    // Disable: ttl 0 means every request resolves through the provider.
    HttpClient nocache = makePlainClient();
    nocache.setDohProvider(provider);
    nocache.setDohCacheTtl(std::chrono::seconds(0));
    CHECK_TRUE(get(nocache, url).success);
    CHECK_TRUE(get(nocache, url).success);
    CHECK_EQ(dohQueries.load(), 4);

    // Provider changes invalidate whatever the old provider answered.
    HttpClient swapped = makePlainClient();
    swapped.setDohProvider(provider);
    CHECK_TRUE(get(swapped, url).success);
    CHECK_EQ(dohQueries.load(), 5);
    swapped.setDohProvider(provider); // reconfigure -> cache dropped
    CHECK_TRUE(get(swapped, url).success);
    CHECK_EQ(dohQueries.load(), 6);
}

// --- LLM page/query caches ---------------------------------------------------

namespace {

struct CachedSearchFixture {
    KeepAliveServer server;
    HttpClient client;
    SearchService service;
    SearchConfig config;
    std::atomic<int> originHits{0};

    bool start(int maxCachedPages, int maxCachedSearches) {
        server.handler_ = [this](const std::string& req) {
            const size_t sp = req.find(' ');
            std::string path = req.substr(sp + 1);
            const size_t end = path.find(' ');
            if (end != std::string::npos) path.resize(end);
            if (path.rfind("/search", 0) == 0) {
                return keepAliveResp(200, "OK", kResultsHtml);
            }
            originHits.fetch_add(1);
            return keepAliveResp(200, "OK",
                "<html><head><title>Doc</title></head>"
                "<body><p>content of " + path + "</p></body></html>");
        };
        if (!server.start()) return false;

        TLSConfig tls;
        tls.init_modern_tls_config(0x0304, 0x0305);
        if (!client.initialize(tls)) return false;

        // IP-literal engine URL: no DoH involved, hits are exact.
        config.searchEngineUrl =
            "http://127.0.0.1:" + std::to_string(server.port());
        config.cachePages = true;
        config.maxCachedPages = maxCachedPages;
        config.cacheSearches = true;
        config.maxCachedSearches = maxCachedSearches;
        return service.initialize(&client, nullptr, config);
    }

    std::string url(const std::string& path) const {
        return "http://127.0.0.1:" + std::to_string(server.port()) + path;
    }

    static constexpr const char* kResultsHtml =
        "<html><head><title>S</title></head><body>"
        "<a href=\"http://one.example/a\">Result A</a>"
        "</body></html>";
};

} // namespace

LETHE_TEST_CASE(LlmCache_PageCache_ServesRepeatReadsWithoutNetwork) {
    CachedSearchFixture fx;
    CHECK_TRUE(fx.start(/*maxCachedPages=*/8, /*maxCachedSearches=*/8));

    auto first = fx.service.readPage(fx.url("/doc-1"));
    CHECK_TRUE(first.success);
    CHECK_FALSE(first.fromCache);
    CHECK_EQ(fx.originHits.load(), 1);

    auto second = fx.service.readPage(fx.url("/doc-1"));
    CHECK_TRUE(second.success);
    CHECK_TRUE(second.fromCache);          // no network at all
    CHECK_EQ(fx.originHits.load(), 1);     // origin untouched
    CHECK_EQ(second.textContent, first.textContent);

    // Browser navigation bypasses the cache BY DESIGN: every document load
    // is a real, policy-checked fetch through the secure stack.
    auto fresh = fx.service.readPageFresh(fx.url("/doc-1"));
    CHECK_TRUE(fresh.success);
    CHECK_FALSE(fresh.fromCache);
    CHECK_EQ(fx.originHits.load(), 2);

    // clearCaches drops everything.
    fx.service.clearCaches();
    CHECK_EQ(fx.service.pageCacheSize(), 0u);
    auto afterClear = fx.service.readPage(fx.url("/doc-1"));
    CHECK_TRUE(afterClear.success);
    CHECK_FALSE(afterClear.fromCache);
    CHECK_EQ(fx.originHits.load(), 3);
}

LETHE_TEST_CASE(LlmCache_PageCache_LruBoundEvictsColdestEntry) {
    CachedSearchFixture fx;
    CHECK_TRUE(fx.start(/*maxCachedPages=*/2, /*maxCachedSearches=*/8));

    (void)fx.service.readPage(fx.url("/p1"));
    (void)fx.service.readPage(fx.url("/p2"));
    CHECK_EQ(fx.service.pageCacheSize(), 2u);

    // Touch p1 so p2 becomes the coldest entry...
    (void)fx.service.readPage(fx.url("/p1"));
    // ...then insert p3: p2 must be evicted, p1 must survive.
    (void)fx.service.readPage(fx.url("/p3"));
    CHECK_EQ(fx.service.pageCacheSize(), 2u);

    const int hitsAfterFill = fx.originHits.load();
    auto p1again = fx.service.readPage(fx.url("/p1"));
    CHECK_TRUE(p1again.fromCache);                    // LRU kept it
    auto p2again = fx.service.readPage(fx.url("/p2"));
    CHECK_FALSE(p2again.fromCache);                   // evicted -> refetch
    CHECK_EQ(fx.originHits.load(), hitsAfterFill + 1);
}

LETHE_TEST_CASE(LlmCache_SearchCache_MemoizesIdenticalQueriesOnly) {
    CachedSearchFixture fx;
    CHECK_TRUE(fx.start(/*maxCachedPages=*/8, /*maxCachedSearches=*/8));

    auto r1 = fx.service.webSearch("quantum breakthrough");
    CHECK_EQ(r1.size(), 1u);
    const int engineRequestsAfterFirst = fx.server.requests();
    auto r2 = fx.service.webSearch("quantum breakthrough");
    CHECK_EQ(r2.size(), 1u);
    CHECK_EQ(fx.server.requests(), engineRequestsAfterFirst); // from cache

    // A different query is a different key: real engine fetch.
    auto r3 = fx.service.webSearch("different query");
    CHECK_EQ(r3.size(), 1u);
    CHECK_TRUE(fx.server.requests() > engineRequestsAfterFirst);
}

// --- Result quality ----------------------------------------------------------

// Expose parseSearchResults for focused parser tests via a tiny subclass.
class TestableSearchService : public SearchService {
public:
    std::vector<SearchResult> parse(const std::string& html) {
        return parseSearchResults(html);
    }
};

LETHE_TEST_CASE(LlmParse_EntityTitles_Snippets_AndNavFiltering) {
    TestableSearchService service;
    SearchConfig cfg;
    cfg.searchEngineUrl = "https://engine.example"; // nav links -> excluded
    HttpClient client;
    TLSConfig tls;
    tls.init_modern_tls_config(0x0304, 0x0305);
    CHECK_TRUE(client.initialize(tls));
    CHECK_TRUE(service.initialize(&client, nullptr, cfg));

    // Realistic result markup: entity-encoded titles with nested tags,
    // snippets after each anchor, a nav link, an empty footer anchor,
    // and a duplicate URL.
    const std::string html =
        "<html><head><title>S</title></head><body>"
        "<nav><a href=\"https://engine.example/settings\">Settings</a></nav>"
        "<div class='result'>"
        "<a href=\"https://one.example/a\">R&amp;D in <b>quantum</b> computing</a>"
        "<span>Breakthroughs &amp; caveats explained.</span>"
        "</div>"
        "<div class='result'>"
        "<a href=\"https://two.example/b\">Second result</a>"
        "<span>Snippet two.</span>"
        "</div>"
        "<div class='result'>"
        "<a href=\"https://one.example/a\">Duplicate of the first URL</a>"
        "<span>Dupe snippet.</span>"
        "</div>"
        "<footer><a href=\"https://engine.example/about\"></a></footer>"
        "</body></html>";

    auto results = service.parse(html);

    // The nav anchor ("Settings") and empty footer anchor are excluded as
    // noise; the duplicate URL collapses into the first entry.
    CHECK_EQ(results.size(), 2u);

    CHECK_EQ(results[0].url, std::string("https://one.example/a"));
    CHECK_EQ(results[0].title, std::string("R&D in quantum computing"));
    CHECK_TRUE(results[0].snippet.find("Breakthroughs & caveats") !=
               std::string::npos);
    CHECK_EQ(results[1].url, std::string("https://two.example/b"));
    CHECK_GE(results[0].relevanceScore, results[1].relevanceScore);
}
