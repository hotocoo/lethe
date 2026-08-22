// test_e2e_stack.cc — Full-stack end-to-end verification
//
// Exercises the complete privacy pipeline exactly as the Aletheia OS uses
// it: Bridge -> LLM search -> engine HttpClient -> DoH resolution ->
// VPN fail-closed policy -> origin fetch over loopback.
//
//   1. LLM search resolves its engine hostname via DoH and reaches a mock
//      origin that has no real DNS record.
//   2. With a full-tunnel VPN configured but DOWN, the same search is
//      blocked even though the origin is reachable - no plaintext leak.
//   3. With the VPN connected to a live reference server, the search
//      succeeds and the server registers the client.

#include "test_framework.h"
#include "test_tls_helpers.h"
#include "aletheia/aletheia_bridge.h"
#include "core/engine.h"
#include "llm/search_service.h"
#include "network/vpn/vpn_server.h"

#include <arpa/inet.h>
#include <atomic>
#include <cstring>
#include <functional>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace lethe;
using namespace lethe::vpn;

namespace {

// Loopback HTTP server playing DoH provider / search engine / origin roles.
class MockHttpServer {
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
                const std::string resp = handler_(req);
                ::send(fd, resp.data(), resp.size(), 0);
                ::shutdown(fd, SHUT_WR);
                ::close(fd);
            }
        });
        return true;
    }

    ~MockHttpServer() {
        running_ = false;
        if (listenFd_ >= 0) {
            ::shutdown(listenFd_, SHUT_RDWR);
            ::close(listenFd_);
        }
        if (thread_.joinable()) thread_.join();
    }

    int port() const { return port_; }
    Handler handler_;

private:
    int listenFd_ = -1;
    int port_ = 0;
    std::atomic<bool> running_{true};
    std::thread thread_;
};

std::string httpResp(int status, const std::string& text, const std::string& body) {
    return "HTTP/1.1 " + std::to_string(status) + " " + text +
           "\r\nContent-Length: " + std::to_string(body.size()) +
           "\r\nConnection: close\r\n\r\n" + body;
}

// Live reference VPN server with a background event loop.
class LiveVpnServer {
public:
    LiveVpnServer() {
        Key priv{};
        CHECK_TRUE(generatePrivateKey(priv));
        CHECK_TRUE(server_.configure(priv));
        CHECK_TRUE(server_.start("127.0.0.1", 0));
        thread_ = std::thread([this]() {
            while (running_.load()) {
                server_.process(std::chrono::milliseconds(20));
            }
        });
    }
    ~LiveVpnServer() {
        running_ = false;
        if (thread_.joinable()) thread_.join();
        server_.stop();
    }

    VpnConfig clientConfig() const {
        VpnConfig cfg;
        cfg.endpointHost = "127.0.0.1";
        cfg.endpointPort = server_.port();
        cfg.serverPublicKey = server_.publicKey();
        cfg.allowedCidrs = {"0.0.0.0/0"};
        return cfg;
    }

    size_t clientCount() const { return server_.clientCount(); }
    size_t relayedRequests() const { return server_.relayedRequests(); }
    void setRelayEnabled(bool enabled) { server_.setRelayEnabled(enabled); }

private:
    VpnServer server_;
    std::atomic<bool> running_{true};
    std::thread thread_;
};

const char* kSearchResultsHtml =
    "<html><head><title>Mock Search</title></head><body>"
    "<a href=\"http://result-one.internal/doc1\">Result One</a>"
    "<a href=\"http://result-two.internal/doc2\">Result Two</a>"
    "</body></html>";

} // namespace

LETHE_TEST_CASE(E2E_LlmSearch_ThroughDohToOrigin) {
    // One mock serves both roles: DoH provider and search engine origin.
    MockHttpServer server;
    server.handler_ = [](const std::string& req) {
        if (req.find("/dns-query?name=") != std::string::npos) {
            return httpResp(200, "OK",
                "{\"Status\":0,\"Answer\":[{\"name\":\"search.internal\","
                "\"type\":1,\"data\":\"127.0.0.1\"}]}");
        }
        return httpResp(200, "OK", kSearchResultsHtml);
    };
    CHECK_TRUE(server.start());

    Config cfg;
    cfg.incognitoMode = true;
    cfg.dnsProvider = "http://127.0.0.1:" + std::to_string(server.port()) + "/dns-query";
    Engine engine;
    CHECK_EQ(engine.initialize(cfg), 0);

    llm::SearchConfig searchCfg;
    searchCfg.searchEngineUrl =
        "http://search.internal:" + std::to_string(server.port());
    aletheia::AletheiaBridge bridge(&engine, searchCfg);

    // The search hostname has NO real DNS record: success proves resolution
    // went through the mock DoH provider and reached the loopback origin.
    auto results = bridge.llmWebSearch("quantum computing");
    CHECK_EQ(results.size(), 2u);
    CHECK_EQ(results[0].url, "http://result-one.internal/doc1");
    CHECK_EQ(results[0].title, "Result One");

    engine.shutdown();
}

LETHE_TEST_CASE(E2E_FullTunnelDown_BlocksLlmSearch) {
    MockHttpServer server; // origin IS reachable - only the tunnel is missing
    server.handler_ = [](const std::string& req) {
        if (req.find("/dns-query?name=") != std::string::npos) {
            return httpResp(200, "OK",
                "{\"Status\":0,\"Answer\":[{\"name\":\"search.internal\","
                "\"type\":1,\"data\":\"127.0.0.1\"}]}");
        }
        return httpResp(200, "OK", kSearchResultsHtml);
    };
    CHECK_TRUE(server.start());

    Config cfg;
    cfg.incognitoMode = true;
    cfg.dnsProvider = "http://127.0.0.1:" + std::to_string(server.port()) + "/dns-query";
    Engine engine;
    CHECK_EQ(engine.initialize(cfg), 0);

    // Full-tunnel config pointed at a dead endpoint: configured but down.
    vpn::VpnConfig vpnCfg;
    vpnCfg.endpointHost = "127.0.0.1";
    vpnCfg.endpointPort = 1;
    vpn::Key priv{};
    CHECK_TRUE(vpn::generatePrivateKey(priv));
    CHECK_TRUE(vpn::derivePublicKey(priv, vpnCfg.serverPublicKey));
    vpnCfg.allowedCidrs = {"0.0.0.0/0"};
    CHECK_TRUE(engine.enableVpn(vpnCfg));
    CHECK_FALSE(engine.isVpnConnected());

    llm::SearchConfig searchCfg;
    searchCfg.searchEngineUrl =
        "http://search.internal:" + std::to_string(server.port());
    aletheia::AletheiaBridge bridge(&engine, searchCfg);

    // The resolved destination (127.0.0.1) matches the full-tunnel CIDR and
    // the tunnel is down: the search MUST be blocked, not leaked.
    auto results = bridge.llmWebSearch("sensitive query");
    CHECK_TRUE(results.empty());

    engine.shutdown();
}

LETHE_TEST_CASE(E2E_VpnConnected_AllowsLlmSearchAndRegistersClient) {
    MockHttpServer server;
    server.handler_ = [](const std::string& req) {
        if (req.find("/dns-query?name=") != std::string::npos) {
            return httpResp(200, "OK",
                "{\"Status\":0,\"Answer\":[{\"name\":\"search.internal\","
                "\"type\":1,\"data\":\"127.0.0.1\"}]}");
        }
        return httpResp(200, "OK", kSearchResultsHtml);
    };
    CHECK_TRUE(server.start());

    LiveVpnServer vpn;
    Config cfg;
    cfg.incognitoMode = true;
    cfg.dnsProvider = "http://127.0.0.1:" + std::to_string(server.port()) + "/dns-query";
    Engine engine;
    CHECK_EQ(engine.initialize(cfg), 0);

    CHECK_TRUE(engine.enableVpn(vpn.clientConfig()));
    CHECK_TRUE(engine.isVpnConnected());

    llm::SearchConfig searchCfg;
    searchCfg.searchEngineUrl =
        "http://search.internal:" + std::to_string(server.port());
    aletheia::AletheiaBridge bridge(&engine, searchCfg);

    auto results = bridge.llmWebSearch("quantum computing");
    CHECK_EQ(results.size(), 2u);

    // The live reference server must have registered this engine's tunnel.
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (vpn.clientCount() == 0 &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK_EQ(vpn.clientCount(), 1u);

    engine.shutdown();
}

// --- Browser-grade navigation e2e ------------------------------------------
//
// The OS bridge navigations are real page loads: openUrl/navigate fetch the
// document through the engine's secure stack (DoH + VPN fail-closed policy),
// publish the fetched title into tab state, cache the readable text, and
// record history only outside incognito.

const char* kDocHtml =
    "<html><head><title>Deep Document</title></head><body>"
    "<h1>Deep Reading</h1>"
    "<p>Readable &amp; clean paragraph.</p>"
    "<ul><li>first item</li><li>second item</li></ul>"
    "<script>tracker()</script>"
    "</body></html>";

// Mock serving DoH (doc.internal -> loopback) plus the origin document,
// counting hits so tests can prove exactly which requests happened.
// pathResponses maps a path prefix to a RAW full HTTP response (headers and
// body) served for that path; unmatched paths get the default document.
struct CountingMock {
    MockHttpServer server;
    std::atomic<int> originHits{0};
    std::atomic<int> dohHits{0};
    std::map<std::string, std::string> pathResponses;

    bool start() {
        server.handler_ = [this](const std::string& req) {
            if (req.find("/dns-query?name=") != std::string::npos) {
                dohHits++;
                return httpResp(200, "OK",
                    "{\"Status\":0,\"Answer\":[{\"name\":\"doc.internal\","
                    "\"type\":1,\"data\":\"127.0.0.1\"}]}");
            }
            originHits++;
            // Extract the request path from "GET <path> HTTP/1.1".
            std::string path;
            const size_t sp1 = req.find(' ');
            if (sp1 != std::string::npos) {
                const size_t sp2 = req.find(' ', sp1 + 1);
                if (sp2 != std::string::npos) {
                    path = req.substr(sp1 + 1, sp2 - sp1 - 1);
                }
            }
            for (const auto& [prefix, raw] : pathResponses) {
                if (path.rfind(prefix, 0) == 0) return raw;
            }
            return httpResp(200, "OK", kDocHtml);
        };
        return server.start();
    }
    int port() const { return server.port(); }
};

Config loopbackConfig(const CountingMock& mock, bool incognito) {
    Config cfg;
    cfg.incognitoMode = incognito;
    cfg.dnsProvider =
        "http://127.0.0.1:" + std::to_string(mock.port()) + "/dns-query";
    return cfg;
}

// Session history is PER TAB: tests inspect the active tab's own history.
NavigationHistory* activeTabHistory(Engine& engine) {
    const int tabId = engine.tabManager()->getActiveTab();
    return engine.tabManager()->history(tabId);
}

LETHE_TEST_CASE(E2E_BridgeOpenUrl_LoadsRendersAndCaches) {
    CountingMock mock;
    CHECK_TRUE(mock.start());

    Engine engine;
    CHECK_EQ(engine.initialize(loopbackConfig(mock, /*incognito=*/true)), 0);
    aletheia::AletheiaBridge bridge(&engine);

    const std::string url =
        "http://doc.internal:" + std::to_string(mock.port()) + "/";

    // Navigation fetches the document for real - the hostname has no DNS
    // record, so success itself proves the DoH + origin round trip.
    CHECK_TRUE(bridge.openUrl(url));
    CHECK_TRUE(bridge.currentPageLoaded());
    CHECK_TRUE(bridge.getStatus().pageLoaded);

    // Fetched title lands in tab state.
    CHECK_EQ(bridge.getCurrentTitle(), std::string("Deep Document"));
    CHECK_EQ(mock.originHits.load(), 1);
    CHECK_TRUE(mock.dohHits.load() >= 1);

    // Reader text is extracted and served from the loaded page without a
    // second fetch; scripts never reach the reader.
    const std::string content = bridge.getCurrentPageContent();
    CHECK_TRUE(content.find("Deep Reading") != std::string::npos);
    CHECK_TRUE(content.find("Readable & clean paragraph.") != std::string::npos);
    CHECK_TRUE(content.find("first item") != std::string::npos);
    CHECK_TRUE(content.find("tracker") == std::string::npos);
    CHECK_EQ(mock.originHits.load(), 1);

    // Repeated OS reads stay cached.
    (void)bridge.getCurrentPageContent();
    (void)bridge.getCurrentPageContent();
    CHECK_EQ(mock.originHits.load(), 1);

    engine.shutdown();
}

LETHE_TEST_CASE(E2E_BridgeNavigate_TunnelDownBlocks_ThenTunnelUpRecovers) {
    CountingMock mock; // origin IS reachable the whole time
    CHECK_TRUE(mock.start());

    LiveVpnServer vpn;
    Engine engine;
    CHECK_EQ(engine.initialize(loopbackConfig(mock, /*incognito=*/true)), 0);
    aletheia::AletheiaBridge bridge(&engine);

    // Full-tunnel config pointed at a dead endpoint: configured but down.
    vpn::VpnConfig downCfg;
    downCfg.endpointHost = "127.0.0.1";
    downCfg.endpointPort = 1;
    vpn::Key priv{};
    CHECK_TRUE(vpn::generatePrivateKey(priv));
    CHECK_TRUE(vpn::derivePublicKey(priv, downCfg.serverPublicKey));
    downCfg.allowedCidrs = {"0.0.0.0/0"};
    CHECK_TRUE(engine.enableVpn(downCfg));
    CHECK_FALSE(engine.isVpnConnected());

    const std::string url =
        "http://doc.internal:" + std::to_string(mock.port()) + "/";

    // The navigation intent is recorded, but the load is blocked: the
    // resolved destination matches the full-tunnel CIDR with the tunnel
    // down, so NOTHING reaches the origin - zero plaintext attempts.
    CHECK_TRUE(bridge.navigate(url));
    CHECK_FALSE(bridge.currentPageLoaded());
    CHECK_FALSE(bridge.getStatus().pageLoaded);
    CHECK_EQ(bridge.getCurrentTitle(), std::string("New Tab"));
    CHECK_TRUE(bridge.getCurrentPageContent().empty());
    CHECK_EQ(mock.originHits.load(), 0);

    // Bring the same engine's tunnel up against the live reference server:
    // the very next navigation loads through it and registers the client.
    CHECK_TRUE(engine.enableVpn(vpn.clientConfig()));
    CHECK_TRUE(engine.isVpnConnected());
    CHECK_TRUE(bridge.navigate(url));
    CHECK_TRUE(bridge.currentPageLoaded());
    CHECK_EQ(bridge.getCurrentTitle(), std::string("Deep Document"));
    CHECK_EQ(mock.originHits.load(), 1);
    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (vpn.clientCount() == 0 &&
           std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CHECK_EQ(vpn.clientCount(), 1u);

    engine.shutdown();
}

LETHE_TEST_CASE(E2E_BridgeNavigation_PersistentSessionRecordsHistory) {
    CountingMock mock;
    CHECK_TRUE(mock.start());

    Config cfg = loopbackConfig(mock, /*incognito=*/false);
    Engine engine;
    CHECK_EQ(engine.initialize(cfg), 0);
    aletheia::AletheiaBridge bridge(&engine);
    CHECK_TRUE(activeTabHistory(engine) != nullptr);

    const std::string urlA =
        "http://doc.internal:" + std::to_string(mock.port()) + "/a";
    const std::string urlB =
        "http://doc.internal:" + std::to_string(mock.port()) + "/b";

    CHECK_TRUE(bridge.openUrl(urlA));
    CHECK_TRUE(bridge.currentPageLoaded());
    CHECK_TRUE(bridge.navigate(urlB));
    CHECK_TRUE(bridge.currentPageLoaded());

    // Only successfully loaded visits are recorded, with fetched titles.
    auto* hist = activeTabHistory(engine);
    CHECK_EQ(hist->size(), 2u);
    CHECK_TRUE(hist->containsUrl(urlA));
    CHECK_TRUE(hist->containsUrl(urlB));
    CHECK_EQ(hist->entries()[0].url, urlA);
    CHECK_EQ(hist->entries()[0].title, std::string("Deep Document"));

    engine.shutdown();
}

LETHE_TEST_CASE(E2E_BridgeNavigation_RedirectUpdatesTabUrlAndHistory) {
    CountingMock mock;
    // /start answers with a RELATIVE redirect to /final (exercises the
    // client's Location resolution); /final serves the real document.
    mock.pathResponses["/start"] =
        "HTTP/1.1 301 Moved Permanently\r\n"
        "Location: /final\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n\r\n";
    mock.pathResponses["/final"] = httpResp(200, "OK",
        "<html><head><title>Final Document</title></head><body>"
        "<p>You arrived.</p></body></html>");
    CHECK_TRUE(mock.start());

    Engine engine;
    CHECK_EQ(engine.initialize(loopbackConfig(mock, /*incognito=*/false)), 0);
    aletheia::AletheiaBridge bridge(&engine);
    CHECK_TRUE(activeTabHistory(engine) != nullptr);

    const std::string baseUrl =
        "http://doc.internal:" + std::to_string(mock.port());
    const std::string startUrl = baseUrl + "/start";
    const std::string finalUrl = baseUrl + "/final";

    CHECK_TRUE(bridge.navigate(startUrl));
    CHECK_TRUE(bridge.currentPageLoaded());

    // The tab now addresses the redirect target, not the requested URL.
    CHECK_EQ(bridge.getCurrentUrl(), finalUrl);
    CHECK_EQ(bridge.getCurrentTitle(), std::string("Final Document"));
    CHECK_TRUE(bridge.getCurrentPageContent().find("You arrived.") !=
               std::string::npos);
    // Exactly two origin hits: the redirect and its target. Cached reads
    // of the final URL add nothing.
    CHECK_EQ(mock.originHits.load(), 2);
    (void)bridge.getCurrentPageContent();
    CHECK_EQ(mock.originHits.load(), 2);

    // History records the destination that was actually read.
    auto* hist = activeTabHistory(engine);
    CHECK_TRUE(hist->containsUrl(finalUrl));
    CHECK_FALSE(hist->containsUrl(startUrl));
    CHECK_EQ(hist->entries()[0].url, finalUrl);
    CHECK_EQ(hist->entries()[0].title, std::string("Final Document"));

    engine.shutdown();
}

LETHE_TEST_CASE(E2E_BridgeOpenUrl_MultiTabLoadsAreIndependent) {
    CountingMock mock;
    mock.pathResponses["/one"] = httpResp(200, "OK",
        "<html><head><title>First Document</title></head><body>"
        "<p>alpha content.</p></body></html>");
    mock.pathResponses["/two"] = httpResp(200, "OK",
        "<html><head><title>Second Document</title></head><body>"
        "<p>beta content.</p></body></html>");
    CHECK_TRUE(mock.start());

    Engine engine;
    CHECK_EQ(engine.initialize(loopbackConfig(mock, /*incognito=*/true)), 0);
    aletheia::AletheiaBridge bridge(&engine);

    const std::string baseUrl =
        "http://doc.internal:" + std::to_string(mock.port());

    CHECK_TRUE(bridge.openUrl(baseUrl + "/one"));
    CHECK_EQ(bridge.getCurrentTitle(), std::string("First Document"));
    const int firstTabId = bridge.getStatus().activeTabId;
    const size_t tabsBefore = bridge.getStatus().tabCount;

    CHECK_TRUE(bridge.openUrl(baseUrl + "/two", /*newTab=*/true));
    CHECK_EQ(bridge.getCurrentTitle(), std::string("Second Document"));
    CHECK_TRUE(bridge.getStatus().tabCount > tabsBefore);
    CHECK_TRUE(bridge.currentPageLoaded());

    // The OS switches back to the first tab: its URL, fetched title, and
    // cached reader text must all be intact - per-tab, no cross-talk.
    engine.tabManager()->setActiveTab(firstTabId);
    CHECK_EQ(bridge.getCurrentUrl(), baseUrl + "/one");
    CHECK_EQ(bridge.getCurrentTitle(), std::string("First Document"));
    CHECK_TRUE(bridge.currentPageLoaded());
    CHECK_TRUE(bridge.getCurrentPageContent().find("alpha content.") !=
               std::string::npos);
    CHECK_TRUE(bridge.getCurrentPageContent().find("beta content.") ==
               std::string::npos);

    // Exactly one origin fetch per load: the switch-back serves from that
    // tab's own cache, and repeated reads add nothing.
    CHECK_EQ(mock.originHits.load(), 2);
    (void)bridge.getCurrentPageContent();
    CHECK_EQ(mock.originHits.load(), 2);

    engine.shutdown();
}

LETHE_TEST_CASE(E2E_BridgeNavigation_BackForwardThroughFullStack) {
    CountingMock mock;
    for (const auto* doc : {"/a", "/b", "/c", "/d"}) {
        mock.pathResponses[doc] = httpResp(200, "OK",
            std::string("<html><head><title>") +
            (doc + 1) + " Document</title></head><body><p>Body of" +
            doc + ".</p></body></html>");
    }
    CHECK_TRUE(mock.start());

    Engine engine;
    CHECK_EQ(engine.initialize(loopbackConfig(mock, /*incognito=*/false)), 0);
    aletheia::AletheiaBridge bridge(&engine);

    const std::string base = "http://doc.internal:" + std::to_string(mock.port());
    const auto urlFor = [&](const char* p) { return base + p; };

    // Visit a -> b -> c: three recorded, cursor at c.
    CHECK_TRUE(bridge.openUrl(urlFor("/a")));
    CHECK_TRUE(bridge.navigate(urlFor("/b")));
    CHECK_TRUE(bridge.navigate(urlFor("/c")));
    CHECK_FALSE(bridge.canGoForward());
    CHECK_TRUE(bridge.canGoBack());

    // Back is a REAL refetch through DoH to the origin - not a memory jump.
    CHECK_TRUE(bridge.goBack());
    CHECK_EQ(bridge.getCurrentUrl(), urlFor("/b"));
    CHECK_EQ(bridge.getCurrentTitle(), std::string("b Document"));
    CHECK_TRUE(bridge.currentPageLoaded());
    CHECK_TRUE(bridge.getCurrentPageContent().find("Body of/b.") !=
               std::string::npos);
    CHECK_TRUE(bridge.canGoBack());
    CHECK_TRUE(bridge.canGoForward());

    CHECK_TRUE(bridge.goBack()); // at a
    CHECK_FALSE(bridge.canGoBack());
    CHECK_EQ(bridge.getCurrentTitle(), std::string("a Document"));
    CHECK_TRUE(bridge.goForward()); // at b
    CHECK_TRUE(bridge.goForward()); // at c
    CHECK_FALSE(bridge.canGoForward());
    CHECK_EQ(bridge.getCurrentTitle(), std::string("c Document"));

    // From the past (b), a fresh navigation truncates the forward branch.
    CHECK_TRUE(bridge.goBack());          // at b
    CHECK_TRUE(bridge.navigate(urlFor("/d")));
    CHECK_FALSE(bridge.canGoForward());
    auto* hist = activeTabHistory(engine);
    CHECK_EQ(hist->size(), 3u);
    CHECK_EQ(hist->entries()[0].url, urlFor("/a"));
    CHECK_EQ(hist->entries()[1].url, urlFor("/b"));
    CHECK_EQ(hist->entries()[2].url, urlFor("/d"));
    CHECK_FALSE(hist->containsUrl(urlFor("/c")));

    // Every load and every traversal was a real fetch: 3 visits + back +
    // back + fwd + fwd + back + fresh d = 9 origin requests exactly.
    CHECK_EQ(mock.originHits.load(), 9);

    engine.shutdown();
}

LETHE_TEST_CASE(E2E_BridgeNavigation_BackBlockedWhenTunnelDown_FailClosed) {
    CountingMock mock; // reachable origin throughout
    mock.pathResponses["/a"] = httpResp(200, "OK",
        "<html><head><title>Alpha</title></head><body><p>alpha body.</p>"
        "</body></html>");
    mock.pathResponses["/b"] = httpResp(200, "OK",
        "<html><head><title>Beta</title></head><body><p>beta body.</p>"
        "</body></html>");
    CHECK_TRUE(mock.start());

    LiveVpnServer vpn;
    Engine engine;
    CHECK_EQ(engine.initialize(loopbackConfig(mock, /*incognito=*/false)), 0);
    aletheia::AletheiaBridge bridge(&engine);

    const std::string base = "http://doc.internal:" + std::to_string(mock.port());

    // Tunnel up: two real visits recorded, cursor at b.
    CHECK_TRUE(engine.enableVpn(vpn.clientConfig()));
    CHECK_TRUE(bridge.navigate(base + "/a"));
    CHECK_TRUE(bridge.navigate(base + "/b"));
    CHECK_EQ(mock.originHits.load(), 2);

    // Drop the tunnel: same engine, dead endpoint under full-tunnel CIDRs.
    vpn::VpnConfig downCfg;
    downCfg.endpointHost = "127.0.0.1";
    downCfg.endpointPort = 1;
    vpn::Key priv{};
    CHECK_TRUE(vpn::generatePrivateKey(priv));
    CHECK_TRUE(vpn::derivePublicKey(priv, downCfg.serverPublicKey));
    downCfg.allowedCidrs = {"0.0.0.0/0"};
    CHECK_TRUE(engine.enableVpn(downCfg));
    CHECK_FALSE(engine.isVpnConnected());

    // Back would target /a through the full-tunnel policy with no tunnel:
    // the traversal FAILS CLOSED - no fetch, no cursor move, tab restored.
    const int hitsBefore = mock.originHits.load();
    CHECK_FALSE(bridge.goBack());
    CHECK_TRUE(bridge.canGoBack());                          // still able to,
    CHECK_EQ(activeTabHistory(engine)->current()->url, base + "/b"); // cursor not moved
    CHECK_EQ(bridge.getCurrentUrl(), base + "/b");
    CHECK_TRUE(bridge.currentPageLoaded());
    CHECK_TRUE(bridge.getCurrentPageContent().find("beta body.") !=
               std::string::npos); // per-tab cache still serves b safely
    CHECK_EQ(mock.originHits.load(), hitsBefore); // zero plaintext attempts

    // Reconnect the tunnel: the very same goBack now succeeds via a real,
    // policy-compliant fetch of /a.
    CHECK_TRUE(engine.enableVpn(vpn.clientConfig()));
    CHECK_TRUE(engine.isVpnConnected());
    CHECK_TRUE(bridge.goBack());
    CHECK_EQ(bridge.getCurrentTitle(), std::string("Alpha"));
    CHECK_EQ(activeTabHistory(engine)->current()->url, base + "/a");
    CHECK_TRUE(bridge.canGoForward());
    CHECK_EQ(mock.originHits.load(), hitsBefore + 1);

    engine.shutdown();
}

LETHE_TEST_CASE(E2E_BridgeNavigate_HttpTunneledThroughVpnRelay) {
    // The DoH mock answers resolution queries ONLY; the origin is a second
    // server that the HTTP client must never contact directly.
    CountingMock dohOnly;
    CHECK_TRUE(dohOnly.start());

    MockHttpServer origin;
    std::atomic<int> originHits{0};
    origin.handler_ = [&](const std::string&) {
        originHits.fetch_add(1);
        return httpResp(200, "OK",
            "<html><head><title>Tunneled Page</title></head><body>"
            "<p>carried through the tunnel</p></body></html>");
    };
    CHECK_TRUE(origin.start());

    LiveVpnServer vpn;
    Engine engine;
    CHECK_EQ(engine.initialize(loopbackConfig(dohOnly, /*incognito=*/true)), 0);
    aletheia::AletheiaBridge bridge(&engine);

    // Tunnel up: covered destinations are carried through the relay.
    CHECK_TRUE(engine.enableVpn(vpn.clientConfig()));
    CHECK_TRUE(engine.isVpnConnected());

    const std::string url =
        "http://doc.internal:" + std::to_string(origin.port()) + "/";
    CHECK_TRUE(bridge.navigate(url));
    CHECK_TRUE(bridge.currentPageLoaded());
    CHECK_EQ(bridge.getCurrentTitle(), std::string("Tunneled Page"));
    CHECK_TRUE(bridge.getCurrentPageContent().find(
                   "carried through the tunnel") != std::string::npos);

    // The bytes reached the origin EXACTLY once - through the relay - and
    // never as a direct client TCP connection.
    CHECK_EQ(originHits.load(), 1);
    CHECK_EQ(vpn.relayedRequests(), 1u);
    CHECK_EQ(dohOnly.originHits.load(), 0);
    CHECK_TRUE(dohOnly.dohHits.load() >= 1);

    // With the relay disabled on the server, the same navigation FAILS
    // CLOSED: no direct-TCP fallback, no origin contact, no page.
    vpn.setRelayEnabled(false);
    const std::string url2 =
        "http://doc.internal:" + std::to_string(origin.port()) + "/second";
    CHECK_TRUE(bridge.navigate(url2)); // navigation intent recorded...
    CHECK_FALSE(bridge.currentPageLoaded()); // ...but nothing loaded
    CHECK_TRUE(bridge.getCurrentPageContent().empty());
    CHECK_EQ(originHits.load(), 1);        // origin untouched
    CHECK_EQ(vpn.relayedRequests(), 1u);   // no new relay exchange

    engine.shutdown();
}

#ifdef HAVE_OPENSSL
LETHE_TEST_CASE(E2E_BridgeNavigate_HttpsTunneledThroughVpnRelay) {
    // The crown-jewel privacy path: a certificate-verified TLS 1.3
    // navigation carried INSIDE the encrypted tunnel. DoH resolves the
    // hostname, the relay carries the stream, and the engine's own CA
    // bundle validates the origin certificate - all at once.
    CountingMock dohOnly;
    CHECK_TRUE(dohOnly.start());

    std::string caPem, caKeyPem, srvCertPem, srvKeyPem;
    CHECK_TRUE(tls_test::generateTestCa(caPem, caKeyPem));
    CHECK_TRUE(tls_test::generateServerCert(caPem, caKeyPem, "doc.internal",
                                            srvCertPem, srvKeyPem));

    tls_test::LoopbackTlsServer origin;
    std::atomic<int> tlsHits{0};
    origin.setHandler([&](const std::string&) {
        tlsHits.fetch_add(1);
        return httpResp(200, "OK",
            "<html><head><title>Tunneled Secure Page</title></head><body>"
            "<p>TLS inside the tunnel</p></body></html>");
    });
    CHECK_TRUE(origin.start(srvCertPem, srvKeyPem));

    const std::string caFile = tls_test::writeTempFile("lethe_e2e_ca", caPem);
    CHECK_TRUE(!caFile.empty());

    LiveVpnServer vpn;
    Engine engine;
    Config cfg = loopbackConfig(dohOnly, /*incognito=*/true);
    cfg.caBundlePath = caFile;
    CHECK_EQ(engine.initialize(cfg), 0);
    aletheia::AletheiaBridge bridge(&engine);

    CHECK_TRUE(engine.enableVpn(vpn.clientConfig()));
    CHECK_TRUE(engine.isVpnConnected());

    const std::string url = "https://doc.internal:" +
                            std::to_string(origin.port()) + "/secure";
    CHECK_TRUE(bridge.navigate(url));
    CHECK_TRUE(bridge.currentPageLoaded());
    CHECK_EQ(bridge.getCurrentTitle(), std::string("Tunneled Secure Page"));
    CHECK_TRUE(bridge.getCurrentPageContent().find(
                   "TLS inside the tunnel") != std::string::npos);

    // One relayed stream; the plain-HTTP mock was never an origin; the TLS
    // origin saw exactly one handshake.
    CHECK_EQ(vpn.relayedRequests(), 1u);
    CHECK_EQ(tlsHits.load(), 1);
    CHECK_EQ(dohOnly.originHits.load(), 0);

    ::remove(caFile.c_str());
    engine.shutdown();
}
#endif

LETHE_TEST_CASE(E2E_BridgeNavigation_HistoryIsolatedAcrossTabs) {
    CountingMock mock;
    for (const auto* doc : {"/a", "/b", "/c"}) {
        mock.pathResponses[doc] = httpResp(200, "OK",
            std::string("<html><head><title>") + (doc + 1) +
            " Document</title></head><body><p>Body of" + doc +
            ".</p></body></html>");
    }
    CHECK_TRUE(mock.start());

    Engine engine;
    CHECK_EQ(engine.initialize(loopbackConfig(mock, /*incognito=*/false)), 0);
    aletheia::AletheiaBridge bridge(&engine);

    const std::string base = "http://doc.internal:" + std::to_string(mock.port());

    // Tab 1 builds its own path: a -> b.
    CHECK_TRUE(bridge.openUrl(base + "/a"));
    const int tab1 = bridge.getStatus().activeTabId;
    CHECK_TRUE(bridge.navigate(base + "/b"));
    CHECK_TRUE(bridge.canGoBack()); // tab1: a behind it

    // Tab 2 opens with a single visit: c.
    CHECK_TRUE(bridge.openUrl(base + "/c", /*newTab=*/true));
    const int tab2 = bridge.getStatus().activeTabId;
    CHECK_TRUE(tab2 != tab1);
    CHECK_FALSE(bridge.canGoBack()); // tab2 has no past of its own
    CHECK_FALSE(bridge.goBack());

    // Back in tab 1 must land on TAB 1's past (/a), never tab 2's (/c).
    engine.tabManager()->setActiveTab(tab1);
    CHECK_TRUE(bridge.canGoBack());
    CHECK_FALSE(bridge.canGoForward()); // tab1 sits at its own end: b
    CHECK_TRUE(bridge.goBack());
    CHECK_EQ(bridge.getCurrentUrl(), base + "/a");
    CHECK_EQ(bridge.getCurrentTitle(), std::string("a Document"));
    CHECK_TRUE(bridge.canGoForward()); // tab1's own b is ahead

    // Tab 2 was untouched by tab 1's traversal.
    engine.tabManager()->setActiveTab(tab2);
    CHECK_EQ(bridge.getCurrentUrl(), base + "/c");
    CHECK_EQ(bridge.getCurrentTitle(), std::string("c Document"));
    CHECK_FALSE(bridge.canGoBack());
    CHECK_FALSE(bridge.canGoForward());

    engine.shutdown();
}

#ifdef HAVE_OPENSSL
LETHE_TEST_CASE(E2E_BridgeNavigate_HttpsThroughEngineCaBundle) {
    // Plain-HTTP mock plays DoH only; the origin is a REAL TLS 1.3 server
    // whose certificate chains to a throwaway CA handed to the engine via
    // Config.caBundlePath - certificate verification stays fully on.
    CountingMock mock;
    CHECK_TRUE(mock.start());

    std::string caPem, caKeyPem, srvCertPem, srvKeyPem;
    CHECK_TRUE(tls_test::generateTestCa(caPem, caKeyPem));
    CHECK_TRUE(tls_test::generateServerCert(caPem, caKeyPem, "doc.internal",
                                            srvCertPem, srvKeyPem));

    tls_test::LoopbackTlsServer origin;
    origin.setHandler([](const std::string&) {
        return httpResp(200, "OK",
            "<html><head><title>Secure Document</title></head><body>"
            "<p>TLS all the way down.</p></body></html>");
    });
    CHECK_TRUE(origin.start(srvCertPem, srvKeyPem));

    const std::string caFile = tls_test::writeTempFile("lethe_e2e_ca", caPem);
    CHECK_TRUE(!caFile.empty());

    Engine engine;
    Config cfg = loopbackConfig(mock, /*incognito=*/true);
    cfg.caBundlePath = caFile;
    CHECK_EQ(engine.initialize(cfg), 0);
    aletheia::AletheiaBridge bridge(&engine);

    const std::string url = "https://doc.internal:" +
                            std::to_string(origin.port()) + "/secure";

    // The hostname has no DNS record and the CA is not in the system store:
    // success proves DoH resolution plus a certificate-verified TLS 1.3
    // navigation through the engine's own trust anchor.
    CHECK_TRUE(bridge.navigate(url));
    CHECK_TRUE(bridge.currentPageLoaded());
    CHECK_EQ(bridge.getCurrentTitle(), std::string("Secure Document"));
    CHECK_TRUE(bridge.getCurrentPageContent().find("TLS all the way down.") !=
               std::string::npos);

    // Nothing ever touched the plain-HTTP mock as an origin.
    CHECK_EQ(mock.originHits.load(), 0);
    CHECK_TRUE(mock.dohHits.load() >= 1);

    ::remove(caFile.c_str());
    engine.shutdown();
}
#endif

LETHE_TEST_CASE(E2E_BridgeNavigation_IncognitoRecordsNothing) {
    CountingMock mock;
    CHECK_TRUE(mock.start());

    Engine engine;
    CHECK_EQ(engine.initialize(loopbackConfig(mock, /*incognito=*/true)), 0);
    aletheia::AletheiaBridge bridge(&engine);
    CHECK_TRUE(activeTabHistory(engine) != nullptr);

    const std::string url =
        "http://doc.internal:" + std::to_string(mock.port()) + "/";
    CHECK_TRUE(bridge.openUrl(url));
    CHECK_TRUE(bridge.currentPageLoaded());

    // Incognito sessions load pages but leave no history behind - and
    // therefore have nowhere to go back to.
    CHECK_TRUE(activeTabHistory(engine)->empty());
    CHECK_FALSE(bridge.canGoBack());
    CHECK_FALSE(bridge.goBack());

    engine.shutdown();
}
