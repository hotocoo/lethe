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
    CHECK_TRUE(engine.history() != nullptr);

    const std::string urlA =
        "http://doc.internal:" + std::to_string(mock.port()) + "/a";
    const std::string urlB =
        "http://doc.internal:" + std::to_string(mock.port()) + "/b";

    CHECK_TRUE(bridge.openUrl(urlA));
    CHECK_TRUE(bridge.currentPageLoaded());
    CHECK_TRUE(bridge.navigate(urlB));
    CHECK_TRUE(bridge.currentPageLoaded());

    // Only successfully loaded visits are recorded, with fetched titles.
    CHECK_EQ(engine.history()->size(), 2u);
    CHECK_TRUE(engine.history()->containsUrl(urlA));
    CHECK_TRUE(engine.history()->containsUrl(urlB));
    CHECK_EQ(engine.history()->entries()[0].url, urlA);
    CHECK_EQ(engine.history()->entries()[0].title, std::string("Deep Document"));

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
    CHECK_TRUE(engine.history() != nullptr);

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
    CHECK_TRUE(engine.history()->containsUrl(finalUrl));
    CHECK_FALSE(engine.history()->containsUrl(startUrl));
    CHECK_EQ(engine.history()->entries()[0].url, finalUrl);
    CHECK_EQ(engine.history()->entries()[0].title,
             std::string("Final Document"));

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
    CHECK_TRUE(engine.history() != nullptr);

    const std::string url =
        "http://doc.internal:" + std::to_string(mock.port()) + "/";
    CHECK_TRUE(bridge.openUrl(url));
    CHECK_TRUE(bridge.currentPageLoaded());

    // Incognito sessions load pages but leave no history behind.
    CHECK_TRUE(engine.history()->empty());

    engine.shutdown();
}
