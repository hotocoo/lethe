// test_private_network.cc — Private-network (SSRF) isolation verification
//
// Unit layer: the IPv4/IPv6 scope classifier matrix (RFC1918, CGNAT,
// link-local incl. cloud-metadata endpoints, ULA, loopback, multicast,
// TEST-NET/benchmarking/reserved ranges) plus the embedded-IPv4 wrappers
// (IPv4-mapped ::ffff:/96, NAT64 64:ff9b::/96, 6to4 2002::/16) that recurse
// into the IPv4 classifier; guard decision semantics (default isolation,
// per-host allowlist, loopback toggle, master switch, fail-closed on
// unclassifiable addresses); canonicalization of the numeric IPv4
// spell-outs getaddrinfo dials but inet_pton refuses; env configuration.
//
// E2E layer: real loopback HTTP origins + a mock DoH provider prove the
// enforcement point sits AFTER resolution and BEFORE any socket dial:
//   - a named host whose DoH answer points into RFC1918 space is blocked
//     with zero origin hits while ordinary loopback navigation still works;
//   - a redirect chain aiming at private space dies on the private hop;
//   - the 169.254.169.254 metadata endpoint is refused by name;
//   - "http://2130706433/" cannot dodge the guard by spelling loopback in
//     decimal: with allowLoopback=false it is blocked exactly like
//     "http://127.0.0.1/" would be.

#include "test_framework.h"
#include "network/http_client.h"
#include "network/tls_config.h"
#include "security/private_network_guard.h"
#include "core/engine.h"

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace lethe;

namespace {

// Minimal loopback HTTP server doubling as mock DoH provider and origin.
class MiniHttpServer {
public:
    using Handler = std::function<std::string(const std::string& request)>;

    bool start() {
        listenFd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listenFd_ < 0) return false;
        int reuse = 1;
        ::setsockopt(listenFd_, SOL_SOCKET, SO_REUSEADDR, &reuse,
                     sizeof(reuse));
        sockaddr_in addr;
        std::memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(0);
        if (::bind(listenFd_, reinterpret_cast<sockaddr*>(&addr),
                   sizeof(addr)) < 0 ||
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
                const int fd = ::accept(listenFd_, nullptr, nullptr);
                if (fd < 0) continue;
                std::string req;
                char buf[8192];
                while (req.find("\r\n\r\n") == std::string::npos) {
                    const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
                    if (n <= 0) break;
                    req.append(buf, static_cast<size_t>(n));
                }
                if (req.find("/dns-query?name=") != std::string::npos) {
                    dohHits_.fetch_add(1);
                } else {
                    originHits_.fetch_add(1);
                }
                const std::string resp = handler_(req);
                if (!resp.empty()) {
                    ::send(fd, resp.data(), resp.size(), 0);
                }
                ::shutdown(fd, SHUT_WR);
                ::close(fd);
            }
        });
        return true;
    }

    ~MiniHttpServer() {
        running_ = false;
        if (listenFd_ >= 0) {
            ::shutdown(listenFd_, SHUT_RDWR);
            ::close(listenFd_);
        }
        if (thread_.joinable()) thread_.join();
    }

    int port() const { return port_; }
    int dohHits() const { return dohHits_.load(); }
    int originHits() const { return originHits_.load(); }
    Handler handler_;

private:
    int listenFd_ = -1;
    int port_ = 0;
    std::atomic<int> dohHits_{0};
    std::atomic<int> originHits_{0};
    std::atomic<bool> running_{true};
    std::thread thread_;
};

std::string plainResp(int status, const std::string& text,
                      const std::string& extraHeaders,
                      const std::string& body) {
    return "HTTP/1.1 " + std::to_string(status) + " " + text + "\r\n" +
           extraHeaders +
           "Content-Length: " + std::to_string(body.size()) +
           "\r\nConnection: close\r\n\r\n" + body;
}

std::string dohAnswerBody(const std::string& ip) {
    return "{\"Status\":0,\"Answer\":[{\"name\":\"query.\",\"type\":1,"
           "\"TTL\":300,\"data\":\"" + ip + "\"}]}";
}

// Query the mocked provider makes -> resolved address. Unknown names get
// an empty answer (the real client then fails closed).
std::string resolveMockName(const std::string& request) {
    const size_t eq = request.find("name=");
    if (eq == std::string::npos) return "";
    size_t end = eq + 5;
    while (end < request.size() && request[end] != '&' &&
           request[end] != ' ') {
        ++end;
    }
    const std::string name = request.substr(eq + 5, end - eq - 5);
    if (name == "site.test") return "127.0.0.1";
    if (name == "internal.example") return "10.0.0.7";
    if (name == "metadata.google.internal") return "169.254.169.254";
    return "";
}

HttpClient makePlainClient() {
    HttpClient client;
    TLSConfig tls;
    tls.init_modern_tls_config(0x0304, 0x0305);
    CHECK_TRUE(client.initialize(tls));
    return client;
}

} // namespace

// --- Classifier: IPv4 special-use ranges ------------------------------------

LETHE_TEST_CASE(PrivateNet_Classify_Ipv4Ranges) {
    CHECK_EQ(classifyAddress("8.8.8.8"), AddressScope::Public);
    CHECK_EQ(classifyAddress("9.255.255.255"), AddressScope::Public);
    CHECK_EQ(classifyAddress("11.0.0.1"), AddressScope::Public);

    CHECK_EQ(classifyAddress("10.0.0.0"), AddressScope::Private);
    CHECK_EQ(classifyAddress("10.255.255.255"), AddressScope::Private);

    CHECK_EQ(classifyAddress("100.63.255.255"), AddressScope::Public);
    CHECK_EQ(classifyAddress("100.64.0.0"), AddressScope::Shared);
    CHECK_EQ(classifyAddress("100.127.255.255"), AddressScope::Shared);
    CHECK_EQ(classifyAddress("100.128.0.0"), AddressScope::Public);

    CHECK_EQ(classifyAddress("126.255.255.255"), AddressScope::Public);
    CHECK_EQ(classifyAddress("127.0.0.0"), AddressScope::Loopback);
    CHECK_EQ(classifyAddress("127.255.255.254"), AddressScope::Loopback);
    CHECK_EQ(classifyAddress("128.0.0.1"), AddressScope::Public);

    CHECK_EQ(classifyAddress("169.253.1.1"), AddressScope::Public);
    CHECK_EQ(classifyAddress("169.254.0.0"), AddressScope::LinkLocal);
    CHECK_EQ(classifyAddress("169.254.169.254"), AddressScope::LinkLocal);
    CHECK_EQ(classifyAddress("169.255.1.1"), AddressScope::Public);

    CHECK_EQ(classifyAddress("172.15.255.255"), AddressScope::Public);
    CHECK_EQ(classifyAddress("172.16.0.0"), AddressScope::Private);
    CHECK_EQ(classifyAddress("172.31.255.255"), AddressScope::Private);
    CHECK_EQ(classifyAddress("172.32.0.0"), AddressScope::Public);

    CHECK_EQ(classifyAddress("192.167.1.1"), AddressScope::Public);
    CHECK_EQ(classifyAddress("192.168.0.0"), AddressScope::Private);
    CHECK_EQ(classifyAddress("192.168.255.255"), AddressScope::Private);
    CHECK_EQ(classifyAddress("192.169.0.0"), AddressScope::Public);

    CHECK_EQ(classifyAddress("192.0.0.1"), AddressScope::Reserved);
    CHECK_EQ(classifyAddress("192.0.2.9"), AddressScope::Reserved);
    CHECK_EQ(classifyAddress("198.18.0.1"), AddressScope::Reserved);
    CHECK_EQ(classifyAddress("198.19.255.255"), AddressScope::Reserved);
    CHECK_EQ(classifyAddress("198.20.0.1"), AddressScope::Public);
    CHECK_EQ(classifyAddress("203.0.113.99"), AddressScope::Reserved);

    CHECK_EQ(classifyAddress("223.255.255.255"), AddressScope::Public);
    CHECK_EQ(classifyAddress("224.0.0.1"), AddressScope::Multicast);
    CHECK_EQ(classifyAddress("239.255.255.255"), AddressScope::Multicast);
    CHECK_EQ(classifyAddress("240.0.0.0"), AddressScope::Reserved);
    CHECK_EQ(classifyAddress("255.255.255.255"), AddressScope::Reserved);
    CHECK_EQ(classifyAddress("0.0.0.0"), AddressScope::Reserved);
}

// --- Classifier: IPv6 forms incl. embedded IPv4 ------------------------------

LETHE_TEST_CASE(PrivateNet_Classify_Ipv6Forms) {
    CHECK_EQ(classifyAddress("::1"), AddressScope::Loopback);
    CHECK_EQ(classifyAddress("[::1]"), AddressScope::Loopback);
    CHECK_EQ(classifyAddress("::"), AddressScope::Unspecified);
    CHECK_EQ(classifyAddress("fe80::1"), AddressScope::LinkLocal);
    CHECK_EQ(classifyAddress("fd12:3456::1"), AddressScope::Private);
    CHECK_EQ(classifyAddress("fc00::1"), AddressScope::Private);
    CHECK_EQ(classifyAddress("ff02::1"), AddressScope::Multicast);
    CHECK_EQ(classifyAddress("2606:4700:4700::1111"), AddressScope::Public);

    // Embedded IPv4 wrappers must inherit the wrapped address's scope.
    CHECK_EQ(classifyAddress("::ffff:8.8.8.8"), AddressScope::Public);
    CHECK_EQ(classifyAddress("::ffff:10.0.0.5"), AddressScope::Private);
    CHECK_EQ(classifyAddress("::ffff:169.254.169.254"),
             AddressScope::LinkLocal);
    CHECK_EQ(classifyAddress("::ffff:127.0.0.1"), AddressScope::Loopback);
    CHECK_EQ(classifyAddress("::10.0.0.5"), AddressScope::Private);

    // NAT64 well-known prefix embeds raw IPv4 after 96 zero bits.
    CHECK_EQ(classifyAddress("64:ff9b::a00:1"), AddressScope::Private);
    CHECK_EQ(classifyAddress("64:ff9b::808:808"), AddressScope::Public);

    // 6to4 embeds the routed IPv4 endpoint in bits 16..47.
    CHECK_EQ(classifyAddress("2002:a00:1::"), AddressScope::Private);
    CHECK_EQ(classifyAddress("2002:808:808::"), AddressScope::Public);

    CHECK_EQ(classifyAddress("not-an-ip"), AddressScope::Invalid);
    CHECK_EQ(classifyAddress(""), AddressScope::Invalid);
}

// --- Guard decision semantics -------------------------------------------------

LETHE_TEST_CASE(PrivateNet_Guard_DecisionMatrix) {
    const PrivateNetworkGuard def; // defaults: isolated, loopback allowed
    CHECK_EQ(def.check("example.net", "8.8.8.8"), std::string(""));
    CHECK_EQ(def.check("localhost", "127.0.0.1"), std::string(""));
    CHECK_NE(def.check("a.internal", "10.1.2.3").find("private-network"),
             std::string::npos);
    CHECK_NE(def.check("metadata", "169.254.169.254").find("link-local"),
             std::string::npos);
    CHECK_FALSE(def.check("cgnat", "100.64.0.1").empty());
    CHECK_FALSE(def.check("ula", "fd00::1").empty());
    CHECK_FALSE(def.check("mcast", "224.0.0.1").empty());
    CHECK_FALSE(def.check("reserved", "192.0.2.1").empty());
    CHECK_FALSE(def.check("unspec", "::").empty());
    // Unclassifiable destination strings fail closed.
    CHECK_NE(def.check("host", "not-an-ip").find("refuses unclassifiable"),
             std::string::npos);

    // Explicit per-host exceptions are exact and case-insensitive.
    PrivateNetworkPolicy allowPolicy;
    allowPolicy.allowedHosts.insert("intra.corp");
    const PrivateNetworkGuard allowlisted(allowPolicy);
    CHECK_EQ(allowlisted.check("INTRA.corp", "10.1.2.3"), std::string(""));
    CHECK_FALSE(allowlisted.check("sub.intra.corp", "10.1.2.3").empty());
    CHECK_FALSE(allowlisted.check("other.corp", "10.1.2.3").empty());

    // Hermetic mode: even loopback is refused.
    PrivateNetworkPolicy hermetic;
    hermetic.allowLoopback = false;
    const PrivateNetworkGuard hermeticGuard(hermetic);
    CHECK_FALSE(hermeticGuard.check("localhost", "127.0.0.1").empty());
    CHECK_FALSE(hermeticGuard.check("localhost", "::1").empty());

    // Master switch off restores unrestricted fetching.
    PrivateNetworkPolicy legacy;
    legacy.isolatePrivateNetworks = false;
    const PrivateNetworkGuard legacyGuard(legacy);
    CHECK_EQ(legacyGuard.check("a.internal", "10.1.2.3"), std::string(""));
    CHECK_EQ(legacyGuard.check("metadata", "169.254.169.254"),
             std::string(""));
}

// --- Numeric spell-out canonicalization ---------------------------------------

LETHE_TEST_CASE(PrivateNet_Canonical_NumericSpellings) {
    CHECK_EQ(HttpClient::canonicalNumericAddress("127.0.0.1"),
             std::string("127.0.0.1"));
    CHECK_EQ(HttpClient::canonicalNumericAddress("2130706433"),
             std::string("127.0.0.1"));          // decimal 32-bit form
    CHECK_EQ(HttpClient::canonicalNumericAddress("0x7f000001"),
             std::string("127.0.0.1"));          // hex 32-bit form
    CHECK_EQ(HttpClient::canonicalNumericAddress("0x7f.1"),
             std::string("127.0.0.1"));          // mixed radix, 2-part form
    CHECK_EQ(HttpClient::canonicalNumericAddress("10.1"),
             std::string("10.0.0.1"));           // short 2-part form
    // Leading-zero spellings are a DOCUMENTED PLATFORM DIVERGENCE: glibc's
    // resolver dials them as octal ("0177.0.0.1" -> 127.0.0.1) while Apple
    // resolvers dial them as decimal ("0177.0.0.1" -> 177.0.0.1). The
    // canonicalizer mirrors whichever resolver will actually dial, so the
    // guard always classifies the true destination.
    const std::string leadingZero =
        HttpClient::canonicalNumericAddress("0177.0.0.1");
    CHECK_TRUE(leadingZero == "127.0.0.1" || leadingZero == "177.0.0.1");
    // Mapped-v6 rendering also differs per libc (glibc prints the hex
    // form, Apple keeps the dotted tail); both are canonical locally.
    const std::string mapped =
        HttpClient::canonicalNumericAddress("::ffff:127.0.0.1");
    CHECK_TRUE(mapped == "::ffff:7f00:1" || mapped == "::ffff:127.0.0.1");

    CHECK_EQ(HttpClient::canonicalNumericAddress("example.com"),
             std::string(""));
    CHECK_EQ(HttpClient::canonicalNumericAddress("256.1.1.1"),
             std::string(""));
    CHECK_EQ(HttpClient::canonicalNumericAddress("999.1.1.1"),
             std::string(""));
    CHECK_EQ(HttpClient::canonicalNumericAddress(""), std::string(""));
}

// --- Environment configuration -----------------------------------------------

LETHE_TEST_CASE(PrivateNet_EnvConfig) {
    ::setenv("LETHE_PRIVATE_NET_MODE", "open", 1);
    ::setenv("LETHE_PRIVATE_NET_ALLOW", " Alpha.corp , beta.corp,,", 1);
    {
        Config cfg;
        applyEnvironmentOverrides(cfg);
        CHECK_FALSE(cfg.isolatePrivateNetworks);
        CHECK_EQ(cfg.privateNetworkAllowedHosts.size(), 2u);
        CHECK_EQ(cfg.privateNetworkAllowedHosts[0], std::string("alpha.corp"));
        CHECK_EQ(cfg.privateNetworkAllowedHosts[1], std::string("beta.corp"));
    }

    ::setenv("LETHE_PRIVATE_NET_MODE", "isolate", 1);
    {
        Config cfg;
        applyEnvironmentOverrides(cfg);
        CHECK_TRUE(cfg.isolatePrivateNetworks);
    }
    ::setenv("LETHE_PRIVATE_NET_MODE", "bogus", 1);
    {
        // Unknown values keep the SAFE default (isolated).
        Config cfg;
        applyEnvironmentOverrides(cfg);
        CHECK_TRUE(cfg.isolatePrivateNetworks);
    }
    ::setenv("LETHE_PRIVATE_NET_ALLOW", "", 1);
    {
        Config cfg;
        applyEnvironmentOverrides(cfg);
        CHECK_TRUE(cfg.privateNetworkAllowedHosts.empty());
    }

    ::unsetenv("LETHE_PRIVATE_NET_MODE");
    ::unsetenv("LETHE_PRIVATE_NET_ALLOW");
    {
        Config cfg;
        applyEnvironmentOverrides(cfg);
        CHECK_TRUE(cfg.isolatePrivateNetworks);
        CHECK_TRUE(cfg.privateNetworkAllowedHosts.empty());
    }
}

// --- E2E: named host resolving into RFC1918 space ------------------------------

LETHE_TEST_CASE(PrivateNet_E2e_NamedPrivateDestination_Blocked) {
    MiniHttpServer srv;
    srv.handler_ = [](const std::string& req) {
        if (req.find("/dns-query?name=") != std::string::npos) {
            const std::string ip = resolveMockName(req);
            if (ip.empty()) {
                return plainResp(200, "OK",
                                 "Content-Type: application/dns-json\r\n",
                                 "{\"Status\":0}");
            }
            return plainResp(200, "OK",
                             "Content-Type: application/dns-json\r\n",
                             dohAnswerBody(ip));
        }
        return plainResp(200, "OK", "", "origin-ok");
    };
    CHECK_TRUE(srv.start());

    HttpClient client = makePlainClient();
    client.setDohProvider("http://127.0.0.1:" + std::to_string(srv.port()) +
                          "/dns-query");

    HttpRequest req;
    req.url = "http://internal.example:" + std::to_string(srv.port()) + "/";
    HttpResponse resp = client.sendRequest(req);
    CHECK_FALSE(resp.success);
    CHECK_NE(resp.error.find("private-network isolation"),
             std::string::npos);
    CHECK_NE(resp.error.find("10.0.0.7"), std::string::npos);
    // Resolution happened; nothing ever reached an origin socket.
    CHECK_EQ(srv.dohHits(), 1);
    CHECK_EQ(srv.originHits(), 0);
}

// --- E2E: ordinary loopback navigation keeps working under isolation ----------

LETHE_TEST_CASE(PrivateNet_E2e_LoopbackNavigation_StillWorks) {
    MiniHttpServer srv;
    srv.handler_ = [](const std::string& req) {
        if (req.find("/dns-query?name=") != std::string::npos) {
            const std::string ip = resolveMockName(req);
            if (ip.empty()) {
                return plainResp(200, "OK",
                                 "Content-Type: application/dns-json\r\n",
                                 "{\"Status\":0}");
            }
            return plainResp(200, "OK",
                             "Content-Type: application/dns-json\r\n",
                             dohAnswerBody(ip));
        }
        return plainResp(200, "OK", "", "<html><title>t</title>origin-ok</html>");
    };
    CHECK_TRUE(srv.start());

    HttpClient client = makePlainClient();
    client.setDohProvider("http://127.0.0.1:" + std::to_string(srv.port()) +
                          "/dns-query");

    HttpRequest req;
    req.url = "http://site.test:" + std::to_string(srv.port()) + "/";
    HttpResponse resp = client.sendRequest(req);
    CHECK_TRUE(resp.success);
    const std::string body(resp.body.data(), resp.body.size());
    CHECK_NE(body.find("origin-ok"), std::string::npos);
    CHECK_EQ(resp.finalUrl, req.url);
    CHECK_GE(srv.dohHits(), 1);
    CHECK_EQ(srv.originHits(), 1);
}

// --- E2E: redirect chain aiming at private space dies on the private hop -------

LETHE_TEST_CASE(PrivateNet_E2e_RedirectToPrivate_Blocked) {
    MiniHttpServer srv;
    const int originPortPlaceholder = 0; // handler set after start()
    (void)originPortPlaceholder;
    CHECK_TRUE(srv.start());
    const int port = srv.port();
    srv.handler_ = [port](const std::string& req) {
        if (req.find("/dns-query?name=") != std::string::npos) {
            const std::string ip = resolveMockName(req);
            if (ip.empty()) {
                return plainResp(200, "OK",
                                 "Content-Type: application/dns-json\r\n",
                                 "{\"Status\":0}");
            }
            return plainResp(200, "OK",
                             "Content-Type: application/dns-json\r\n",
                             dohAnswerBody(ip));
        }
        if (req.find("GET /redirect") == 0) {
            return plainResp(
                302, "Found",
                "Location: http://internal.example:" + std::to_string(port) +
                    "/next\r\n",
                "");
        }
        return plainResp(200, "OK", "", "origin-ok");
    };

    HttpClient client = makePlainClient();
    client.setDohProvider("http://127.0.0.1:" + std::to_string(port) +
                          "/dns-query");

    HttpRequest req;
    req.url = "http://site.test:" + std::to_string(port) + "/redirect";
    HttpResponse resp = client.sendRequest(req);
    CHECK_FALSE(resp.success);
    CHECK_NE(resp.error.find("private-network isolation"),
             std::string::npos);
    // Hop 1 landed on the origin (the redirector); hop 2 was resolved and
    // blocked before any connection attempt.
    CHECK_GE(srv.dohHits(), 2);
    CHECK_EQ(srv.originHits(), 1);
}

// --- E2E: the cloud-metadata endpoint is refused by name ----------------------

LETHE_TEST_CASE(PrivateNet_E2e_MetadataEndpoint_Blocked) {
    MiniHttpServer srv;
    srv.handler_ = [](const std::string& req) {
        if (req.find("/dns-query?name=") != std::string::npos) {
            const std::string ip = resolveMockName(req);
            if (ip.empty()) {
                return plainResp(200, "OK",
                                 "Content-Type: application/dns-json\r\n",
                                 "{\"Status\":0}");
            }
            return plainResp(200, "OK",
                             "Content-Type: application/dns-json\r\n",
                             dohAnswerBody(ip));
        }
        return plainResp(200, "OK", "", "metadata leaked");
    };
    CHECK_TRUE(srv.start());

    HttpClient client = makePlainClient();
    client.setDohProvider("http://127.0.0.1:" + std::to_string(srv.port()) +
                          "/dns-query");

    HttpRequest req;
    req.url = "http://metadata.google.internal:" +
              std::to_string(srv.port()) + "/computeMetadata/v1/";
    HttpResponse resp = client.sendRequest(req);
    CHECK_FALSE(resp.success);
    CHECK_NE(resp.error.find("link-local"), std::string::npos);
    CHECK_EQ(srv.originHits(), 0);
}

// --- E2E: decimal spell-outs of loopback cannot dodge the guard ---------------

LETHE_TEST_CASE(PrivateNet_E2e_NumericSpellOut_Guarded) {
    MiniHttpServer origin;
    origin.handler_ = [](const std::string&) {
        return plainResp(200, "OK", "", "origin-ok");
    };
    CHECK_TRUE(origin.start());

    // Control: default policy allows loopback regardless of its spelling.
    HttpClient control = makePlainClient();
    HttpRequest req;
    req.url = "http://2130706433:" + std::to_string(origin.port()) + "/";
    HttpResponse ok = control.sendRequest(req);
    CHECK_TRUE(ok.success);
    CHECK_EQ(origin.originHits(), 1);

    // Hermetic policy blocks the SAME URL: the decimal form is
    // canonicalized to 127.0.0.1 and classified as loopback.
    HttpClient guarded = makePlainClient();
    PrivateNetworkPolicy hermetic;
    hermetic.allowLoopback = false;
    guarded.setPrivateNetworkPolicy(std::move(hermetic));
    HttpResponse denied = guarded.sendRequest(req);
    CHECK_FALSE(denied.success);
    CHECK_NE(denied.error.find("private-network isolation"),
             std::string::npos);
    CHECK_NE(denied.error.find("127.0.0.1"), std::string::npos);
    CHECK_EQ(origin.originHits(), 1); // unchanged by the blocked attempt
}
