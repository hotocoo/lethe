// test_hsts.cc — HSTS (RFC 6797) verification
//
// Unit layer: HstsCache policy semantics — exact and subdomain matching,
// includeSubDomains boundaries, max-age=0 revocation, expiry, IP-literal
// refusal, capacity bounding, and Strict-Transport-Security header parsing.
//
// E2E layer: a real TLS 1.3 origin teaches Strict-Transport-Security; the
// next plain http:// request to that host is rewritten to https:// BEFORE
// any connection attempt. Proof by construction:
//   - the TLS origin's handler sees the request (a plaintext GET could
//     never complete a TLS handshake) and resp.finalUrl shows https://;
//   - the control run WITHOUT a learned policy fails against the same
//     TLS-only origin — no silent plaintext path exists;
//   - an STS header received over plain HTTP is ignored entirely.

#include "test_framework.h"
#include "test_tls_helpers.h"
#include "network/http_client.h"
#include "security/hsts_cache.h"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace lethe;

namespace {

// Minimal loopback HTTP server (DoH-provider role).
class MiniHttpServer {
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
                const int fd = ::accept(listenFd_, nullptr, nullptr);
                if (fd < 0) continue;
                std::string req;
                char buf[8192];
                while (req.find("\r\n\r\n") == std::string::npos) {
                    const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
                    if (n <= 0) break;
                    req.append(buf, static_cast<size_t>(n));
                }
                const bool isDoh = req.find("/dns-query?name=") != std::string::npos;
                if (isDoh) dohHits_.fetch_add(1); else originHits_.fetch_add(1);
                const std::string resp = handler_(req);
                ::send(fd, resp.data(), resp.size(), 0);
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

// DoH JSON A-record answer mapping the queried hostname to loopback.
std::string dohAnswer(const std::string& request) {
    const size_t eq = request.find("name=");
    std::string name = "host.internal";
    if (eq != std::string::npos) {
        const size_t end = request.find_first_of(" &", eq);
        name = request.substr(eq + 5,
                              end == std::string::npos ? std::string::npos
                                                       : end - eq - 5);
    }
    return "{\"Status\":0,\"Answer\":[{\"name\":\"" + name +
           "\",\"type\":1,\"data\":\"127.0.0.1\"}]}";
}

void setupDohMock(MiniHttpServer& doh) {
    doh.handler_ = [](const std::string& req) {
        if (req.find("/dns-query?name=") != std::string::npos) {
            return plainResp(200, "OK", "", dohAnswer(req));
        }
        // Any non-DoH request here would mean a plaintext origin leak.
        return plainResp(404, "Not Found", "", "no origin at the resolver");
    };
}

} // namespace

// --- HstsCache unit semantics ------------------------------------------------

LETHE_TEST_CASE(Hsts_Record_EnablesExactUpgrade) {
    HstsCache cache;
    CHECK_FALSE(cache.shouldUpgrade("example.com"));
    cache.record("example.com", std::chrono::hours(1), false);
    CHECK_TRUE(cache.shouldUpgrade("example.com"));
    CHECK_FALSE(cache.shouldUpgrade("other.com"));
    CHECK_EQ(cache.size(), 1u);
}

LETHE_TEST_CASE(Hsts_HostNormalization_CaseAndTrailingDot) {
    HstsCache cache;
    cache.record("ExAmple.COM.", std::chrono::hours(1), false);
    CHECK_TRUE(cache.shouldUpgrade("example.com"));
    CHECK_TRUE(cache.shouldUpgrade("EXAMPLE.com"));
    CHECK_TRUE(cache.shouldUpgrade("Example.Com."));
}

LETHE_TEST_CASE(Hsts_Subdomain_NeedsIncludeSubDomains) {
    HstsCache cache;
    cache.record("parent.example", std::chrono::hours(1), /*isd*/false);
    CHECK_TRUE(cache.shouldUpgrade("parent.example"));
    CHECK_FALSE(cache.shouldUpgrade("sub.parent.example"));

    HstsCache wide;
    wide.record("secure.example", std::chrono::hours(1), /*isd*/true);
    CHECK_TRUE(wide.shouldUpgrade("secure.example"));
    CHECK_TRUE(wide.shouldUpgrade("sub.secure.example"));
    CHECK_TRUE(wide.shouldUpgrade("deep.a.b.secure.example"));
    // Label boundaries: bare suffix strings must never match.
    CHECK_FALSE(wide.shouldUpgrade("xsecure.example"));
    CHECK_FALSE(wide.shouldUpgrade("notsecure.example"));
}

LETHE_TEST_CASE(Hsts_MaxAgeZero_RevokesPolicy) {
    HstsCache cache;
    cache.record("gone.example", std::chrono::hours(1), false);
    CHECK_TRUE(cache.shouldUpgrade("gone.example"));
    cache.record("gone.example", std::chrono::seconds(0), false);
    CHECK_FALSE(cache.shouldUpgrade("gone.example"));
    // Revoking an unknown host is harmless.
    cache.record("never-there.example", std::chrono::seconds(0), false);
    CHECK_EQ(cache.size(), 0u);
}

LETHE_TEST_CASE(Hsts_Expired_Policy_DoesNotUpgrade) {
    HstsCache cache;
    const auto now = std::chrono::steady_clock::now();
    cache.record("exp.example", std::chrono::seconds(100), true, now);
    CHECK_TRUE(cache.shouldUpgrade("exp.example", now));
    CHECK_TRUE(cache.shouldUpgrade("sub.exp.example", now));
    const auto later = now + std::chrono::seconds(101);
    CHECK_FALSE(cache.shouldUpgrade("exp.example", later));
    CHECK_FALSE(cache.shouldUpgrade("sub.exp.example", later));
    CHECK_EQ(cache.size(later), 0u); // expired entries stop counting
}

LETHE_TEST_CASE(Hsts_IpLiterals_NeverCarryPolicy) {
    HstsCache cache;
    cache.record("192.168.1.1", std::chrono::hours(1), false);
    cache.record("[::1]", std::chrono::hours(1), false);
    cache.record("::1", std::chrono::hours(1), false);
    CHECK_FALSE(cache.shouldUpgrade("192.168.1.1"));
    CHECK_FALSE(cache.shouldUpgrade("[::1]"));
    CHECK_FALSE(cache.shouldUpgrade("::1"));
    CHECK_EQ(cache.size(), 0u);
}

LETHE_TEST_CASE(Hsts_Capacity_Bounded_OldestEvicted) {
    HstsCache cache;
    for (int i = 0; i < 600; ++i) {
        char host[32];
        std::snprintf(host, sizeof(host), "h%03d.test", i);
        cache.record(host, std::chrono::hours(1), false);
    }
    CHECK_EQ(cache.size(), 512u);
    CHECK_FALSE(cache.shouldUpgrade("h000.test")); // oldest evicted
    CHECK_TRUE(cache.shouldUpgrade("h599.test"));  // most recent kept
    CHECK_TRUE(cache.shouldUpgrade("h200.test"));
}

LETHE_TEST_CASE(Hsts_Clear_DropsEverything) {
    HstsCache cache;
    cache.record("a.test", std::chrono::hours(1), true);
    cache.record("b.test", std::chrono::hours(1), false);
    cache.clear();
    CHECK_EQ(cache.size(), 0u);
    CHECK_FALSE(cache.shouldUpgrade("a.test"));
    CHECK_FALSE(cache.shouldUpgrade("sub.a.test"));
}

LETHE_TEST_CASE(Hsts_StsHeader_Parse_ValidForms) {
    std::chrono::seconds maxAge{0};
    bool isd = false;

    CHECK_TRUE(HstsCache::parseStsHeader("max-age=31536000", maxAge, isd));
    CHECK_EQ(static_cast<long long>(maxAge.count()), 31536000LL);
    CHECK_FALSE(isd);

    CHECK_TRUE(HstsCache::parseStsHeader("MAX-AGE=60", maxAge, isd));

    CHECK_TRUE(HstsCache::parseStsHeader(
        "max-age=15768000 ; includeSubDomains", maxAge, isd));
    CHECK_TRUE(isd);

    isd = true;
    CHECK_TRUE(HstsCache::parseStsHeader(
        "max-age=10; preload; unknown=zzz", maxAge, isd));
    CHECK_EQ(static_cast<long long>(maxAge.count()), 10LL);
    CHECK_FALSE(isd); // reset per call; this header carried no ISD

    CHECK_TRUE(HstsCache::parseStsHeader("max-age=0", maxAge, isd));
    CHECK_EQ(maxAge.count(), 0); // zero parses (revocation)
}

LETHE_TEST_CASE(Hsts_StsHeader_MissingOrBadMaxAge_RejectedEntirely) {
    std::chrono::seconds maxAge{99};
    bool isd = false;

    // Missing max-age: whole header ignored even with ISD present.
    CHECK_FALSE(HstsCache::parseStsHeader("includeSubDomains", maxAge, isd));
    // Unparsable values.
    CHECK_FALSE(HstsCache::parseStsHeader("max-age=abc", maxAge, isd));
    CHECK_FALSE(HstsCache::parseStsHeader("max-age=-1", maxAge, isd));
    CHECK_FALSE(HstsCache::parseStsHeader("max-age=", maxAge, isd));
    CHECK_FALSE(HstsCache::parseStsHeader("", maxAge, isd));
    // Quoted value violates the 1*DIGIT grammar.
    CHECK_FALSE(HstsCache::parseStsHeader("max-age=\"3600\"", maxAge, isd));
    // Absurd length rejected before arithmetic can overflow.
    CHECK_FALSE(HstsCache::parseStsHeader(
        "max-age=99999999999999999999", maxAge, isd));
}

// --- E2E ---------------------------------------------------------------------

#ifdef HAVE_OPENSSL

LETHE_TEST_CASE(Hsts_E2e_LearnedPolicy_UpgradesPlainHttpBeforeConnect) {
    MiniHttpServer doh;
    setupDohMock(doh);
    CHECK_TRUE(doh.start());

    std::string caPem, caKeyPem, srvCertPem, srvKeyPem;
    CHECK_TRUE(tls_test::generateTestCa(caPem, caKeyPem));
    CHECK_TRUE(tls_test::generateServerCert(caPem, caKeyPem, "sts.internal",
                                            srvCertPem, srvKeyPem));

    tls_test::LoopbackTlsServer origin;
    std::mutex pathsMu;
    std::vector<std::string> tlsPaths;
    origin.setHandler([&](const std::string& req) {
        std::string path = "/";
        const size_t sp = req.find(' ');
        if (sp != std::string::npos) {
            const size_t sp2 = req.find(' ', sp + 1);
            path = req.substr(sp + 1,
                              sp2 == std::string::npos ? std::string::npos
                                                       : sp2 - sp - 1);
        }
        {
            std::lock_guard<std::mutex> lock(pathsMu);
            tlsPaths.push_back(path);
        }
        if (path == "/hsts") {
            return plainResp(200, "OK",
                             "Strict-Transport-Security: "
                             "max-age=3600; includeSubDomains\r\n",
                             "<html><body>policy set</body></html>");
        }
        return plainResp(200, "OK", "",
                         "<html><body>secure content</body></html>");
    });
    CHECK_TRUE(origin.start(srvCertPem, srvKeyPem));

    const std::string caFile = tls_test::writeTempFile("lethe_hsts_ca", caPem);
    CHECK_TRUE(!caFile.empty());

    HstsCache cache;
    HttpClient client;
    TLSConfig tls;
    tls.init_modern_tls_config(0x0304, 0x0305);
    tls.setCaBundlePath(caFile);
    CHECK_TRUE(client.initialize(tls));
    client.setDohProvider("http://127.0.0.1:" +
                          std::to_string(doh.port()) + "/dns-query");
    client.enableHsts(&cache);

    // 1. Learn the policy over a certificate-verified TLS hop.
    const std::string base = "https://sts.internal:" +
                             std::to_string(origin.port());
    HttpRequest learnReq;
    learnReq.url = base + "/hsts";
    HttpResponse first = client.sendRequest(learnReq);
    CHECK_TRUE(first.success);
    CHECK_TRUE(cache.shouldUpgrade("sts.internal"));
    CHECK_TRUE(cache.shouldUpgrade("anything.sts.internal")); // ISD honored

    // 2. The plain http:// URL is rewritten BEFORE any connection: it lands
    //    on the TLS origin (only TLS could complete against this socket)
    //    and the response reports the upgraded final URL.
    HttpRequest plainReq;
    plainReq.url = "http://sts.internal:" + std::to_string(origin.port()) +
                   "/plain";
    HttpResponse second = client.sendRequest(plainReq);
    CHECK_TRUE(second.success);
    CHECK_EQ(second.finalUrl,
             "https://sts.internal:" + std::to_string(origin.port()) +
                 "/plain");

    {
        std::lock_guard<std::mutex> lock(pathsMu);
        CHECK_EQ(tlsPaths.size(), 2u);
        CHECK_EQ(tlsPaths[0], std::string("/hsts"));
        CHECK_EQ(tlsPaths[1], std::string("/plain"));
    }

    // Every mock request was a DNS lookup; none was an origin fetch.
    CHECK_TRUE(doh.dohHits() >= 1);
    CHECK_EQ(doh.originHits(), 0);

    ::remove(caFile.c_str());
}

LETHE_TEST_CASE(Hsts_E2e_Control_NoPolicy_FailsAgainstTlsOnlyOrigin) {
    // Identical servers but NO STS learned: the same plain http:// URL
    // cannot silently ride through - plaintext bytes break the TLS
    // handshake and the request fails closed with zero origin hits.
    MiniHttpServer doh;
    setupDohMock(doh);
    CHECK_TRUE(doh.start());

    std::string caPem, caKeyPem, srvCertPem, srvKeyPem;
    CHECK_TRUE(tls_test::generateTestCa(caPem, caKeyPem));
    CHECK_TRUE(tls_test::generateServerCert(caPem, caKeyPem, "sts.internal",
                                            srvCertPem, srvKeyPem));
    tls_test::LoopbackTlsServer origin;
    std::atomic<int> handled{0};
    origin.setHandler([&](const std::string&) {
        handled.fetch_add(1);
        return plainResp(200, "OK", "", "plaintext reached a TLS origin");
    });
    CHECK_TRUE(origin.start(srvCertPem, srvKeyPem));
    const std::string caFile = tls_test::writeTempFile("lethe_hsts_ca", caPem);
    CHECK_TRUE(!caFile.empty());

    HstsCache cache;
    HttpClient client;
    TLSConfig tls;
    tls.init_modern_tls_config(0x0304, 0x0305);
    tls.setCaBundlePath(caFile);
    CHECK_TRUE(client.initialize(tls));
    client.setDohProvider("http://127.0.0.1:" +
                          std::to_string(doh.port()) + "/dns-query");
    client.enableHsts(&cache);

    HttpRequest plainReq;
    plainReq.url = "http://sts.internal:" +
                   std::to_string(origin.port()) + "/plain";
    HttpResponse resp = client.sendRequest(plainReq);
    CHECK_FALSE(resp.success);
    CHECK_EQ(handled.load(), 0); // the TLS handler never saw the request

    ::remove(caFile.c_str());
}

#endif // HAVE_OPENSSL

LETHE_TEST_CASE(Hsts_E2e_StsOverPlainHttp_IsIgnored) {
    // RFC 6797: policy may only be learned over secure transport. A plain
    // HTTP server shouting Strict-Transport-Security must change nothing.
    MiniHttpServer doh;
    setupDohMock(doh);
    CHECK_TRUE(doh.start());

    MiniHttpServer origin;
    origin.handler_ = [](const std::string&) {
        return plainResp(200, "OK",
                         "Strict-Transport-Security: max-age=3600\r\n",
                         "<html><body>insecure page</body></html>");
    };
    CHECK_TRUE(origin.start());

    HstsCache cache;
    HttpClient client;
    TLSConfig tls;
    tls.init_modern_tls_config(0x0304, 0x0305);
    CHECK_TRUE(client.initialize(tls));
    client.setDohProvider("http://127.0.0.1:" +
                          std::to_string(doh.port()) + "/dns-query");
    client.enableHsts(&cache);

    HttpRequest req;
    req.url = "http://plainsts.internal:" +
              std::to_string(origin.port()) + "/";
    HttpResponse r1 = client.sendRequest(req);
    CHECK_TRUE(r1.success);
    HttpResponse r2 = client.sendRequest(req);
    CHECK_TRUE(r2.success);

    // The header arrived over HTTP: it must NOT create upgrade policy.
    CHECK_FALSE(cache.shouldUpgrade("plainsts.internal"));
    CHECK_EQ(cache.size(), 0u);
    CHECK_EQ(origin.originHits(), 2);
}

LETHE_TEST_CASE(Hsts_Disabled_NoEnforcement) {
    HstsCache cache;
    cache.record("example.com", std::chrono::hours(1), false);
    CHECK_TRUE(cache.shouldUpgrade("example.com"));

    HttpClient client;
    TLSConfig tls;
    tls.init_modern_tls_config(0x0304, 0x0305);
    CHECK_TRUE(client.initialize(tls));
    client.enableHsts(&cache);
    CHECK_TRUE(client.hstsEnabled());
    client.disableHsts();
    CHECK_FALSE(client.hstsEnabled());
}
