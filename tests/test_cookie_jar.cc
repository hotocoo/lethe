// test_cookie_jar.cc - Partitioned cookie storage + HttpClient wiring.
//
// Unit coverage for the jar semantics (partitioning, scoping, expiry,
// capacity) and a real-loopback round trip proving Set-Cookie capture and
// Cookie attach through the actual HTTP client.

#include "test_framework.h"
#include "network/http_client.h"
#include "network/tls_config.h"
#include "security/cookie_jar.h"

#include <cstring>
#include <functional>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

using namespace lethe;

namespace {

// Minimal single-connection loopback server: one request per accept, full
// response from the handler, then close. Enough to prove wire behavior.
class EchoServer {
public:
    using Handler = std::function<std::string(const std::string& request)>;

    bool start() {
        listenFd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listenFd_ < 0) return false;
        int reuse = 1;
        ::setsockopt(listenFd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (::bind(listenFd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0 ||
            ::listen(listenFd_, 4) < 0) {
            ::close(listenFd_);
            listenFd_ = -1;
            return false;
        }
        sockaddr_in bound{};
        socklen_t len = sizeof(bound);
        ::getsockname(listenFd_, reinterpret_cast<sockaddr*>(&bound), &len);
        port_ = ntohs(bound.sin_port);
        running_ = true;
        thread_ = std::thread([this] { loop(); });
        return true;
    }

    int port() const { return port_; }
    void setHandler(Handler h) { handler_ = std::move(h); }

    void stop() {
        running_ = false;
        if (listenFd_ >= 0) { ::shutdown(listenFd_, SHUT_RDWR); ::close(listenFd_); listenFd_ = -1; }
        if (thread_.joinable()) thread_.join();
    }

    ~EchoServer() { stop(); }

private:
    void loop() {
        while (running_) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(listenFd_, &rfds);
            timeval tv{0, 100000};
            if (::select(listenFd_ + 1, &rfds, nullptr, nullptr, &tv) <= 0) continue;
            int c = ::accept(listenFd_, nullptr, nullptr);
            if (c < 0) continue;
            std::string req;
            char buf[4096];
            while (req.find("\r\n\r\n") == std::string::npos) {
                ssize_t n = ::recv(c, buf, sizeof(buf), 0);
                if (n <= 0) break;
                req.append(buf, static_cast<size_t>(n));
            }
            const std::string resp = handler_ ? handler_(req)
                                              : std::string("HTTP/1.1 500 Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            ssize_t ignored = ::send(c, resp.data(), resp.size(), 0);
            (void)ignored;
            ::close(c);
        }
    }

    int listenFd_ = -1;
    int port_ = 0;
    bool running_ = false;
    std::thread thread_;
    Handler handler_;
};

std::string simpleResponse(const std::string& extraHeaders,
                           const std::string& body = "<html>ok</html>") {
    std::string r = "HTTP/1.1 200 OK\r\n";
    r += extraHeaders;
    r += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    r += "Connection: close\r\n\r\n";
    r += body;
    return r;
}

} // namespace

// --- Jar unit semantics -------------------------------------------------------

LETHE_TEST_CASE(CookieJar_TopLevelSiteFor) {
    CHECK_EQ(CookieJar::topLevelSiteFor("https://example.com/a/b?x=1#frag"),
             std::string("https://example.com"));
    CHECK_EQ(CookieJar::topLevelSiteFor("http://WWW.Example.COM"),
             std::string("http://www.example.com"));
    CHECK_EQ(CookieJar::topLevelSiteFor("https://example.com:8443/x"),
             std::string("https://example.com:8443"));
    CHECK_EQ(CookieJar::topLevelSiteFor("http://example.com:80/"), // default port dropped
             std::string("http://example.com"));
    CHECK_EQ(CookieJar::topLevelSiteFor("https://user:pass@example.com/p"),
             std::string("https://example.com"));
}

LETHE_TEST_CASE(CookieJar_BasicStoreAndSend) {
    CookieJar jar;
    jar.store("https://site.com", "https://site.com/page",
              "sid=abc123; Path=/");
    CHECK_EQ(jar.headerFor("https://site.com", "https://site.com/other"),
             std::string("sid=abc123"));
    CHECK(jar.headerFor("https://other.com", "https://other.com/").empty());
    CHECK_EQ(jar.size(), size_t(1));
}

LETHE_TEST_CASE(CookieJar_PartitionIsolation) {
    CookieJar jar;
    // Same embedded host under two different top-level sites.
    jar.store("https://news.com", "https://tracker.net/pixel", "id=A");
    jar.store("https://shop.net", "https://tracker.net/pixel", "id=B");

    CHECK_EQ(jar.headerFor("https://news.com", "https://tracker.net/pixel"),
             std::string("id=A"));
    CHECK_EQ(jar.headerFor("https://shop.net", "https://tracker.net/pixel"),
             std::string("id=B"));
    // A third context sees nothing at all.
    CHECK(jar.headerFor("https://blog.org", "https://tracker.net/pixel").empty());
}

LETHE_TEST_CASE(CookieJar_HostOnlyExactMatch) {
    CookieJar jar;
    jar.store("https://site.com", "https://site.com/", "a=1"); // host-only
    CHECK_EQ(jar.headerFor("https://site.com", "https://site.com/x"), std::string("a=1"));
    CHECK(jar.headerFor("https://site.com", "https://www.site.com/x").empty());
    CHECK(jar.headerFor("https://site.com", "https://evil-site.com/").empty());
}

LETHE_TEST_CASE(CookieJar_DomainAttrSubdomains) {
    CookieJar jar;
    jar.store("https://site.com", "https://www.site.com/",
              "d=2; Domain=.site.com; Path=/");
    CHECK_EQ(jar.headerFor("https://site.com", "https://site.com/"), std::string("d=2"));
    CHECK_EQ(jar.headerFor("https://site.com", "https://deep.www.site.com/"), std::string("d=2"));
}

LETHE_TEST_CASE(CookieJar_ForeignDomainRejected) {
    CookieJar jar;
    // evil.com must not plant a cookie for site.com.
    jar.store("https://site.com", "https://evil.com/",
              "steal=1; Domain=site.com; Path=/");
    CHECK_EQ(jar.size(), size_t(0));
    CHECK(jar.headerFor("https://site.com", "https://site.com/").empty());
}

LETHE_TEST_CASE(CookieJar_SecureHttpsOnly) {
    CookieJar jar;
    jar.store("https://site.com", "https://site.com/", "s=9; Secure; Path=/");
    CHECK(jar.headerFor("https://site.com", "http://site.com/").empty());   // plain http
    CHECK_EQ(jar.headerFor("https://site.com", "https://site.com/"), std::string("s=9"));
}

LETHE_TEST_CASE(CookieJar_PathScoping) {
    CookieJar jar;
    // Default path = request directory (/account).
    jar.store("https://site.com", "https://site.com/account/settings",
              "acct=7");
    CHECK_EQ(jar.headerFor("https://site.com", "https://site.com/account/billing"),
             std::string("acct=7"));
    CHECK_EQ(jar.headerFor("https://site.com",
                           "https://site.com/account-settings"), std::string("")); // not under /account/
    CHECK(jar.headerFor("https://site.com", "https://site.com/home").empty());

    // Explicit deep path stays scoped there only.
    jar.store("https://site.com", "https://site.com/account/settings",
              "deep=1; Path=/account/settings");
    CHECK_EQ(jar.headerFor("https://site.com", "https://site.com/account/settings/x"),
             std::string("acct=7; deep=1"));
    CHECK_EQ(jar.headerFor("https://site.com", "https://site.com/account/billing"),
             std::string("acct=7"));
}

LETHE_TEST_CASE(CookieJar_MaxAgeZeroDeletes) {
    CookieJar jar;
    jar.store("https://site.com", "https://site.com/", "gone=1; Path=/");
    CHECK_EQ(jar.size(), size_t(1));
    jar.store("https://site.com", "https://site.com/", "gone=x; Max-Age=0; Path=/");
    CHECK_EQ(jar.size(), size_t(0));

    jar.store("https://site.com", "https://site.com/", "neg=1; Path=/");
    jar.store("https://site.com", "https://site.com/", "neg=x; Max-Age=-5; Path=/");
    CHECK_EQ(jar.size(), size_t(0));
}

LETHE_TEST_CASE(CookieJar_ExpiresPastDateDeletesAndBlocks) {
    CookieJar jar;
    jar.store("https://site.com", "https://site.com/", "old=1; Path=/");
    CHECK_EQ(jar.size(), size_t(1));
    jar.store("https://site.com", "https://site.com/",
              "old=1; Expires=Thu, 01 Jan 1970 00:00:00 GMT; Path=/");
    CHECK_EQ(jar.size(), size_t(0));
    CHECK(jar.headerFor("https://site.com", "https://site.com/").empty());

    // A future Expires keeps the cookie deliverable.
    jar.store("https://site.com", "https://site.com/",
              "fut=1; Expires=Wed, 09 Jun 2100 10:18:14 GMT; Path=/");
    CHECK_EQ(jar.headerFor("https://site.com", "https://site.com/"), std::string("fut=1"));
}

LETHE_TEST_CASE(CookieJar_ReplaceSameCookie) {
    CookieJar jar;
    jar.store("https://site.com", "https://site.com/", "k=1; Path=/");
    jar.store("https://site.com", "https://site.com/", "k=2; Path=/");
    CHECK_EQ(jar.size(), size_t(1)); // replaced, not duplicated
    CHECK_EQ(jar.headerFor("https://site.com", "https://site.com/"), std::string("k=2"));
}

LETHE_TEST_CASE(CookieJar_PurgeClearsAllPartitions) {
    CookieJar jar;
    jar.store("https://a.com", "https://a.com/", "a=1");
    jar.store("https://b.com", "https://b.com/", "b=2");
    CHECK_EQ(jar.size(), size_t(2));
    jar.purge();
    CHECK_EQ(jar.size(), size_t(0));
    CHECK(jar.empty());
}

LETHE_TEST_CASE(CookieJar_CapacityBounded) {
    CookieJar jar;
    for (int i = 0; i < 2200; i++) {
        jar.store("https://site.com", "https://site.com/",
                  "n" + std::to_string(i) + "=v" + std::to_string(i) + "; Path=/");
    }
    CHECK(jar.size() <= 2048); // hard bound held
    // Oldest expired-soonest entries were evicted first; newest survive.
    CHECK(!jar.headerFor("https://site.com", "https://site.com/").empty());
}

// --- Wire behavior through the real HttpClient --------------------------------

LETHE_TEST_CASE(HttpClient_CookieRoundTripAndPartitioning) {
    EchoServer server;
    CHECK(server.start());
    const std::string base = "http://127.0.0.1:" + std::to_string(server.port());

    server.setHandler([](const std::string& req) {
        const bool hasCookie = req.find("Cookie:") != std::string::npos;
        if (req.rfind("GET /embedded", 0) == 0) {
            // Foreign partition: must arrive WITHOUT the jar's cookie.
            return hasCookie ? simpleResponse("", "<html>leaked</html>")
                             : simpleResponse("", "<html>wrong-cookie</html>");
        }
        if (!hasCookie) {
            // First visit plants two cookies (multi Set-Cookie preserved).
            return simpleResponse(
                "Set-Cookie: sid=wire42; Path=/\r\n"
                "Set-Cookie: pref=dark; Path=/\r\n"
                "X-Other: keep\r\n");
        }
        // Second visit echoes whether the cookie came back.
        return req.find("sid=wire42") != std::string::npos
                   ? simpleResponse("", "<html>with-cookie</html>")
                   : simpleResponse("", "<html>leaked</html>");
    });

    TLSConfig tls;
    tls.init_modern_tls_config(0x0304, 0x0304);

    CookieJar jar;
    HttpClient client;
    CHECK(client.initialize(tls));
    client.enableCookies(&jar);

    HttpRequest first;
    first.url = base + "/landing";
    first.topLevelSite = base; // top-level navigation partition
    HttpResponse r1 = client.sendRequest(first);
    CHECK(r1.success);
    CHECK_EQ(r1.setCookieHeaders.size(), size_t(2));
    CHECK_EQ(r1.setCookieHeaders[0], std::string("sid=wire42; Path=/"));

    HttpRequest second;
    second.url = base + "/return";
    second.topLevelSite = base;
    HttpResponse r2 = client.sendRequest(second);
    CHECK(r2.success);
    CHECK(std::string(r2.body.data(), r2.body.size())
              .find("with-cookie") != std::string::npos); // same partition rode sid

    // A different top-level partition must NOT see the cookie, so the
    // handler (which saw no Cookie header) answers "wrong-cookie".
    HttpRequest foreignPartition;
    foreignPartition.url = base + "/embedded";
    foreignPartition.topLevelSite = "http://other-origin.example";
    HttpResponse r3 = client.sendRequest(foreignPartition);
    CHECK(r3.success);
    CHECK(std::string(r3.body.data(), r3.body.size()).find("wrong-cookie") !=
          std::string::npos);
    CHECK(std::string(r3.body.data(), r3.body.size()).find("leaked") ==
          std::string::npos);

    server.stop();
}

LETHE_TEST_CASE(HttpClient_ExplicitCookieHeaderWins) {
    EchoServer server;
    CHECK(server.start());
    const std::string base = "http://127.0.0.1:" + std::to_string(server.port());

    server.setHandler([](const std::string& req) {
        size_t pos = req.find("Cookie:");
        std::string seen = pos == std::string::npos ? "" : req.substr(pos);
        return simpleResponse("X-Saw-Cookie: " + (seen.empty() ? std::string("none")
                                                               : seen.substr(0, seen.find("\r\n"))) +
                                  "\r\n",
                              "<html>ok</html>");
    });

    TLSConfig tls;
    tls.init_modern_tls_config(0x0304, 0x0304);
    CookieJar jar;
    jar.store(base, base + "/", "jar=1");
    HttpClient client;
    CHECK(client.initialize(tls));
    client.enableCookies(&jar);

    HttpRequest req;
    req.url = base + "/";
    req.headers["Cookie"] = "explicit=caller";
    HttpResponse resp = client.sendRequest(req);
    CHECK(resp.success);
    const auto it = resp.headers.find("x-saw-cookie");
    CHECK(it != resp.headers.end());
    CHECK(it->second.find("explicit=caller") != std::string::npos);
    CHECK(it->second.find("jar=1") == std::string::npos); // jar did not append

    server.stop();
}
