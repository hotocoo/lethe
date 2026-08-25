
// test_request_hygiene.cc — Navigation request hygiene over real sockets
//
// Verifies what Lethe actually puts on the wire:
//   - Referer computed under the Referrer-Policy engine (never pasted
//     verbatim): full URL same-origin, origin-only cross-origin, stripped
//     entirely on https -> http downgrades
//   - Referrer-Policy response headers narrowing the policy for later
//     hops of the same request chain
//   - Sec-Fetch-Site/Mode/Dest/User metadata and Upgrade-Insecure-
//     Requests on top-level navigations only (API fetches stay unchanged)
//   - Fail-closed http/https scheme allowlist, enforced before any I/O
//     and again on every redirect target

#include "test_framework.h"
#include "network/http_client.h"
#include "network/tls_config.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <functional>
#include <netinet/in.h>
#include <sstream>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <vector>

#ifdef HAVE_OPENSSL
#include "test_tls_helpers.h"
#endif

using namespace lethe;

namespace {

std::string toLower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string trim(const std::string& s) {
    const size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    const size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

bool iequals(const std::string& a, const std::string& b) {
    return toLower(a) == toLower(b);
}

// Value of a header in a raw request text ("" when absent).
std::string headerValueIn(const std::string& raw, const std::string& name) {
    std::istringstream stream(raw);
    std::string line;
    while (std::getline(stream, line)) {
        line = trim(line);
        if (line.empty()) break; // end of headers
        const size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        if (iequals(trim(line.substr(0, colon)), name)) {
            return trim(line.substr(colon + 1));
        }
    }
    return "";
}

int countHeadersNamed(const std::string& raw, const std::string& name) {
    int n = 0;
    std::istringstream stream(raw);
    std::string line;
    while (std::getline(stream, line)) {
        line = trim(line);
        if (line.empty()) break;
        const size_t colon = line.find(':');
        if (colon == std::string::npos) continue;
        if (iequals(trim(line.substr(0, colon)), name)) ++n;
    }
    return n;
}

std::string httpResponse(int status, const std::string& statusText,
                         const std::string& body,
                         const std::vector<std::pair<std::string, std::string>>& extra = {}) {
    std::string resp = "HTTP/1.1 " + std::to_string(status) + " " + statusText + "\r\n";
    for (const auto& h : extra) {
        resp += h.first + ": " + h.second + "\r\n";
    }
    resp += "Content-Length: " + std::to_string(body.size()) + "\r\n";
    resp += "Connection: close\r\n\r\n";
    resp += body;
    return resp;
}

// Minimal single-threaded loopback HTTP server capturing every request.
class HygieneServer {
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
        running_ = true;
        thread_ = std::thread([this]() { runLoop(); });
        return true;
    }

    int port() const { return port_; }
    void setHandler(Handler h) { handler_ = std::move(h); }

    void stop() {
        running_ = false;
        if (listenFd_ >= 0) {
            ::shutdown(listenFd_, SHUT_RDWR);
            ::close(listenFd_);
            listenFd_ = -1;
        }
        if (thread_.joinable()) thread_.join();
    }

    ~HygieneServer() { stop(); }

    std::vector<std::string> requests_;

private:
    void runLoop() {
        while (running_) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(listenFd_, &rfds);
            timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 100000;
            if (::select(listenFd_ + 1, &rfds, nullptr, nullptr, &tv) <= 0) continue;
            const int fd = ::accept(listenFd_, nullptr, nullptr);
            if (fd < 0) continue;
            std::string request;
            char buf[4096];
            while (request.find("\r\n\r\n") == std::string::npos) {
                const int n = static_cast<int>(::recv(fd, buf, sizeof(buf), 0));
                if (n <= 0) break;
                request.append(buf, static_cast<size_t>(n));
            }
            requests_.push_back(request);
            const std::string resp =
                handler_ ? handler_(request) : httpResponse(200, "OK", "ok");
            const ssize_t ignored [[maybe_unused]] =
                ::send(fd, resp.data(), resp.size(), 0);
            ::close(fd);
        }
    }

    int listenFd_ = -1;
    int port_ = 0;
    bool running_ = false;
    std::thread thread_;
    Handler handler_;
};

HttpClient makeClient() {
    HttpClient c;
    CHECK_TRUE(c.initialize(TLSConfig{}));
    return c;
}

} // namespace

// --- Unit semantics ----------------------------------------------------------

LETHE_TEST_CASE(ParseReferrerPolicy_Tokens) {
    ReferrerPolicy p = ReferrerPolicy::Unset;
    CHECK_TRUE(HttpClient::parseReferrerPolicy("no-referrer", p));
    CHECK_EQ(p, ReferrerPolicy::NoReferrer);

    CHECK_TRUE(HttpClient::parseReferrerPolicy("  Strict-Origin-When-Cross-Origin ",
                                               p));
    CHECK_EQ(p, ReferrerPolicy::StrictOriginWhenCrossOrigin);

    // Last recognized token wins; unknown tokens are skipped.
    CHECK_TRUE(HttpClient::parseReferrerPolicy("banana, unsafe-url", p));
    CHECK_EQ(p, ReferrerPolicy::UnsafeUrl);
    CHECK_TRUE(HttpClient::parseReferrerPolicy("unsafe-url, banana", p));
    CHECK_EQ(p, ReferrerPolicy::UnsafeUrl);
    CHECK_TRUE(HttpClient::parseReferrerPolicy("origin, banana, no-referrer", p));
    CHECK_EQ(p, ReferrerPolicy::NoReferrer);

    // A list with no recognized token must not change the active policy.
    CHECK_FALSE(HttpClient::parseReferrerPolicy("banana, choco", p));
    CHECK_FALSE(HttpClient::parseReferrerPolicy("", p));

    // Policies we deliberately do not implement are skipped rather than
    // mapped to wrong semantics.
    CHECK_FALSE(HttpClient::parseReferrerPolicy("strict-origin, same-origin", p));
}

LETHE_TEST_CASE(FetchSite_Derivation) {
    // No triggering document: user-initiated navigation.
    CHECK_EQ(HttpClient::deriveFetchSite("", "https://example.com/x"),
             std::string("none"));
    CHECK_EQ(HttpClient::deriveFetchSite("https://example.com/a", "https://example.com/b"),
             std::string("same-origin"));
    // Port differences break same-origin but stay same-site.
    CHECK_EQ(HttpClient::deriveFetchSite("http://example.com:8080/a", "https://example.com/b"),
             std::string("same-site"));
    // Subdomains share a registrable-domain guess.
    CHECK_EQ(HttpClient::deriveFetchSite("http://cdn.example.test/a", "http://api.example.test/b"),
             std::string("same-site"));
    // Different sites.
    CHECK_EQ(HttpClient::deriveFetchSite("http://evil.test/a", "http://example.com/b"),
             std::string("cross-site"));
    // Fetch Metadata semantics: the site ignores the port, so the same
    // host on different ports is same-site (but never same-origin).
    CHECK_EQ(HttpClient::deriveFetchSite("http://127.0.0.1:9000/a", "http://127.0.0.1:9100/b"),
             std::string("same-site"));
    // Distinct address literals do NOT get same-site treatment from the
    // registrable-domain heuristic.
    CHECK_EQ(HttpClient::deriveFetchSite("http://127.0.0.1/a", "http://127.0.0.2/b"),
             std::string("cross-site"));
}

// --- Wire behavior: navigation metadata --------------------------------------

LETHE_TEST_CASE(NavigationHeaders_EmittedOnlyForNavigations) {
    HygieneServer srv;
    CHECK_TRUE(srv.start());
    HttpClient client = makeClient();

    HttpRequest nav;
    nav.url = "http://127.0.0.1:" + std::to_string(srv.port()) + "/doc";
    nav.navigationRequest = true;
    HttpResponse rnav = client.sendRequest(nav);
    CHECK_TRUE(rnav.success);
    CHECK_EQ(srv.requests_.size(), size_t{1});
    const std::string& navReq = srv.requests_[0];
    CHECK_EQ(countHeadersNamed(navReq, "Upgrade-Insecure-Requests"), 1);
    CHECK_EQ(headerValueIn(navReq, "Upgrade-Insecure-Requests"), std::string("1"));
    CHECK_EQ(headerValueIn(navReq, "Sec-Fetch-Site"), std::string("none"));
    CHECK_EQ(headerValueIn(navReq, "Sec-Fetch-Mode"), std::string("navigate"));
    CHECK_EQ(headerValueIn(navReq, "Sec-Fetch-Dest"), std::string("document"));
    CHECK_EQ(headerValueIn(navReq, "Sec-Fetch-User"), std::string("?1"));
    // No triggering document -> no Referer.
    CHECK_EQ(countHeadersNamed(navReq, "Referer"), 0);

    HttpRequest api;
    api.url = "http://127.0.0.1:" + std::to_string(srv.port()) + "/api";
    HttpResponse rapi = client.sendRequest(api);
    CHECK_TRUE(rapi.success);
    CHECK_EQ(srv.requests_.size(), size_t{2});
    const std::string& apiReq = srv.requests_[1];
    CHECK_EQ(countHeadersNamed(apiReq, "Upgrade-Insecure-Requests"), 0);
    CHECK_EQ(countHeadersNamed(apiReq, "Sec-Fetch-Site"), 0);
    CHECK_EQ(countHeadersNamed(apiReq, "Sec-Fetch-Mode"), 0);
    CHECK_EQ(countHeadersNamed(apiReq, "Sec-Fetch-Dest"), 0);
    CHECK_EQ(countHeadersNamed(apiReq, "Sec-Fetch-User"), 0);
    CHECK_EQ(countHeadersNamed(apiReq, "Referer"), 0);
    srv.stop();
}

LETHE_TEST_CASE(NavigationHeaders_CallerValuesWin) {
    HygieneServer srv;
    CHECK_TRUE(srv.start());
    HttpClient client = makeClient();

    HttpRequest req;
    req.url = "http://127.0.0.1:" + std::to_string(srv.port()) + "/";
    req.navigationRequest = true;
    req.headers["Sec-Fetch-Site"] = "same-origin";
    req.headers["Referer"] = "https://caller.example/explicit";
    CHECK_TRUE(client.sendRequest(req).success);
    CHECK_EQ(srv.requests_.size(), size_t{1});
    const std::string& raw = srv.requests_[0];
    // Exactly one occurrence each - the caller's, not a duplicated default.
    CHECK_EQ(countHeadersNamed(raw, "Sec-Fetch-Site"), 1);
    CHECK_EQ(headerValueIn(raw, "Sec-Fetch-Site"), std::string("same-origin"));
    CHECK_EQ(countHeadersNamed(raw, "Referer"), 1);
    CHECK_EQ(headerValueIn(raw, "Referer"),
             std::string("https://caller.example/explicit"));
    srv.stop();
}

LETHE_TEST_CASE(Referer_ComputedPerHopUnderDefaultPolicy) {
    HygieneServer srv;
    CHECK_TRUE(srv.start());
    const std::string base = "http://127.0.0.1:" + std::to_string(srv.port());
    HttpClient client = makeClient();

    // Same-origin trigger: the full triggering URL rides along.
    HttpRequest same;
    same.url = base + "/target";
    same.referrer = base + "/from/page";
    same.navigationRequest = true;
    CHECK_TRUE(client.sendRequest(same).success);
    CHECK_EQ(srv.requests_.size(), size_t{1});
    CHECK_EQ(headerValueIn(srv.requests_[0], "Referer"),
             base + "/from/page");
    CHECK_EQ(headerValueIn(srv.requests_[0], "Sec-Fetch-Site"),
             std::string("same-origin"));

    // Cross-origin trigger: reduced to the bare origin, path dropped.
    HttpRequest cross;
    cross.url = base + "/target";
    cross.referrer = "http://other.example.org/deep/page?q=secret";
    cross.navigationRequest = true;
    CHECK_TRUE(client.sendRequest(cross).success);
    CHECK_EQ(srv.requests_.size(), size_t{2});
    CHECK_EQ(headerValueIn(srv.requests_[1], "Referer"),
             std::string("http://other.example.org"));
    CHECK_EQ(headerValueIn(srv.requests_[1], "Sec-Fetch-Site"),
             std::string("cross-site"));
    srv.stop();
}

LETHE_TEST_CASE(RedirectChain_RefererFollowsHopsNotTheOriginalUrl) {
    HygieneServer a, b;
    CHECK_TRUE(a.start());
    CHECK_TRUE(b.start());
    a.setHandler([&](const std::string&) {
        return httpResponse(302, "Found", "",
                            {{"Location", "http://127.0.0.1:" +
                                          std::to_string(b.port()) + "/hop2"}});
    });

    HttpClient client = makeClient();
    HttpRequest req;
    req.url = "http://127.0.0.1:" + std::to_string(a.port()) + "/hop1";
    req.navigationRequest = true;
    req.referrer = "http://start.example.net/entry";
    HttpResponse resp = client.sendRequest(req);
    CHECK_TRUE(resp.success);
    CHECK_EQ(resp.finalUrl,
             "http://127.0.0.1:" + std::to_string(b.port()) + "/hop2");

    // Hop 1: cross-origin trigger reduced to its origin...
    CHECK_GE(a.requests_.size(), size_t{1});
    CHECK_EQ(headerValueIn(a.requests_[0], "Referer"),
             std::string("http://start.example.net"));
    // Hop 2: the PREVIOUS HOP is now the referrer, again reduced to ITS
    // origin for the cross-origin target. The original trigger URL never
    // travels past the first hop.
    CHECK_GE(b.requests_.size(), size_t{1});
    CHECK_EQ(headerValueIn(b.requests_[0], "Referer"),
             "http://127.0.0.1:" + std::to_string(a.port()));
    // Same host, different port: never same-origin, but per Fetch
    // Metadata the site comparison ignores ports - same-site.
    CHECK_EQ(headerValueIn(b.requests_[0], "Sec-Fetch-Site"),
             std::string("same-site"));
}

#ifdef HAVE_OPENSSL
LETHE_TEST_CASE(Referer_HttpsDowngradeIsStrippedEntirely) {
    std::string caPem, caKeyPem, certPem, keyPem;
    CHECK_TRUE(tls_test::generateTestCa(caPem, caKeyPem));
    CHECK_TRUE(tls_test::generateServerCert(caPem, caKeyPem, "localhost",
                                            certPem, keyPem));
    const std::string bundle = tls_test::writeTempFile("hygiene_ca", caPem);
    CHECK_FALSE(bundle.empty());

    tls_test::LoopbackTlsServer tlsSrv;
    CHECK_TRUE(tlsSrv.start(certPem, keyPem));
    HygieneServer plain;
    CHECK_TRUE(plain.start());

    tlsSrv.setHandler([&](const std::string&) {
        return httpResponse(302, "Found", "",
                            {{"Location", "http://127.0.0.1:" +
                                          std::to_string(plain.port()) + "/downgraded"}});
    });

    HttpClient client;
    TLSConfig cfg;
    cfg.setCaBundlePath(bundle);
    CHECK_TRUE(client.initialize(cfg));

    HttpRequest req;
    req.url = "https://localhost:" + std::to_string(tlsSrv.port()) + "/secure";
    req.referrer = "https://localhost:" + std::to_string(tlsSrv.port()) + "/origin-doc";
    req.navigationRequest = true;
    HttpResponse resp = client.sendRequest(req);
    CHECK_TRUE(resp.success);
    CHECK_EQ(plain.requests_.size(), size_t{1});
    // An https -> http downgrade strips the referrer outright: the
    // plaintext peer learns NOTHING about where the user came from -
    // not even the bare origin of the secure page.
    CHECK_EQ(headerValueIn(plain.requests_[0], "Referer"), std::string(""));
}
#endif // HAVE_OPENSSL

// --- Wire behavior: Referrer-Policy responses --------------------------------

namespace {

struct RedirectPair {
    HygieneServer a, b;
    HttpClient client;

    bool start(const std::string& referrerPolicyHeader) {
        if (!a.start() || !b.start()) return false;
        std::vector<std::pair<std::string, std::string>> extra = {
            {"Location", "http://127.0.0.1:" + std::to_string(b.port()) + "/x"}};
        if (!referrerPolicyHeader.empty()) {
            extra.push_back({"Referrer-Policy", referrerPolicyHeader});
        }
        a.setHandler([extra](const std::string&) {
            return httpResponse(302, "Found", "", extra);
        });
        return client.initialize(TLSConfig{});
    }

    bool navigate(const std::string& path = "/") {
        HttpRequest req;
        req.url = "http://127.0.0.1:" + std::to_string(a.port()) + path;
        return client.sendRequest(req).success;
    }
};

} // namespace

LETHE_TEST_CASE(ReferrerPolicy_HeaderGovernsLaterRedirectHops) {
    // Control: without the header the redirect hop reveals the previous
    // hop's origin.
    {
        RedirectPair rp;
        CHECK_TRUE(rp.start(""));
        CHECK_TRUE(rp.navigate());
        CHECK_GE(rp.b.requests_.size(), size_t{1});
        CHECK_EQ(headerValueIn(rp.b.requests_[0], "Referer"),
                 "http://127.0.0.1:" + std::to_string(rp.a.port()));
    }
    // Referrer-Policy: no-referrer -> later hops get nothing.
    {
        RedirectPair rp;
        CHECK_TRUE(rp.start("no-referrer"));
        CHECK_TRUE(rp.navigate());
        CHECK_GE(rp.b.requests_.size(), size_t{1});
        CHECK_EQ(headerValueIn(rp.b.requests_[0], "Referer"), std::string(""));
    }
    // unsafe-url opts into the FULL previous-hop URL even cross-origin.
    {
        RedirectPair rp;
        CHECK_TRUE(rp.start("unsafe-url"));
        CHECK_TRUE(rp.navigate("/deep/path?q=1"));
        CHECK_GE(rp.b.requests_.size(), size_t{1});
        CHECK_EQ(headerValueIn(rp.b.requests_[0], "Referer"),
                 "http://127.0.0.1:" + std::to_string(rp.a.port()) + "/deep/path?q=1");
    }
    // Mixed list: the LAST KNOWN token wins ("banana"/"choco" are noise).
    {
        RedirectPair rp;
        CHECK_TRUE(rp.start("banana, no-referrer, choco"));
        CHECK_TRUE(rp.navigate());
        CHECK_GE(rp.b.requests_.size(), size_t{1});
        CHECK_EQ(headerValueIn(rp.b.requests_[0], "Referer"), std::string(""));
    }
    // Unknown-only header: default policy survives untouched.
    {
        RedirectPair rp;
        CHECK_TRUE(rp.start("banana"));
        CHECK_TRUE(rp.navigate());
        CHECK_GE(rp.b.requests_.size(), size_t{1});
        CHECK_EQ(headerValueIn(rp.b.requests_[0], "Referer"),
                 "http://127.0.0.1:" + std::to_string(rp.a.port()));
    }
}

LETHE_TEST_CASE(ReferrerPolicy_ClientDefaultAndRequestOverride) {
    HygieneServer srv;
    CHECK_TRUE(srv.start());
    const std::string base = "http://127.0.0.1:" + std::to_string(srv.port());

    // Client-wide default: never send a referrer at all.
    {
        HttpClient client = makeClient();
        client.setDefaultReferrerPolicy(ReferrerPolicy::NoReferrer);
        HttpRequest req;
        req.url = base + "/t";
        req.referrer = base + "/from";
        CHECK_TRUE(client.sendRequest(req).success);
        CHECK_EQ(headerValueIn(srv.requests_[0], "Referer"), std::string(""));
    }
    // Per-request override beats the client default; Origin sends the
    // bare origin even same-origin.
    {
        HttpClient client = makeClient();
        HttpRequest req;
        req.url = base + "/t";
        req.referrer = base + "/from/page";
        req.referrerPolicy = ReferrerPolicy::Origin;
        CHECK_TRUE(client.sendRequest(req).success);
        CHECK_EQ(headerValueIn(srv.requests_[1], "Referer"), base);
    }
}

// --- Scheme allowlist ---------------------------------------------------------

LETHE_TEST_CASE(SchemeAllowlist_BlocksNonHttpSchemesBeforeAnyIo) {
    HygieneServer srv;
    CHECK_TRUE(srv.start());
    HttpClient client = makeClient();
    const std::string base = "http://127.0.0.1:" + std::to_string(srv.port());

    const char* blocked[] = {
        "ftp://127.0.0.1/file",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "data:text/html,<h1>hi</h1>",
        "ws://127.0.0.1/socket",
    };
    for (const char* url : blocked) {
        HttpRequest req;
        req.url = url;
        const HttpResponse resp = client.sendRequest(req);
        CHECK_FALSE(resp.success);
        CHECK_TRUE(resp.error.find("scheme") != std::string::npos);
    }
    // A URL with no scheme at all is equally refused - guessing "http"
    // would put plaintext requests on paths nobody asked for.
    {
        HttpRequest req;
        req.url = "noscheme.example.invalid/path";
        const HttpResponse resp = client.sendRequest(req);
        CHECK_FALSE(resp.success);
        CHECK_TRUE(resp.error.find("scheme") != std::string::npos);
    }
    // Nothing above may have touched the network.
    CHECK_EQ(srv.requests_.size(), size_t{0});

    // Sanity: the allowlisted schemes still work.
    HttpRequest ok;
    ok.url = base + "/fine";
    CHECK_TRUE(client.sendRequest(ok).success);
    CHECK_EQ(srv.requests_.size(), size_t{1});
}

LETHE_TEST_CASE(SchemeAllowlist_RedirectTargetsAreCheckedToo) {
    HygieneServer a;
    CHECK_TRUE(a.start());
    a.setHandler([](const std::string&) {
        return httpResponse(302, "Found", "",
                            {{"Location", "ftp://evil.example/payload"}});
    });
    HttpClient client = makeClient();
    HttpRequest req;
    req.url = "http://127.0.0.1:" + std::to_string(a.port()) + "/hop1";
    req.navigationRequest = true;
    const HttpResponse resp = client.sendRequest(req);
    CHECK_FALSE(resp.success);
    CHECK_TRUE(resp.error.find("ftp") != std::string::npos);
    // Exactly one request hit the wire: the redirect itself was refused
    // before any connection attempt.
    CHECK_EQ(a.requests_.size(), size_t{1});
}
