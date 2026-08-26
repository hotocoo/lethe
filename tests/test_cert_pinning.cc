// test_cert_pinning.cc — Per-host certificate pinning (SPKI SHA-256).
//
// Unit coverage: pin spelling parse/format, strict host matching, OR
// semantics across multiple pins, malformed-pin rejection.
//
// E2E coverage: real TLS 1.3 origins whose certificates chain to a test
// CA (verification ON), resolved through mock DoH. A correct leaf pin
// admits the connection; any other digest fails closed BEFORE the HTTP
// request is sent (origins count zero requests); pins re-arm on every
// redirect hop by that hop's own host name.

#include "test_framework.h"
#include "security/cert_pinner.h"
#include "network/http_client.h"
#include "network/tls_config.h"

using namespace lethe;

#include <atomic>
#include <cstring>
#include <string>
#include <thread>

#ifdef HAVE_OPENSSL
#include "test_tls_helpers.h"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

namespace {

using lethe::CertPinner;

// ---- Minimal plain-HTTP server for the mock DoH provider -----------------
class MockHttpServer {
public:
    using Handler = std::function<std::string(const std::string&)>;

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
            return false;
        }
        socklen_t len = sizeof(addr);
        ::getsockname(listenFd_, reinterpret_cast<sockaddr*>(&addr), &len);
        port_ = ntohs(addr.sin_port);
        thread_ = std::thread([this]() { runLoop(); });
        return true;
    }

    int port() const { return port_; }

    ~MockHttpServer() {
        running_ = false;
        if (listenFd_ >= 0) {
            ::shutdown(listenFd_, SHUT_RDWR);
            ::close(listenFd_);
        }
        if (thread_.joinable()) thread_.join();
    }

    Handler handler_;

private:
    void runLoop() {
        while (running_.load()) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(listenFd_, &rfds);
            timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 100000;
            if (::select(listenFd_ + 1, &rfds, nullptr, nullptr, &tv) <= 0) continue;
            const int fd = ::accept(listenFd_, nullptr, nullptr);
            if (fd < 0) continue;
            std::string req;
            char buf[4096];
            while (req.find("\r\n\r\n") == std::string::npos) {
                const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
                if (n <= 0) break;
                req.append(buf, static_cast<size_t>(n));
            }
            const std::string resp = handler_(req);
            ::send(fd, resp.data(), resp.size(), 0);
            ::shutdown(fd, SHUT_WR);
            ::close(fd);
        }
    }

    int listenFd_ = -1;
    int port_ = 0;
    std::atomic<bool> running_{true};
    std::thread thread_;
};

std::string httpResponse(int status, const std::string& statusText,
                         const std::string& body,
                         const std::vector<std::pair<std::string, std::string>>& extraHeaders = {}) {
    std::string head = "HTTP/1.1 " + std::to_string(status) + " " + statusText +
                       "\r\nContent-Length: " + std::to_string(body.size()) +
                       "\r\nConnection: close\r\n";
    for (const auto& [k, v] : extraHeaders) {
        head += k + ": " + v + "\r\n";
    }
    return head + "\r\n" + body;
}

// SPKI SHA-256 of the certificate in \p certPem, spelled as a pin.
bool spkiPinFromCertPem(const std::string& certPem, CertPinner::Digest& out) {
    BIO* bio = BIO_new_mem_buf(certPem.data(), static_cast<int>(certPem.size()));
    X509* x = PEM_read_bio_X509(bio, nullptr, nullptr, nullptr);
    BIO_free(bio);
    if (!x) return false;
    X509_PUBKEY* pk = X509_get_X509_PUBKEY(x);
    bool ok = false;
    if (pk) {
        unsigned char* der = nullptr;
        const int len = i2d_X509_PUBKEY(pk, &der);
        if (len > 0 && der) {
            unsigned int mdLen = 0;
            ok = EVP_Digest(der, static_cast<size_t>(len), out.data(), &mdLen,
                            EVP_sha256(), nullptr) == 1 &&
                 mdLen == CertPinner::kDigestSize;
            OPENSSL_free(der);
        }
    }
    X509_free(x);
    return ok;
}

// One pinned TLS origin: test-CA-signed cert for \p dnsName served from a
// loopback TLS server, plus a GET counter of COMPLETE requests.
struct TlsOrigin {
    tls_test::LoopbackTlsServer server;
    std::string host;                    // e.g. "pin-a.test"
    std::string certPem;
    std::atomic<int> completeRequests{0};

    bool start(const std::string& caPem, const std::string& caKey,
               const std::string& dnsName) {
        host = dnsName;
        if (!tls_test::generateServerCert(caPem, caKey, dnsName,
                                          certPem, keyPem)) {
            return false;
        }
        server.setHandler([this](const std::string& req) {
            if (req.rfind("GET ", 0) == 0 || req.rfind("POST ", 0) == 0) {
                ++completeRequests;
            }
            return httpResponse(200, "OK", "<html>pin-origin-" + host +
                                    "</html>",
                                {{"Content-Type", "text/html"}});
        });
        return server.start(certPem, keyPem);
    }

    std::string url(const std::string& path) const {
        return "https://" + host + ":" + std::to_string(server.port()) + path;
    }

private:
    std::string keyPem;
};

// Mock DoH provider answering every name with 127.0.0.1.
struct MockDoh {
    MockHttpServer server;
    std::string url;

    bool start() {
        server.handler_ = [](const std::string& req) {
            const size_t q = req.find("dns-query?name=");
            if (q == std::string::npos) {
                return httpResponse(404, "Not Found", "");
            }
            size_t begin = q + strlen("dns-query?name=");
            const size_t end = req.find_first_of(" &", begin);
            const std::string name = req.substr(begin, end - begin);
            // Test labels are plain, so no URL-decoding is needed; the
            // client scans for the first IPv4-shaped "data" value.
            return httpResponse(200, "OK",
                "{\"Status\":0,\"Answer\":[{\"name\":\"" + name +
                "\",\"type\":1,\"data\":\"127.0.0.1\"}]}");
        };
        if (!server.start()) return "";
        url = "http://127.0.0.1:" + std::to_string(server.port()) + "/dns-query";
        return true;
    }
};

// HttpClient wired to the mock resolver and trusting ONLY the test CA.
HttpClient makeVerifiedClient(const std::string& dohUrl,
                              const std::string& caBundlePath) {
    TLSConfig tls;
    tls.init_modern_tls_config(0x0304, 0x0305);
    tls.setCaBundlePath(caBundlePath); // verification stays fully on
    HttpClient client;
    if (!client.initialize(tls)) {
        throw lethe::test::TestFailure("HttpClient::initialize failed");
    }
    client.setDohProvider(dohUrl);
    return client;
}

struct PinRig {
    std::string caPem, caKey, caPath;
    MockDoh doh;
    TlsOrigin a; // pin-a.test
    TlsOrigin b; // pin-b.test

    bool start() {
        if (!tls_test::generateTestCa(caPem, caKey)) return false;
        caPath = tls_test::writeTempFile("lethe_pin_ca", caPem);
        if (caPath.empty()) return false;
        if (!doh.start()) return false;
        if (!a.start(caPem, caKey, "pin-a.test")) return false;
        if (!b.start(caPem, caKey, "pin-b.test")) return false;
        return true;
    }

    CertPinner::Digest pinOf(const TlsOrigin& o) const {
        CertPinner::Digest d{};
        const bool ok = spkiPinFromCertPem(o.certPem, d);
        if (!ok) throw lethe::test::TestFailure("spkiPinFromCertPem failed");
        return d;
    }
};

} // namespace

// ---- E2E ----------------------------------------------------------------

LETHE_TEST_CASE(CertPin_E2E_CorrectLeafPinAllowsVerifiedTls) {
    PinRig rig;
    CHECK_TRUE(rig.start());

    CertPinner pinner;
    CHECK_TRUE(pinner.addPin("pin-a.test",
                             CertPinner::formatPin(rig.pinOf(rig.a))));

    HttpClient client = makeVerifiedClient(rig.doh.url, rig.caPath);
    client.enableCertPinning(&pinner);

    HttpRequest req;
    req.url = rig.a.url("/");
    HttpResponse resp = client.sendRequest(req);

    CHECK_TRUE(resp.success);
    CHECK_EQ(resp.statusCode, 200);
    CHECK_EQ(rig.a.completeRequests.load(), 1);
    std::string body(resp.body.begin(), resp.body.end());
    CHECK_TRUE(body.find("pin-origin-pin-a.test") != std::string::npos);

    client.shutdown();
}

LETHE_TEST_CASE(CertPin_E2E_WrongPinFailsClosedBeforeRequest) {
    PinRig rig;
    CHECK_TRUE(rig.start());

    CertPinner pinner;
    // A validly spelled pin that matches nothing in the peer chain.
    CertPinner::Digest bogus{};
    for (size_t i = 0; i < bogus.size(); ++i) bogus[i] = static_cast<uint8_t>(i * 7 + 1);
    CHECK_TRUE(pinner.addPin("pin-a.test", CertPinner::formatPin(bogus)));

    HttpClient client = makeVerifiedClient(rig.doh.url, rig.caPath);
    client.enableCertPinning(&pinner);

    HttpRequest req;
    req.url = rig.a.url("/secret");
    HttpResponse resp = client.sendRequest(req);

    CHECK_FALSE(resp.success);
    CHECK_TRUE(resp.error.find("certificate pin mismatch") != std::string::npos);
    // Fail-closed proof: the origin never received an HTTP request.
    CHECK_EQ(rig.a.completeRequests.load(), 0);

    client.shutdown();
}

LETHE_TEST_CASE(CertPin_E2E_UnpinnedHostKeepsWorking) {
    PinRig rig;
    CHECK_TRUE(rig.start());

    HttpClient client = makeVerifiedClient(rig.doh.url, rig.caPath);

    HttpRequest req;
    req.url = rig.a.url("/");
    HttpResponse resp = client.sendRequest(req);

    CHECK_TRUE(resp.success);
    CHECK_EQ(resp.statusCode, 200);
    CHECK_EQ(rig.a.completeRequests.load(), 1);

    client.shutdown();
}

LETHE_TEST_CASE(CertPin_E2E_AnyOfMultiplePinsSatisfies) {
    PinRig rig;
    CHECK_TRUE(rig.start());

    CertPinner pinner;
    CertPinner::Digest bogus{};
    for (size_t i = 0; i < bogus.size(); ++i) bogus[i] = static_cast<uint8_t>(0xF0 ^ i);
    CHECK_TRUE(pinner.addPin("pin-a.test", CertPinner::formatPin(bogus)));
    CHECK_TRUE(pinner.addPin("pin-a.test",
                             CertPinner::formatPin(rig.pinOf(rig.a))));

    HttpClient client = makeVerifiedClient(rig.doh.url, rig.caPath);
    client.enableCertPinning(&pinner);

    HttpRequest req;
    req.url = rig.a.url("/");
    HttpResponse resp = client.sendRequest(req);

    CHECK_TRUE(resp.success); // second pin matched
    CHECK_EQ(rig.a.completeRequests.load(), 1);

    client.shutdown();
}

LETHE_TEST_CASE(CertPin_E2E_RedirectHopRePinnedFailsClosed) {
    PinRig rig;
    CHECK_TRUE(rig.start());

    // Origin A serves a redirect to B. Both hops are verified TLS with
    // correct chain-of-trust - only the PIN policy differs per host.
    rig.a.server.setHandler([&rig](const std::string& req) {
        if (req.rfind("GET ", 0) == 0) ++rig.a.completeRequests;
        return httpResponse(301, "Moved Permanently", "",
                            {{"Location", rig.b.url("/final")}});
    });

    CertPinner pinner;
    CHECK_TRUE(pinner.addPin("pin-a.test",
                             CertPinner::formatPin(rig.pinOf(rig.a))));
    CertPinner::Digest bogus{};
    for (size_t i = 0; i < bogus.size(); ++i) bogus[i] = static_cast<uint8_t>(i + 0x40);
    CHECK_TRUE(pinner.addPin("pin-b.test", CertPinner::formatPin(bogus)));

    HttpClient client = makeVerifiedClient(rig.doh.url, rig.caPath);
    client.enableCertPinning(&pinner);

    HttpRequest req;
    req.navigationRequest = true;
    req.url = rig.a.url("/jump");
    HttpResponse resp = client.sendRequest(req);

    CHECK_FALSE(resp.success);
    CHECK_TRUE(resp.error.find("pin-b.test") != std::string::npos);
    CHECK_EQ(rig.a.completeRequests.load(), 1); // first hop happened
    CHECK_EQ(rig.b.completeRequests.load(), 0); // second hop never sent

    client.shutdown();
}

LETHE_TEST_CASE(CertPin_E2E_RedirectWithBothHostsCorrectlyPinnedSucceeds) {
    PinRig rig;
    CHECK_TRUE(rig.start());

    rig.a.server.setHandler([&rig](const std::string& req) {
        if (req.rfind("GET ", 0) == 0) ++rig.a.completeRequests;
        return httpResponse(301, "Moved Permanently", "",
                            {{"Location", rig.b.url("/final")}});
    });

    CertPinner pinner;
    CHECK_TRUE(pinner.addPin("pin-a.test",
                             CertPinner::formatPin(rig.pinOf(rig.a))));
    CHECK_TRUE(pinner.addPin("PIN-B.TEST", // host normalization on the way in
                             CertPinner::formatPin(rig.pinOf(rig.b))));

    HttpClient client = makeVerifiedClient(rig.doh.url, rig.caPath);
    client.enableCertPinning(&pinner);

    HttpRequest req;
    req.navigationRequest = true;
    req.url = rig.a.url("/jump");
    HttpResponse resp = client.sendRequest(req);

    CHECK_TRUE(resp.success);
    CHECK_EQ(resp.statusCode, 200);
    CHECK_TRUE(resp.finalUrl.find("pin-b.test") != std::string::npos);
    CHECK_EQ(rig.a.completeRequests.load(), 1);
    CHECK_EQ(rig.b.completeRequests.load(), 1);

    client.shutdown();
}

#endif // HAVE_OPENSSL

// ---- Unit tests (no OpenSSL required) ------------------------------------

using Digest = lethe::CertPinner::Digest;

Digest digestOfPattern(uint8_t seed) {
    Digest d{};
    for (size_t i = 0; i < d.size(); ++i) {
        d[i] = static_cast<uint8_t>(seed + i * 13);
    }
    return d;
}

LETHE_TEST_CASE(CertPin_FormatParseRoundTrip) {
    const Digest original = digestOfPattern(3);
    const std::string pin = lethe::CertPinner::formatPin(original);
    CHECK_EQ(pin.size(), static_cast<size_t>(7 + 44)); // "sha256-" + base64(32)
    CHECK_EQ(pin.substr(0, 7), "sha256-");

    Digest parsed{};
    CHECK_TRUE(lethe::CertPinner::parsePin(pin, parsed));
    CHECK(parsed == original);
}

LETHE_TEST_CASE(CertPin_ParseAcceptsUnpaddedAndPaddedBase64) {
    const Digest original = digestOfPattern(9);
    const std::string padded = lethe::CertPinner::formatPin(original);
    // 32 bytes -> ceil(32/3)*4 = 44 base64 chars; canonical padding ends
    // in exactly one '='. Strip it to get the unpadded spelling.
    CHECK_EQ(padded.back(), '=');
    std::string unpadded = padded;
    while (!unpadded.empty() && unpadded.back() == '=') unpadded.pop_back();

    Digest fromPadded{}, fromUnpadded{};
    CHECK_TRUE(lethe::CertPinner::parsePin(padded, fromPadded));
    CHECK_TRUE(lethe::CertPinner::parsePin(unpadded, fromUnpadded));
    CHECK(fromPadded == original);
    CHECK(fromUnpadded == original);
}

LETHE_TEST_CASE(CertPin_ParseRejectsMalformed) {
    Digest out{};
    CHECK_FALSE(lethe::CertPinner::parsePin("", out));
    CHECK_FALSE(lethe::CertPinner::parsePin("sha256-", out));
    CHECK_FALSE(lethe::CertPinner::parsePin("md5-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", out));
    CHECK_FALSE(lethe::CertPinner::parsePin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", out)); // no prefix
    CHECK_FALSE(lethe::CertPinner::parsePin("sha256-not!!base64@@@@@@@@@@@@@@@@@@@@", out));
    // Decodes to 31 bytes:
    CHECK_FALSE(lethe::CertPinner::parsePin("sha256-MzY1NjQ3ODlhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eg==", out));
}

LETHE_TEST_CASE(CertPin_HostMatchingIsCaseInsensitiveAndExact) {
    lethe::CertPinner pinner;
    const Digest good = digestOfPattern(1);
    CHECK_TRUE(pinner.addPin("Example.COM", lethe::CertPinner::formatPin(good)));

    CHECK_TRUE(pinner.hasPins("example.com"));
    CHECK_TRUE(pinner.hasPins("EXAMPLE.com"));
    CHECK_FALSE(pinner.hasPins("other.example.com")); // exact hosts only
    CHECK_FALSE(pinner.hasPins("example.org"));

    CHECK_TRUE(pinner.matchesAny("EXAMPLE.COM", good));
    CHECK_FALSE(pinner.matchesAny("example.com", digestOfPattern(2)));
    CHECK_FALSE(pinner.matchesAny("unpinned.test", good)); // strict: no match
}

LETHE_TEST_CASE(CertPin_MultiplePinsUseOrSemantics) {
    lethe::CertPinner pinner;
    const Digest leaf = digestOfPattern(10);
    const Digest intermediate = digestOfPattern(20);
    const Digest stranger = digestOfPattern(30);

    pinner.addPinDigest("site.test", leaf);
    pinner.addPinDigest("site.test", intermediate);

    CHECK_TRUE(pinner.hasPins("site.test"));
    CHECK_TRUE(pinner.matchesAny("site.test", leaf));
    CHECK_TRUE(pinner.matchesAny("site.test", intermediate));
    CHECK_FALSE(pinner.matchesAny("site.test", stranger));
    CHECK_EQ(pinner.hostCount(), static_cast<size_t>(1));
    CHECK_EQ(pinner.pinCount(), static_cast<size_t>(2));
}

LETHE_TEST_CASE(CertPin_AddPinRejectsGarbageWithoutStoring) {
    lethe::CertPinner pinner;
    CHECK_FALSE(pinner.addPin("site.test", "garbage"));
    CHECK_FALSE(pinner.addPin("", lethe::CertPinner::formatPin(digestOfPattern(5))));
    CHECK_FALSE(pinner.hasPins("site.test"));
    CHECK_EQ(pinner.pinCount(), static_cast<size_t>(0));
}
