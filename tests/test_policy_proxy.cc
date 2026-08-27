// test_policy_proxy.cc - security coverage for the local policy-enforcing
// proxy that carries embedded full-web engine traffic. Every refusal must
// fail CLOSED with a named reason; every allowed path must still run the
// full request-path pipeline (DoH-only resolution, private-net guard,
// VPN routing, verified TLS).

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <thread>

#include "network/policy_proxy.h"
#include "network/vpn/wireguard_cipher.h"
#include "test_framework.h"
#include "test_tls_helpers.h"

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#endif

namespace lethe {
namespace {

// Minimal loopback HTTP origin: one response per connection.
class TinyOrigin {
public:
    bool start(std::string body) {
        body_ = std::move(body);
        listenFd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (listenFd_ < 0) return false;
        int one = 1;
        ::setsockopt(listenFd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (::bind(listenFd_, reinterpret_cast<sockaddr*>(&addr),
                   sizeof(addr)) != 0 ||
            ::listen(listenFd_, 8) != 0)
            return false;
        socklen_t len = sizeof(addr);
        ::getsockname(listenFd_, reinterpret_cast<sockaddr*>(&addr), &len);
        port_ = ntohs(addr.sin_port);
        running_ = true;
        thread_ = std::thread([this] { loop(); });
        return true;
    }
    ~TinyOrigin() {
        running_ = false;
        if (listenFd_ >= 0) {
            ::shutdown(listenFd_, SHUT_RDWR);
            ::close(listenFd_);
        }
        if (thread_.joinable()) thread_.join();
    }
    int port() const { return port_; }
    std::atomic<int> requests{0};

private:
    void loop() {
        while (running_) {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(listenFd_, &rfds);
            timeval tv{0, 100000};
            if (::select(listenFd_ + 1, &rfds, nullptr, nullptr, &tv) <= 0)
                continue;
            int fd = ::accept(listenFd_, nullptr, nullptr);
            if (fd < 0) continue;
            char buf[4096];
            ssize_t n = ::recv(fd, buf, sizeof(buf) - 1, 0);
            if (n > 0) {
                buf[n] = 0;
                lastRequest_ = buf;
                requests.fetch_add(1);
                std::string resp =
                    "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: " +
                    std::to_string(body_.size()) + "\r\n\r\n" + body_;
                ::send(fd, resp.data(), resp.size(), MSG_NOSIGNAL);
            }
            ::close(fd);
        }
    }
    int listenFd_ = -1;
    int port_ = 0;
    std::atomic<bool> running_{false};
    std::thread thread_;
    std::string body_ = "proxy-origin-body";
    std::string lastRequest_;

public:
    const std::string& lastRequest() const { return lastRequest_; }
};

PolicyProxyServer::Options baseOptions(const TLSConfig& tls) {
    PolicyProxyServer::Options o;
    o.tls = tls;
    return o;
}

// Raw loopback client used to talk to the proxy like an embedded engine.
int dial(int port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_port = htons(static_cast<uint16_t>(port));
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
        ::close(fd);
        return -1;
    }
    return fd;
}

std::string readAll(int fd) {
    std::string out;
    char buf[4096];
    for (;;) {
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        out.append(buf, static_cast<size_t>(n));
    }
    return out;
}

} // namespace

LETHE_TEST_CASE(PolicyProxy_ForwardsPlainGetThroughStack) {
    TinyOrigin origin;
    CHECK_TRUE(origin.start("<html>via-proxy</html>"));

    TLSConfig tls;
    tls.init_modern_tls_config(LETHE_MIN_TLS_VERSION, LETHE_MAX_TLS_VERSION);
    PolicyProxyServer proxy;
    CHECK_TRUE(proxy.start(baseOptions(tls)));

    int fd = dial(proxy.port());
    CHECK_GE(fd, 0);
    const std::string req =
        "GET http://127.0.0.1:" + std::to_string(origin.port()) +
        "/page HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    CHECK_TRUE(send(fd, req.data(), (int)req.size(), 0) == (ssize_t)req.size());
    const std::string resp = readAll(fd);
    ::close(fd);
    proxy.stop();

    CHECK_EQ(origin.requests.load(), 1);
    CHECK_TRUE(resp.find("200 OK") != std::string::npos);
    CHECK_TRUE(resp.find("via-proxy") != std::string::npos);
    // Hop-by-hop framing must be re-derived by the proxy, not forwarded.
    CHECK_TRUE(resp.find("Content-Length:") != std::string::npos);
}

LETHE_TEST_CASE(PolicyProxy_RefusesNonHttpSchemes) {
    TinyOrigin origin;
    CHECK_TRUE(origin.start("x"));
    TLSConfig tls;
    tls.init_modern_tls_config(LETHE_MIN_TLS_VERSION, LETHE_MAX_TLS_VERSION);
    PolicyProxyServer proxy;
    CHECK_TRUE(proxy.start(baseOptions(tls)));

    int fd = dial(proxy.port());
    CHECK_GE(fd, 0);
    const std::string req = "GET ftp://127.0.0.1/file HTTP/1.1\r\nHost: x\r\n\r\n";
    CHECK_TRUE(send(fd, req.data(), (int)req.size(), 0) == (ssize_t)req.size());
    const std::string resp = readAll(fd);
    ::close(fd);
    proxy.stop();

    CHECK_TRUE(resp.find("403 Forbidden") != std::string::npos);
    CHECK_TRUE(resp.find("Blocked by Lethe policy") != std::string::npos);
    CHECK_EQ(origin.requests.load(), 0); // nothing ever left the machine
}

LETHE_TEST_CASE(PolicyProxy_RefusesPrivateScopeConnects) {
    TLSConfig tls;
    tls.init_modern_tls_config(LETHE_MIN_TLS_VERSION, LETHE_MAX_TLS_VERSION);
    PolicyProxyServer proxy;
    CHECK_TRUE(proxy.start(baseOptions(tls)));

    int fd = dial(proxy.port());
    CHECK_GE(fd, 0);
    const std::string req =
        "CONNECT 10.9.9.9:443 HTTP/1.1\r\nHost: 10.9.9.9:443\r\n\r\n";
    CHECK_TRUE(send(fd, req.data(), (int)req.size(), 0) == (ssize_t)req.size());
    const std::string resp = readAll(fd);
    ::close(fd);
    proxy.stop();

    CHECK_TRUE(resp.find("403 Forbidden") != std::string::npos);
    CHECK_TRUE(resp.find("Blocked by Lethe policy") != std::string::npos);
}

LETHE_TEST_CASE(PolicyProxy_VpnFailClosedWhileTunnelDown) {
    using vpn::Key;
    // Full-tunnel CIDRs + configured-but-DISCONNECTED tunnel: the CONNECT
    // must be refused before any byte is dialed.
    Key serverPriv{};
    CHECK_TRUE(vpn::generatePrivateKey(serverPriv));
    vpn::VpnTunnel server;
    CHECK_TRUE(server.configureServer(serverPriv));

    vpn::VpnConfig vcfg;
    vcfg.endpointHost = "127.0.0.1";
    vcfg.endpointPort = 51820;
    vcfg.serverPublicKey = server.localPublicKey();
    vcfg.allowedCidrs = {"0.0.0.0/0"};
    vpn::VpnTunnel clientTunnel;
    CHECK_TRUE(clientTunnel.configureClient(vcfg));
    CHECK_FALSE(clientTunnel.isConnected());

    TLSConfig tls;
    tls.init_modern_tls_config(LETHE_MIN_TLS_VERSION, LETHE_MAX_TLS_VERSION);
    PolicyProxyServer::Options o = baseOptions(tls);
    o.vpnTunnel = &clientTunnel;
    PolicyProxyServer proxy;
    CHECK_TRUE(proxy.start(o));

    int fd = dial(proxy.port());
    CHECK_GE(fd, 0);
    const std::string req =
        "CONNECT 93.184.216.34:443 HTTP/1.1\r\nHost: x\r\n\r\n";
    CHECK_TRUE(send(fd, req.data(), (int)req.size(), 0) == (ssize_t)req.size());
    const std::string resp = readAll(fd);
    ::close(fd);
    proxy.stop();

    CHECK_TRUE(resp.find("403 Forbidden") != std::string::npos);
    CHECK_TRUE(resp.find("tunnel is down") != std::string::npos);
}

#ifdef HAVE_OPENSSL
LETHE_TEST_CASE(PolicyProxy_ConnectSplicesVerifiedTls) {
    namespace tt = tls_test;
    // Mock DoH: doc.internal -> 127.0.0.1 so the proxy resolves through the
    // secure path instead of the system resolver.

    std::string caPem, caKey;
    CHECK_TRUE(tt::generateTestCa(caPem, caKey));
    std::string certPem, keyPem;
    CHECK_TRUE(tt::generateServerCert(caPem, caKey, "doc.internal", certPem,
                                      keyPem));
    tt::LoopbackTlsServer origin;
    origin.setHandler([](const std::string&) {
        const std::string b = "tls-through-connect";
        return "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: " +
               std::to_string(b.size()) + "\r\n\r\n" + b;
    });
    CHECK_TRUE(origin.start(certPem, keyPem));

    // Dynamic mock DoH server.
    class DynServer {
    public:
        bool start(std::function<std::string(const std::string&)> h) {
            h_ = std::move(h);
            listenFd_ = ::socket(AF_INET, SOCK_STREAM, 0);
            sockaddr_in a{};
            a.sin_family = AF_INET;
            a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            a.sin_port = 0;
            int one = 1;
            ::setsockopt(listenFd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
            if (::bind(listenFd_, reinterpret_cast<sockaddr*>(&a), sizeof(a)) ||
                ::listen(listenFd_, 8)) return false;
            socklen_t l = sizeof(a);
            ::getsockname(listenFd_, reinterpret_cast<sockaddr*>(&a), &l);
            port_ = ntohs(a.sin_port);
            th_ = std::thread([this] { run(); });
            return true;
        }
        int port() const { return port_; }
        ~DynServer() {
            running_ = false;
            if (listenFd_ >= 0) { ::shutdown(listenFd_, SHUT_RDWR); ::close(listenFd_); }
            if (th_.joinable()) th_.join();
        }
    private:
        void run() {
            for (;;) {
                fd_set r; FD_ZERO(&r); FD_SET(listenFd_, &r);
                timeval tv{0, 100000};
                if (::select(listenFd_ + 1, &r, nullptr, nullptr, &tv) <= 0) {
                    if (!running_.load()) break;
                    continue;
                }
                if (!running_.load()) break;
                int fd = ::accept(listenFd_, nullptr, nullptr);
                if (fd < 0) continue;
                char b[4096]; ssize_t n = ::recv(fd, b, sizeof(b) - 1, 0);
                if (n > 0) {
                    b[n] = 0;
                    std::string body = h_(b);
                    std::string r2 = "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: " +
                        std::to_string(body.size()) + "\r\n\r\n" + body;
                    ::send(fd, r2.data(), r2.size(), MSG_NOSIGNAL);
                }
                ::close(fd);
            }
        }
        int listenFd_ = -1; int port_ = 0;
        std::thread th_;
        std::function<std::string(const std::string&)> h_;
        std::atomic<bool> running_{true};

    };
    DynServer dohDyn;
    CHECK_TRUE(dohDyn.start([](const std::string& req) {
        if (req.find("/dns-query?name=doc.internal") != std::string::npos)
            return std::string(
                "{\"Status\":0,\"Answer\":[{\"name\":\"doc.internal\"," 
                "\"type\":1,\"data\":\"127.0.0.1\"}]}");
        return std::string("{}");
    }));

    TLSConfig tls;
    tls.init_modern_tls_config(LETHE_MIN_TLS_VERSION, LETHE_MAX_TLS_VERSION);
    PolicyProxyServer::Options o = baseOptions(tls);
    o.dohProvider =
        "http://127.0.0.1:" + std::to_string(dohDyn.port()) + "/dns-query";
    PolicyProxyServer proxy;
    CHECK_TRUE(proxy.start(o));

    // CONNECT through the proxy...
    int fd = dial(proxy.port());
    CHECK_GE(fd, 0);
    const std::string target =
        "doc.internal:" + std::to_string(origin.port());
    const std::string req = "CONNECT " + target +
                            " HTTP/1.1\r\nHost: " + target + "\r\n\r\n";
    CHECK_TRUE(send(fd, req.data(), (int)req.size(), 0) == (ssize_t)req.size());
    std::string connectResp;
    char c;
    while (connectResp.find("\r\n\r\n") == std::string::npos &&
           recv(fd, &c, 1, 0) == 1)
        connectResp.push_back(c);
    CHECK_TRUE(connectResp.find("200 Connection Established") !=
               std::string::npos);

    // ...then run a REAL certificate-verified TLS 1.3 handshake through the
    // spliced pipe, trusting ONLY the mini-CA bundle.
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    CHECK_TRUE(ctx != nullptr);
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    const std::string caFile = tt::writeTempFile("lethe_proxy_ca", caPem);
    CHECK_EQ(SSL_CTX_load_verify_locations(ctx, caFile.c_str(), nullptr), 1);
    SSL* ssl = SSL_new(ctx);
    CHECK_TRUE(ssl != nullptr);
    SSL_set_fd(ssl, fd);
    SSL_set_tlsext_host_name(ssl, "doc.internal");
    SSL_set1_host(ssl, "doc.internal");
    X509_VERIFY_PARAM* param = SSL_get0_param(ssl);
    X509_VERIFY_PARAM_set_auth_level(param, 2);
    CHECK_EQ(SSL_connect(ssl), 1);
    CHECK_EQ(SSL_version(ssl), TLS1_3_VERSION);
    const std::string httpReq =
        "GET / HTTP/1.1\r\nHost: doc.internal\r\nConnection: close\r\n\r\n";
    CHECK_EQ(SSL_write(ssl, httpReq.data(), (int)httpReq.size()),
             (int)httpReq.size());
    std::string resp;
    char rb[4096];
    int n;
    while ((n = SSL_read(ssl, rb, sizeof(rb))) > 0)
        resp.append(rb, static_cast<size_t>(n));
    SSL_free(ssl);
    SSL_CTX_free(ctx);
    ::close(fd);
    proxy.stop();

    CHECK_TRUE(resp.find("tls-through-connect") != std::string::npos);
}
#endif // HAVE_OPENSSL



// One HTTP response: head + Content-Length body (the 407 keeps the
// connection open for the authenticated retry, so EOF never comes).
std::string readOneResponse(int fd) {
    std::string out;
    char buf[4096];
    size_t bodyStart = std::string::npos;
    size_t contentLength = 0;
    for (;;) {
        if (bodyStart == std::string::npos) {
            const size_t hdrEnd = out.find("\r\n\r\n");
            if (hdrEnd != std::string::npos) {
                bodyStart = hdrEnd + 4;
                const size_t cl = out.find("Content-Length: ");
                if (cl != std::string::npos && cl < hdrEnd)
                    contentLength = static_cast<size_t>(std::atol(out.c_str() + cl + 16));
            }
        }
        if (bodyStart != std::string::npos && out.size() >= bodyStart + contentLength) break;
        ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n <= 0) break;
        out.append(buf, static_cast<size_t>(n));
    }
    return out;
}

LETHE_TEST_CASE(PolicyProxy_AuthToken_RefusesUnauthenticatedPeers) {
    // With a per-launch token configured the proxy is no longer an open
    // loopback relay: a request without the exact Proxy-Authorization gets
    // 407 and the origin never sees traffic; the right credential passes.
    TinyOrigin origin;
    CHECK_TRUE(origin.start("<html>authed</html>"));
    TLSConfig tls;
    tls.init_modern_tls_config(LETHE_MIN_TLS_VERSION, LETHE_MAX_TLS_VERSION);
    PolicyProxyServer::Options o = baseOptions(tls);
    o.authToken = PolicyProxyServer::generateAuthToken();
    CHECK_EQ(o.authToken.size(), 64u);
    PolicyProxyServer proxy;
    CHECK_TRUE(proxy.start(o));
    const std::string target = "http://127.0.0.1:" + std::to_string(origin.port()) + "/p";

    // 1. No credential.
    int fd = dial(proxy.port());
    CHECK_GE(fd, 0);
    std::string req = "GET " + target + " HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
    CHECK_TRUE(send(fd, req.data(), (int)req.size(), 0) == (ssize_t)req.size());
    std::string resp = readOneResponse(fd);
    CHECK_TRUE(resp.find("407 Proxy Authentication Required") != std::string::npos);
    CHECK_TRUE(resp.find("Proxy-Authenticate: Basic") != std::string::npos);
    CHECK_TRUE(resp.find("Connection: keep-alive") != std::string::npos);
    CHECK_EQ(origin.requests.load(), 0);

    // 2. Wrong credential (same length, one byte off) on the SAME socket -
    //    still refused, connection still open for a real retry.
    std::string wrong = PolicyProxyServer::basicCredentialFor(o.authToken);
    wrong[wrong.size() - 3] = wrong[wrong.size() - 3] == 'A' ? 'B' : 'A';
    req = "CONNECT 127.0.0.1:" + std::to_string(origin.port()) + " HTTP/1.1\r\nHost: x\r\n"
          "Proxy-Authorization: " + wrong + "\r\n\r\n";
    CHECK_TRUE(send(fd, req.data(), (int)req.size(), 0) == (ssize_t)req.size());
    resp = readOneResponse(fd);
    CHECK_TRUE(resp.find("407") != std::string::npos);
    CHECK_EQ(origin.requests.load(), 0);

    // 3. Correct credential (header name case-insensitive), same socket as
    //    the challenge - forwarded. This is the engine's real retry path.
    req = "GET " + target + " HTTP/1.1\r\nHost: 127.0.0.1\r\nproxy-authorization: " +
          PolicyProxyServer::basicCredentialFor(o.authToken) + "\r\n\r\n";
    CHECK_TRUE(send(fd, req.data(), (int)req.size(), 0) == (ssize_t)req.size());
    resp = readAll(fd);
    ::close(fd);

    // 4. A peer that never authenticates is dropped after three tries.
    fd = dial(proxy.port());
    for (int i = 0; i < 3; i++) {
        req = "GET " + target + " HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        CHECK_TRUE(send(fd, req.data(), (int)req.size(), 0) == (ssize_t)req.size());
        std::string r = readOneResponse(fd);
        CHECK_TRUE(r.find("407") != std::string::npos);
        if (i == 2) CHECK_TRUE(r.find("Connection: close") != std::string::npos);
    }
    CHECK_EQ(readAll(fd), std::string());   // server closed
    ::close(fd);
    proxy.stop();
    CHECK_TRUE(resp.find("200 OK") != std::string::npos);
    CHECK_TRUE(resp.find("authed") != std::string::npos);
    CHECK_EQ(origin.requests.load(), 1);
}

} // namespace lethe
