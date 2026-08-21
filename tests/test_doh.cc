// test_doh.cc — DNS-over-HTTPS tests over real loopback sockets
//
// A mock DoH provider runs on loopback and answers the JSON API
// (application/dns-json). Verifies that:
//   - hostname resolution goes through DoH and the connection reaches the
//     resolved IP (a hostname with no DNS record still connects)
//   - a dead DoH provider blocks requests (fail closed, never plaintext DNS)
//   - IP-literal URLs bypass resolution entirely

#include "test_framework.h"
#include "network/http_client.h"
#include "network/tls_config.h"

#include <arpa/inet.h>
#include <cstring>
#include <functional>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace lethe;

namespace {

// Minimal single-connection-at-a-time loopback HTTP server.
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
            ::listen(listenFd_, 8) < 0) {
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
                char buf[4096];
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

std::string httpResponse(int status, const std::string& statusText,
                         const std::string& body) {
    return "HTTP/1.1 " + std::to_string(status) + " " + statusText +
           "\r\nContent-Length: " + std::to_string(body.size()) +
           "\r\nConnection: close\r\n\r\n" + body;
}

HttpClient makeClient(const std::string& dohUrl) {
    TLSConfig tls;
    tls.init_modern_tls_config(0x0304, 0x0305);
    HttpClient client;
    CHECK_TRUE(client.initialize(tls));
    client.setDohProvider(dohUrl);
    return client;
}

} // namespace

LETHE_TEST_CASE(Doh_EndToEnd_HostnameResolvedViaMockProvider) {
    // One server plays two roles: DoH provider (/dns-query) and web origin.
    MockHttpServer server;
    server.handler_ = [](const std::string& req) {
        if (req.find("/dns-query?name=") != std::string::npos) {
            // Cloudflare-style JSON answer: web.internal -> 127.0.0.1
            return httpResponse(200, "OK",
                "{\"Status\":0,\"Answer\":[{\"name\":\"web.internal\","
                "\"type\":5,\"data\":\"alias.example\"},"
                "{\"name\":\"web.internal\",\"type\":1,"
                "\"data\":\"127.0.0.1\"}]}");
        }
        return httpResponse(200, "OK", "<html>doh-origin-ok</html>");
    };
    CHECK_TRUE(server.start());

    HttpClient client = makeClient("http://127.0.0.1:" + std::to_string(server.port()) + "/dns-query");

    HttpRequest req;
    req.url = "http://web.internal:" + std::to_string(server.port()) + "/page";
    HttpResponse resp = client.sendRequest(req);

    // The mock provider mapped web.internal to 127.0.0.1, so despite having
    // no real DNS record the request must reach the origin and succeed.
    CHECK_TRUE(resp.success);
    CHECK_EQ(resp.statusCode, 200);
    std::string body(resp.body.data(), resp.body.size());
    CHECK_TRUE(body.find("doh-origin-ok") != std::string::npos);
}

LETHE_TEST_CASE(Doh_FailClosed_WhenProviderDead) {
    // Provider points at a closed port: lookups fail, so requests to
    // hostnames are BLOCKED rather than falling back to plaintext DNS.
    int closedPort = 1; // nothing listens here
    HttpClient client = makeClient("http://127.0.0.1:" + std::to_string(closedPort) + "/dns-query");

    HttpRequest req;
    req.url = "http://secret.internal:9/";
    HttpResponse resp = client.sendRequest(req);

    CHECK_TRUE(!resp.success);
    CHECK_TRUE(resp.error.find("Blocked") != std::string::npos);
    CHECK_TRUE(resp.error.find("DoH") != std::string::npos);
}

LETHE_TEST_CASE(Doh_IpLiteral_SkipsResolution) {
    // Dead DoH provider, but an IP-literal URL needs no resolution at all.
    MockHttpServer server;
    server.handler_ = [](const std::string&) {
        return httpResponse(200, "OK", "<html>direct-ip</html>");
    };
    CHECK_TRUE(server.start());

    HttpClient client = makeClient("http://127.0.0.1:1/dns-query"); // dead provider

    HttpRequest req;
    req.url = "http://127.0.0.1:" + std::to_string(server.port()) + "/";
    HttpResponse resp = client.sendRequest(req);

    CHECK_TRUE(resp.success);
    CHECK_EQ(resp.statusCode, 200);
}

LETHE_TEST_CASE(Doh_DisabledByDefault_UsesSystemResolution) {
    // No provider configured: behavior unchanged from before DoH existed.
    MockHttpServer server;
    server.handler_ = [](const std::string&) {
        return httpResponse(200, "OK", "<html>plain</html>");
    };
    CHECK_TRUE(server.start());

    TLSConfig tls;
    tls.init_modern_tls_config(0x0304, 0x0305);
    HttpClient client;
    CHECK_TRUE(client.initialize(tls));
    CHECK_TRUE(!client.isDohEnabled());

    HttpRequest req;
    req.url = "http://127.0.0.1:" + std::to_string(server.port()) + "/";
    HttpResponse resp = client.sendRequest(req);
    CHECK_TRUE(resp.success);
}
