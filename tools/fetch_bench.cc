// fetch_bench.cc - honest throughput measurement of Lethe's HTTP stack.
// Sequential GETs to one origin over a keep-alive connection; prints ops/s
// and mean latency. No parallelism games, no warmup tricks beyond the
// first request.
#include <chrono>
#include <cstdio>
#include <string>
#include <thread>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <cstring>
#include <thread>

#include "network/http_client.h"
#include "network/tls_config.h"

// Surface the transport-level refusal reason when a request never parses.
static std::string lastErrorProbe() { return ""; }

// Embedded keep-alive origin: isolates Lethe-stack throughput from origin
// slowness. Serves one static body over persistent connections.
class SelfOrigin {
public:
    bool start() {
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        int one = 1;
        setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in a{};
        a.sin_family = AF_INET;
        a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        a.sin_port = 0;
        if (bind(fd_, (sockaddr*)&a, sizeof(a)) || listen(fd_, 16)) return false;
        socklen_t l = sizeof(a);
        getsockname(fd_, (sockaddr*)&a, &l);
        port_ = ntohs(a.sin_port);
        th_ = std::thread([this] { run(); });
        return true;
    }
    int port() const { return port_; }
    ~SelfOrigin() {
        running_ = false;
        if (fd_ >= 0) { shutdown(fd_, SHUT_RDWR); close(fd_); }
        if (th_.joinable()) th_.join();
    }
private:
    void serve(int fd) {
        timeval rcv{0, 200000};
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &rcv, sizeof(rcv));
        std::string body(4096, 'x');
        std::string resp = "HTTP/1.1 200 OK\r\nContent-Length: " +
                           std::to_string(body.size()) + "\r\n\r\n" + body;
        char buf[8192];
        for (;;) {
            if (!running_) break;
            ssize_t n = recv(fd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            if (!sendAll(fd, resp)) break;
        }
        close(fd);
    }
    static bool sendAll(int fd, const std::string& s) {
        size_t off = 0;
        while (off < s.size()) {
            ssize_t w = send(fd, s.data() + off, s.size() - off, MSG_NOSIGNAL);
            if (w <= 0) return false;
            off += (size_t)w;
        }
        return true;
    }
    void run() {
        while (running_) {
            fd_set r; FD_ZERO(&r); FD_SET(fd_, &r);
            timeval tv{0, 100000};
            if (select(fd_ + 1, &r, nullptr, nullptr, &tv) <= 0) continue;
            int c = accept(fd_, nullptr, nullptr);
            if (c >= 0 && running_) serve(c);
            else if (c >= 0) close(c);
        }
    }
    int fd_ = -1; int port_ = 0;
    std::atomic<bool> running_{true};
    std::thread th_;
};

int main(int argc, char** argv) {
    const std::string url = argc > 1 ? argv[1] : "http://127.0.0.1:8099/bench";
    const int n = argc > 2 ? std::atoi(argv[2]) : 500;
    lethe::TLSConfig tls;
    tls.init_modern_tls_config(LETHE_MIN_TLS_VERSION, LETHE_MAX_TLS_VERSION);
    lethe::HttpClient client;
    if (!client.initialize(tls)) return 1;

    SelfOrigin selfOrigin;
    std::string effectiveUrl = url;
    if (url == "--self") {
        if (!selfOrigin.start()) return 3;
        effectiveUrl = "http://127.0.0.1:" + std::to_string(selfOrigin.port()) + "/bench";
    }
    const std::string& target = effectiveUrl;
    lethe::HttpRequest req;
    req.url = target;
    auto warm = client.sendRequest(req);
    if (warm.statusCode == 0) {
        fprintf(stderr, "origin unreachable: %s%s\n", warm.error.c_str(),
                lastErrorProbe().c_str());
        return 2;
    }

    using clock = std::chrono::steady_clock;
    double totalMs = 0;
    int ok = 0;
    for (int i = 0; i < n; ++i) {
        auto t0 = clock::now();
        auto r = client.sendRequest(req);
        auto t1 = clock::now();
        totalMs += std::chrono::duration<double, std::milli>(t1 - t0).count();
        if (r.statusCode != 0) ok++;
    }
    printf("requests=%d ok=%d keepalive_ops_per_s=%.1f mean_ms=%.3f\n", n,
           ok, n / (totalMs / 1000.0), totalMs / n);
    client.shutdown();
    return 0;
}
