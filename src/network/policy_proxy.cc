#include "network/policy_proxy.h"

#include <arpa/inet.h>
#include <atomic>
#include <openssl/rand.h>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>

namespace lethe {

namespace {

constexpr size_t kMaxHeadBytes = 64 * 1024;

std::string forbiddenResponse(const std::string& reason) {
    std::string body = "Blocked by Lethe policy: " + reason + "\n";
    return "HTTP/1.1 403 Forbidden\r\n"
           "Content-Type: text/plain\r\n"
           "Connection: close\r\nContent-Length: " +
           std::to_string(body.size()) + "\r\n\r\n" + body;
}

std::string proxyAuthRequiredResponse(bool keepAlive) {
    const std::string body = "Proxy authentication required (Lethe per-launch token)\n";
    return "HTTP/1.1 407 Proxy Authentication Required\r\n"
           "Proxy-Authenticate: Basic realm=\"Lethe\"\r\n"
           "Content-Type: text/plain\r\n"
           "Connection: " + std::string(keepAlive ? "keep-alive" : "close") +
           "\r\nContent-Length: " +
           std::to_string(body.size()) + "\r\n\r\n" + body;
}

std::string base64Encode(const std::string& in) {
    static const char* tbl =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    size_t i = 0;
    while (i + 2 < in.size()) {
        const unsigned v = (static_cast<unsigned char>(in[i]) << 16) |
                           (static_cast<unsigned char>(in[i + 1]) << 8) |
                           static_cast<unsigned char>(in[i + 2]);
        out += tbl[(v >> 18) & 63]; out += tbl[(v >> 12) & 63];
        out += tbl[(v >> 6) & 63]; out += tbl[v & 63];
        i += 3;
    }
    if (i + 1 == in.size()) {
        const unsigned v = static_cast<unsigned char>(in[i]) << 16;
        out += tbl[(v >> 18) & 63]; out += tbl[(v >> 12) & 63]; out += "==";
    } else if (i + 2 == in.size()) {
        const unsigned v = (static_cast<unsigned char>(in[i]) << 16) |
                           (static_cast<unsigned char>(in[i + 1]) << 8);
        out += tbl[(v >> 18) & 63]; out += tbl[(v >> 12) & 63];
        out += tbl[(v >> 6) & 63]; out += '=';
    }
    return out;
}

// Case-insensitive header lookup in a request head; "" when absent.
std::string headerValue(const std::string& head, const std::string& name) {
    size_t pos = head.find("\r\n");
    while (pos != std::string::npos && pos + 2 < head.size()) {
        const size_t end = head.find("\r\n", pos + 2);
        const std::string line = head.substr(pos + 2, end == std::string::npos ? std::string::npos : end - pos - 2);
        if (line.size() > name.size() + 1 && line[name.size()] == ':') {
            bool match = true;
            for (size_t i = 0; i < name.size(); i++) {
                if (::tolower(static_cast<unsigned char>(line[i])) !=
                    ::tolower(static_cast<unsigned char>(name[i]))) { match = false; break; }
            }
            if (match) {
                size_t v = name.size() + 1;
                while (v < line.size() && (line[v] == ' ' || line[v] == '\t')) v++;
                return line.substr(v);
            }
        }
        pos = end;
    }
    return "";
}

bool sendAll(int fd, const char* p, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = ::send(fd, p + off, n - off, MSG_NOSIGNAL);
        if (w <= 0) return false;
        off += static_cast<size_t>(w);
    }
    return true;
}

// Read until CRLFCRLF or cap. False on EOF/error/oversize.
// Reads in 4KB chunks for efficiency instead of byte-by-byte.
bool readHead(int fd, std::string& out) {
    out.clear();
    char buf[4096];
    while (out.size() < kMaxHeadBytes) {
        ssize_t r = ::recv(fd, buf, sizeof(buf), 0);
        if (r <= 0) return false;
        out.append(buf, static_cast<size_t>(r));
        // Check for CRLFCRLF at the end
        if (out.size() >= 4 &&
            out.compare(out.size() - 4, 4, "\r\n\r\n") == 0)
            return true;
        // Also check if CRLFCRLF appears in the middle (in case we read past it)
        size_t pos = out.find("\r\n\r\n");
        if (pos != std::string::npos) {
            out.resize(pos + 4);
            return true;
        }
    }
    return false;
}

} // namespace

PolicyProxyServer::~PolicyProxyServer() { stop(); }

std::string PolicyProxyServer::generateAuthToken() {
    unsigned char raw[32];
    if (RAND_bytes(raw, sizeof(raw)) != 1) return "";
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(64);
    for (unsigned char b : raw) { out += hex[b >> 4]; out += hex[b & 15]; }
    return out;
}

std::string PolicyProxyServer::basicCredentialFor(const std::string& token) {
    return "Basic " + base64Encode("lethe:" + token);
}

bool PolicyProxyServer::start(const Options& options) {
    opts_ = options;
    listenFd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (listenFd_ < 0) {
        lastError_ = "socket() failed";
        return false;
    }
    int one = 1;
    ::setsockopt(listenFd_, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(opts_.bindPort));
    if (::inet_pton(AF_INET, opts_.bindHost.c_str(), &addr.sin_addr) != 1) {
        lastError_ = "invalid bind host";
        ::close(listenFd_);
        listenFd_ = -1;
        return false;
    }
    if (::bind(listenFd_, reinterpret_cast<sockaddr*>(&addr),
               sizeof(addr)) != 0 ||
        ::listen(listenFd_, 16) != 0) {
        lastError_ = "bind/listen failed";
        ::close(listenFd_);
        listenFd_ = -1;
        return false;
    }
    socklen_t len = sizeof(addr);
    ::getsockname(listenFd_, reinterpret_cast<sockaddr*>(&addr), &len);
    port_ = ntohs(addr.sin_port);
    if (!opts_.dohCache) opts_.dohCache = std::make_shared<SharedDohCache>();
    if (!opts_.dohResolver && !opts_.dohProvider.empty() && !opts_.disableDohResolverPool) {
        const TLSConfig tls = opts_.tls;
        const std::string provider = opts_.dohProvider;
        auto cache = opts_.dohCache;
        opts_.dohResolver = std::make_shared<SharedDohResolver>([tls, provider, cache]() {
            auto c = std::make_unique<HttpClient>();
            c->initialize(tls);
            c->setDohProvider(provider);
            c->setSharedDohCache(cache);
            return c;
        });
    }
    // -- v0.1.1 perf: fixed worker pool --------------------------------
    // The previous design detached a fresh std::thread per connection. With
    // a busy page (50+ parallel subresources) the cost of a pthread + an
    // 8 MiB stack per request dominated TTFB. A small pool sized to the
    // box's hardware_concurrency keeps the cache hot and avoids the churn.
    workerCount_ = opts_.workerThreads;
    if (workerCount_ == 0) {
        unsigned hc = std::thread::hardware_concurrency();
        workerCount_ = hc == 0 ? 8 : (hc < 4 ? 4 : hc);
    }
    // Cap at a sane number: each worker is a real thread. Past ~32 the
    // scheduler itself becomes the bottleneck.
    if (workerCount_ > 32) workerCount_ = 32;
    workers_.reserve(workerCount_);
    for (size_t i = 0; i < workerCount_; ++i) {
        workers_.emplace_back([this] { workerLoop(); });
    }
    std::cout << "[lethe-proxy] worker pool: " << workerCount_ << " threads"
              << std::endl;
    running_ = true;
    acceptThread_ = std::thread([this] { acceptLoop(); });
    return true;
}

void PolicyProxyServer::trackFd(int fd) {
    std::lock_guard<std::mutex> lk(activeFds_mtx_);
    activeFds_.insert(fd);
}

void PolicyProxyServer::untrackFd(int fd) {
    std::lock_guard<std::mutex> lk(activeFds_mtx_);
    activeFds_.erase(fd);
}

void PolicyProxyServer::stop() {
    if (!running_.exchange(false)) return;
    // Tell in-flight handlers to bail and close their sockets so any worker
    // stuck in recv()/read()/splice wakes up and returns to the pool. Without
    // this, quit() blocks on the worker join for as long as a live tunnel
    // stays open (the reported "only force-quit works" bug).
    stopping_.store(true, std::memory_order_relaxed);
    {
        std::lock_guard<std::mutex> lk(activeFds_mtx_);
        for (int fd : activeFds_) {
            ::shutdown(fd, SHUT_RDWR);
            ::close(fd);
        }
        activeFds_.clear();
    }
    if (listenFd_ >= 0) {
        ::shutdown(listenFd_, SHUT_RDWR);
        ::close(listenFd_);
        listenFd_ = -1;
    }
    if (acceptThread_.joinable()) acceptThread_.join();
    // Wake all workers and tell them to drain. A sentinel -1 fd tells them
    // to exit once the queue is empty (we still close any real fds the
    // workers were handling).
    {
        std::lock_guard<std::mutex> lk(queue_mtx_);
        running_.store(false);
        for (size_t i = 0; i < workers_.size(); ++i) queue_.push_back(-1);
    }
    queue_cv_.notify_all();
    for (auto& t : workers_) if (t.joinable()) t.join();
    workers_.clear();
}

void PolicyProxyServer::acceptLoop() {
    while (running_) {
        int fd = ::accept(listenFd_, nullptr, nullptr);
        if (fd < 0) break;
        {
            std::lock_guard<std::mutex> lk(queue_mtx_);
            queue_.push_back(fd);
        }
        queue_cv_.notify_one();
    }
}

void PolicyProxyServer::workerLoop() {
    for (;;) {
        int fd;
        {
            std::unique_lock<std::mutex> lk(queue_mtx_);
            queue_cv_.wait(lk, [&] { return !queue_.empty(); });
            fd = queue_.front();
            queue_.pop_front();
        }
        if (fd == -1) return;  // sentinel: shutdown
        serveConnection(fd);
    }
}

HttpClient::PolicyDialConfig PolicyProxyServer::dialConfig() const {
    HttpClient::PolicyDialConfig cfg;
    cfg.tls = opts_.tls;
    cfg.dohProvider = opts_.dohProvider;
    cfg.dohCache = opts_.dohCache;
    cfg.dohResolver = opts_.dohResolver;
    cfg.privateNet = opts_.privateNet;
    cfg.vpnTunnel = opts_.vpnTunnel;
    cfg.vpnUdp = static_cast<UdpTransport*>(opts_.udpTransport);
    cfg.relayEndpointHost = opts_.relayHost;
    cfg.relayEndpointPort = opts_.relayPort;
    return cfg;
}

void PolicyProxyServer::serveConnection(int clientFd) {
    // RAII: keep this fd in the active set for its whole lifetime so stop()
    // can close it and unblock us. Covers every return path below.
    struct FdGuard {
        PolicyProxyServer* self;
        int fd;
        ~FdGuard() { self->untrackFd(fd); }
    } guard{this, clientFd};
    trackFd(clientFd);
    // Loopback leg of the tunnel: engine <-> proxy. Small TLS records must
    // not sit in Nagle's buffer waiting for an ACK.
    int nodelay = 1;
    ::setsockopt(clientFd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    std::string head, method, target;
    // Engines (CFNetwork, libsoup) do not remember proxy credentials across
    // connections: every new connection opens with an unauthenticated
    // request, gets 407, then retries WITH the credential. Serve that retry
    // on the same socket instead of forcing a reconnect; a peer that never
    // authenticates is dropped after a few attempts.
    for (int attempt = 0;; attempt++) {
        if (!readHead(clientFd, head)) {
            ::close(clientFd);
            return;
        }
        const size_t lineEnd = head.find("\r\n");
        const std::string line = head.substr(0, lineEnd);
        const size_t sp1 = line.find(' ');
        if (sp1 == std::string::npos) {
            ::close(clientFd);
            return;
        }
        const size_t sp2 = line.find(' ', sp1 + 1);
        method = line.substr(0, sp1);
        target = sp2 == std::string::npos ? "" : line.substr(sp1 + 1, sp2 - sp1 - 1);

        // Authenticate FIRST: an unauthenticated peer gets no policy work,
        // no DoH traffic and no upstream socket - nothing it can measure.
        // Chromium strips Proxy-Authorization out of CONNECT tunnel requests
        // (it belongs to the auth system), so the CEF shell also stamps the
        // same per-launch credential into X-Lethe-Proxy-Auth, which survives
        // the tunnel. Either header authenticates; both terminate here and
        // are never forwarded upstream.
        if (opts_.authToken.empty()) break;
        std::string presented = headerValue(head, "Proxy-Authorization");
        if (presented.empty())
            presented = headerValue(head, "X-Lethe-Proxy-Auth");
        const std::string expected = basicCredentialFor(opts_.authToken);
        bool ok = presented.size() == expected.size();
        // Constant-time compare: a local attacker could otherwise time the
        // prefix match byte by byte.
        unsigned diff = ok ? 0 : 1;
        for (size_t i = 0; ok && i < expected.size(); i++)
            diff |= static_cast<unsigned>(presented[i] ^ expected[i]);
        if (diff == 0) break;
        // A wrong (not merely absent) credential is a foreign process
        // probing - always logged. The empty first request is the normal
        // challenge dance; LETHE_DEBUG shows it.
        if (!presented.empty() || std::getenv("LETHE_DEBUG"))
            std::cout << "[lethe-proxy] 407 " << method << " " << target
                      << (presented.empty() ? " (no credential)" : " (BAD credential)")
                      << std::endl;
        const bool keepAlive = attempt < 2;
        const std::string resp = proxyAuthRequiredResponse(keepAlive);
        sendAll(clientFd, resp.data(), resp.size());
        if (!keepAlive) {
            ::close(clientFd);
            return;
        }
        // A body-less request head was consumed whole by readHead; the
        // retry starts at the next byte.
    }
    const HttpClient::PolicyDialConfig cfg = dialConfig();

    if (method == "CONNECT") {
        const size_t colon = target.rfind(':');
        const std::string host = colon == std::string::npos
                                     ? target
                                     : target.substr(0, colon);
        const int port = colon == std::string::npos
                             ? 443
                             : std::atoi(target.c_str() + colon + 1);

        // CONNECT = raw tunnel: full policy gate, zero TLS termination.
        HttpClient::PolicyDialConfig rawCfg = cfg;
        rawCfg.rawTunnel = true;
        std::string err;
        auto stream = HttpClient::dialPolicyChecked(rawCfg, "https", host,
                                                    port, err);
        if (!stream) {
            const std::string resp = forbiddenResponse(err);
            sendAll(clientFd, resp.data(), resp.size());
            ::close(clientFd);
            return;
        }
        sendAll(clientFd,
                "HTTP/1.1 200 Connection Established\r\n\r\n", 39);

        // Splice both directions until either side closes. The upstream
        // direction runs on its own thread; downstream here.
        std::atomic<bool> done{false};
        std::thread up([&] {
            uint8_t buf[16384];
            while (!done.load(std::memory_order_relaxed) &&
                   !isStopping()) {
                ssize_t r = ::recv(clientFd, buf, sizeof(buf), 0);
                if (r <= 0) break;
                if (!stream->write(buf, static_cast<size_t>(r))) break;
            }
            stream->shutdownWrite();
            done.store(true, std::memory_order_relaxed);
        });
        uint8_t buf[16384];
        while (!done.load(std::memory_order_relaxed) && !isStopping()) {
            ssize_t r = stream->read(buf, sizeof(buf), 30000);
            if (r <= 0) break;
            if (!sendAll(clientFd,
                         reinterpret_cast<const char*>(buf),
                         static_cast<size_t>(r)))
                break;
        }
        done.store(true, std::memory_order_relaxed);
        ::shutdown(clientFd, SHUT_RDWR);
        up.join();
        ::close(clientFd);
        return;
    }

    // Absolute-form plain HTTP forwarding (engines emit these for http://).
    if (method != "GET" && method != "POST" && method != "HEAD" &&
        method != "PUT" && method != "DELETE" && method != "PATCH") {
        const std::string resp = forbiddenResponse("method not supported");
        sendAll(clientFd, resp.data(), resp.size());
        ::close(clientFd);
        return;
    }
    if (target.rfind("http://", 0) != 0) {
        const std::string resp =
            forbiddenResponse("scheme not permitted through proxy");
        sendAll(clientFd, resp.data(), resp.size());
        ::close(clientFd);
        return;
    }

    auto client = std::make_unique<HttpClient>();
    client->initialize(cfg.tls);
    if (!cfg.dohProvider.empty()) client->setDohProvider(cfg.dohProvider);
    if (cfg.dohCache) client->setSharedDohCache(cfg.dohCache);
    if (cfg.dohResolver) client->setSharedDohResolver(cfg.dohResolver);
    client->setPrivateNetworkPolicy(cfg.privateNet);
    if (cfg.vpnTunnel)
        client->setVpnTunnel(std::shared_ptr<vpn::VpnTunnel>(
            cfg.vpnTunnel, [](vpn::VpnTunnel*) {}));

    HttpRequest req;
    req.url = target;
    req.timeout = std::chrono::seconds(30);
    HttpResponse resp = client->sendRequest(req);
    if (!resp.success) {
        const std::string body = forbiddenResponse(
            resp.error.empty() ? "upstream fetch failed" : resp.error);
        sendAll(clientFd, body.data(), body.size());
        ::close(clientFd);
        return;
    }

    std::string out =
        "HTTP/1.1 " + std::to_string(resp.statusCode) + " OK\r\n";
    for (const auto& h : resp.headers) {
        std::string lower = h.first;
        for (auto& ch : lower) ch = static_cast<char>(::tolower(ch));
        // Hop-by-hop and framing headers are re-derived, never forwarded.
        if (lower == "connection" || lower == "keep-alive" ||
            lower == "transfer-encoding" || lower == "content-length")
            continue;
        out += h.first + ": " + h.second + "\r\n";
    }
    out += "Content-Length: " + std::to_string(resp.body.size()) + "\r\n";
    out += "Connection: close\r\n\r\n";
    sendAll(clientFd, out.data(), out.size());
    if (!resp.body.empty())
        sendAll(clientFd,
                reinterpret_cast<const char*>(resp.body.data()),
                resp.body.size());
    ::close(clientFd);
}

} // namespace lethe
