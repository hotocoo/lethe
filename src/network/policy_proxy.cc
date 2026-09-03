#include "network/policy_proxy.h"

#include <arpa/inet.h>
#include <algorithm>
#include <atomic>
#include <charconv>
#include <openssl/rand.h>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <string_view>
#include <sys/socket.h>
#include <sys/uio.h>
#include <thread>
#include <unistd.h>

namespace lethe {

namespace {

constexpr size_t kMaxHeadBytes = 64 * 1024;
constexpr size_t kMaxQueuedConnections = 256;

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

// Case-insensitive header lookup without allocating. The returned view is
// valid only while `head` remains alive; request authentication is the hot
// path, so avoid constructing a temporary std::string for every connection.
std::string_view headerValueView(std::string_view head, std::string_view name) {
    size_t pos = head.find("\r\n");
    while (pos != std::string::npos && pos + 2 < head.size()) {
        const size_t end = head.find("\r\n", pos + 2);
        const size_t lineEnd = end == std::string::npos ? head.size() : end;
        const std::string_view line = head.substr(pos + 2, lineEnd - pos - 2);
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
        if (end == std::string::npos) break;
        pos = end;
    }
    return {};
}

bool sendAll(int fd, const char* p, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = ::send(fd, p + off, n - off, MSG_NOSIGNAL);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return false;
        off += static_cast<size_t>(w);
    }
    return true;
}

// Send a response head and body without first concatenating them. Most proxy
// responses have two buffers already (generated headers + HttpClient body),
// so writev() removes one syscall and avoids another potentially-large copy.
bool sendAllParts(int fd, const char* p1, size_t n1,
                  const char* p2, size_t n2) {
    iovec iov[2] = {
        {const_cast<char*>(p1), n1},
        {const_cast<char*>(p2), n2},
    };
    int count = (n1 != 0 ? 1 : 0) + (n2 != 0 ? 1 : 0);
    if (count == 0) return true;
    int first = 0;
    if (n1 == 0) iov[0] = iov[1], first = 0;
    while (count > 0) {
        ssize_t w = ::writev(fd, iov + first, count);
        if (w < 0 && errno == EINTR) continue;
        if (w <= 0) return false;
        size_t left = static_cast<size_t>(w);
        while (count > 0 && left >= iov[first].iov_len) {
            left -= iov[first].iov_len;
            ++first;
            --count;
        }
        if (count > 0 && left != 0) {
            auto* base = static_cast<char*>(iov[first].iov_base);
            iov[first].iov_base = base + left;
            iov[first].iov_len -= left;
        }
    }
    return true;
}

bool isHopByHopHeader(std::string_view name) {
    if (name.size() == 10) {
        constexpr std::string_view kConnection = "connection";
        bool match = true;
        for (size_t i = 0; i < name.size(); ++i)
            match &= ::tolower(static_cast<unsigned char>(name[i])) == kConnection[i];
        if (match) return true;
    }
    if (name.size() == 10) {
        constexpr std::string_view kKeepAlive = "keep-alive";
        bool match = true;
        for (size_t i = 0; i < name.size(); ++i)
            match &= ::tolower(static_cast<unsigned char>(name[i])) == kKeepAlive[i];
        if (match) return true;
    }
    if (name.size() == 17) {
        constexpr std::string_view kTransferEncoding = "transfer-encoding";
        bool match = true;
        for (size_t i = 0; i < name.size(); ++i)
            match &= ::tolower(static_cast<unsigned char>(name[i])) == kTransferEncoding[i];
        if (match) return true;
    }
    if (name.size() == 14) {
        constexpr std::string_view kContentLength = "content-length";
        bool match = true;
        for (size_t i = 0; i < name.size(); ++i)
            match &= ::tolower(static_cast<unsigned char>(name[i])) == kContentLength[i];
        if (match) return true;
    }
    return false;
}

// Read until CRLFCRLF or cap. False on EOF/error/oversize/timeout.
// Reads in 4KB chunks for efficiency instead of byte-by-byte. The bounded
// wait is important because this socket is serviced by a fixed worker pool:
// a local peer must not be able to pin every worker with a slowloris header.
bool readHead(int fd, std::string& out) {
    out.clear();
    char buf[4096];
    constexpr int kHeaderTimeoutMs = 5000;
    while (out.size() < kMaxHeadBytes) {
        struct pollfd pfd {fd, POLLIN, 0};
        int ready;
        do {
            ready = ::poll(&pfd, 1, kHeaderTimeoutMs);
        } while (ready < 0 && errno == EINTR);
        if (ready <= 0 || !(pfd.revents & POLLIN)) return false;
        const size_t remaining = kMaxHeadBytes - out.size();
        const size_t want = remaining < sizeof(buf) ? remaining : sizeof(buf);
        ssize_t r = ::recv(fd, buf, want, 0);
        if (r < 0 && errno == EINTR) continue;
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
    stopping_.store(false, std::memory_order_relaxed);
    expectedAuthCredential_.clear();
    if (!opts_.authToken.empty()) {
        expectedAuthCredential_ = basicCredentialFor(opts_.authToken);
    }
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
        // Browser HTTPS uses one blocking CONNECT splice per live origin.
        // Eight workers can therefore be exhausted by a single media-heavy
        // page (YouTube commonly keeps more than eight tunnels alive), which
        // starves the next top-level navigation even though the browser is
        // otherwise healthy. Keep the pool bounded, but give a browser enough
        // concurrent tunnels to avoid head-of-line blocking.
        // Long-lived CONNECT tunnels (video/audio, WebSocket, HTTP/2) hold a
        // worker for the lifetime of the tunnel. A 16-thread ceiling lets a
        // media-heavy Chromium page consume the entire pool and push an
        // unrelated navigation behind the queue. M4-class hosts have ample
        // memory for the additional stacks; cap at 32 to avoid scheduler
        // thrash while materially reducing this p99.9 head-of-line stall.
        workerCount_ = hc == 0 ? 32 : std::min<size_t>(32, std::max<size_t>(16, hc * 2));
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
            // Only shutdown here. The serving worker owns the descriptor and
            // will close it on every exit path. Closing it from stop() creates
            // an fd-reuse race: another socket can acquire the same integer
            // before the worker reaches its final close(), causing an
            // unrelated live connection to be closed.
            ::shutdown(fd, SHUT_RDWR);
        }
    }
    if (listenFd_ >= 0) {
        ::shutdown(listenFd_, SHUT_RDWR);
        ::close(listenFd_);
        listenFd_ = -1;
    }
    if (acceptThread_.joinable()) acceptThread_.join();
    // No queued fd is tracked until a worker starts serving it. Drain and
    // close those descriptors here; otherwise shutdown can leave accepted
    // clients alive behind the sentinel queue entries.
    {
        std::lock_guard<std::mutex> lk(queue_mtx_);
        for (int fd : queue_) {
            if (fd >= 0) ::close(fd);
        }
        queue_.clear();
        running_.store(false);
        for (size_t i = 0; i < workers_.size(); ++i) queue_.push_back(-1);
    }
    queue_cv_.notify_all();
    for (auto& t : workers_) if (t.joinable()) t.join();
    workers_.clear();
    {
        std::lock_guard<std::mutex> lk(tunnelWorkers_mtx_);
        for (auto& t : tunnelWorkers_) if (t.joinable()) t.join();
        tunnelWorkers_.clear();
    }
}

void PolicyProxyServer::acceptLoop() {
    while (running_) {
        int fd = ::accept(listenFd_, nullptr, nullptr);
        if (fd < 0) break;
        {
            std::lock_guard<std::mutex> lk(queue_mtx_);
            if (!running_ || isStopping()) {
                ::close(fd);
                continue;
            }
            if (queue_.size() >= kMaxQueuedConnections) {
                static constexpr char kBusy[] =
                    "HTTP/1.1 503 Service Unavailable\r\n"
                    "Connection: close\r\n"
                    "Content-Length: 0\r\n\r\n";
                sendAll(fd, kBusy, sizeof(kBusy) - 1);
                ::close(fd);
                continue;
            }
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
        if (isStopping()) {
            ::close(fd);
            continue;
        }
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
        ~FdGuard() { if (self) self->untrackFd(fd); }
    } guard{this, clientFd};
    trackFd(clientFd);
    // Loopback leg of the tunnel: engine <-> proxy. Small TLS records must
    // not sit in Nagle's buffer waiting for an ACK.
    int nodelay = 1;
    ::setsockopt(clientFd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));
    std::string head;
    std::string_view method;
    std::string_view target;
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
        const std::string_view line(head.data(),
                                    lineEnd == std::string::npos ? head.size() : lineEnd);
        const size_t sp1 = line.find(' ');
        if (sp1 == std::string::npos) {
            ::close(clientFd);
            return;
        }
        const size_t sp2 = line.find(' ', sp1 + 1);
        method = line.substr(0, sp1);
        target =
            sp2 == std::string::npos ? std::string_view{} :
            line.substr(sp1 + 1, sp2 - sp1 - 1);

        // Authenticate FIRST: an unauthenticated peer gets no policy work,
        // no DoH traffic and no upstream socket - nothing it can measure.
        // Chromium owns Proxy-Authorization for CONNECT and CEF does not
        // expose a safe way to pre-stamp it on every new proxy connection.
        // Do not replace it with a normal request header: for HTTPS that
        // header would travel inside the end-to-end tunnel to the origin.
        if (opts_.authToken.empty()) break;
        std::string_view presented = headerValueView(head, "Proxy-Authorization");
        if (presented.empty())
            presented = headerValueView(head, "X-Lethe-Proxy-Auth");
        const std::string& expected = expectedAuthCredential_;
        bool ok = presented.size() == expected.size();
        // Constant-time compare: a local attacker could otherwise time the
        // prefix match byte by byte.
        unsigned diff = ok ? 0 : 1;
        for (size_t i = 0; i < expected.size(); i++) {
            const unsigned char actual =
                i < presented.size() ? static_cast<unsigned char>(presented[i]) : 0;
            diff |= static_cast<unsigned>(actual ^
                                          static_cast<unsigned char>(expected[i]));
        }
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
        const std::string_view hostView = colon == std::string::npos
                                              ? target
                                              : target.substr(0, colon);
        const std::string host(hostView);
        int port = 443;
        if (colon != std::string::npos) {
            const std::string_view portView = target.substr(colon + 1);
            const char* first = portView.data();
            const char* last = first + portView.size();
            const auto parsed = std::from_chars(first, last, port);
            if (parsed.ec != std::errc{} || parsed.ptr != last || port < 1 || port > 65535)
                port = -1;
        }

        if (host.empty() || port < 1) {
            const std::string resp = forbiddenResponse("invalid CONNECT target");
            sendAll(clientFd, resp.data(), resp.size());
            ::close(clientFd);
            return;
        }

        // CONNECT = raw tunnel: full policy gate, zero TLS termination.
        HttpClient::PolicyDialConfig rawCfg = cfg;
        rawCfg.rawTunnel = true;
        std::string err;
        
        // Timing instrumentation for LETHE_DEBUG
        auto t0 = std::chrono::steady_clock::now();
        auto stream = HttpClient::dialPolicyChecked(rawCfg, "https", host,
                                                    port, err);
        auto t1 = std::chrono::steady_clock::now();
        if (getenv("LETHE_DEBUG")) {
            std::cout << "[lethe-proxy] CONNECT " << host << ":" << port
                      << " dialPolicyChecked: "
                      << std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count()
                      << "ms" << std::endl;
            std::cout.flush();
        }
        if (!stream) {
            const std::string resp = forbiddenResponse(err);
            sendAll(clientFd, resp.data(), resp.size());
            ::close(clientFd);
            return;
        }
        sendAll(clientFd,
                "HTTP/1.1 200 Connection Established\r\n\r\n", 39);

        // Long-lived CONNECT tunnels must not occupy a request worker for
        // their entire lifetime. Handoff the bidirectional splice to a
        // separately joined tunnel thread, then return this worker to the
        // queue immediately. This removes media-induced head-of-line
        // blocking without changing the authenticated/policy-gated tunnel.
        guard.self = nullptr;
        std::thread tunnel([this, clientFd, stream = std::move(stream)]() mutable {
            std::atomic<bool> done{false};
            std::thread up([&] {
                uint8_t buf[262144];
                while (!done.load(std::memory_order_relaxed) && !isStopping()) {
                    ssize_t r = ::recv(clientFd, buf, sizeof(buf), 0);
                    if (r <= 0) break;
                    if (!stream->write(buf, static_cast<size_t>(r))) break;
                }
                stream->shutdownWrite();
                done.store(true, std::memory_order_relaxed);
            });
            uint8_t buf[262144];
            while (!done.load(std::memory_order_relaxed) && !isStopping()) {
                // Keep shutdown latency bounded without treating a normal
                // media/network stall as EOF. A 1 s timeout was too short for
                // adaptive video (and even some image/TLS delivery gaps): a
                // quiet upstream interval was mapped to -1 and the tunnel
                // was closed as if the origin had ended it. stop() already
                // calls stream->cancel(), so a 5 s read timeout does not
                // compromise shutdown latency while materially improving
                // long-lived media reliability.
                ssize_t r = stream->read(buf, sizeof(buf), 5000);
                if (r <= 0) break;
                if (!sendAll(clientFd, reinterpret_cast<const char*>(buf),
                             static_cast<size_t>(r))) break;
            }
            done.store(true, std::memory_order_relaxed);
            stream->cancel();
            ::shutdown(clientFd, SHUT_RDWR);
            up.join();
            ::close(clientFd);
            untrackFd(clientFd);
        });
        {
            std::lock_guard<std::mutex> lk(tunnelWorkers_mtx_);
            tunnelWorkers_.push_back(std::move(tunnel));
        }
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

    // -- v0.2.x perf: thread-local upstream client ----------------------
    // The previous code built a fresh HttpClient per request, paying the
    // full TCP+TLS setup and (for hostnames) a DoH round-trip every time.
    // A busy page fans out dozens of same-origin subresources; reusing one
    // client per worker thread lets its keep-alive connection (and the
    // already-validated origin) serve every subsequent request with no
    // handshake. The client is owned by this thread for its whole life.
    thread_local std::unique_ptr<HttpClient> tlsClient;
    thread_local bool tlsClientReady = false;
    if (!tlsClientReady) {
        tlsClient = std::make_unique<HttpClient>();
        tlsClient->initialize(cfg.tls);
        if (!cfg.dohProvider.empty()) tlsClient->setDohProvider(cfg.dohProvider);
        if (cfg.dohCache) tlsClient->setSharedDohCache(cfg.dohCache);
        if (cfg.dohResolver) tlsClient->setSharedDohResolver(cfg.dohResolver);
        tlsClient->setPrivateNetworkPolicy(cfg.privateNet);
        if (cfg.vpnTunnel)
            tlsClient->setVpnTunnel(std::shared_ptr<vpn::VpnTunnel>(
                cfg.vpnTunnel, [](vpn::VpnTunnel*) {}));
        tlsClientReady = true;
    }
    HttpClient* client = tlsClient.get();

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

    std::string out;
    out.reserve(512);
    out +=
        "HTTP/1.1 " + std::to_string(resp.statusCode) + " OK\r\n";
    for (const auto& h : resp.headers) {
        // Hop-by-hop and framing headers are re-derived, never forwarded.
        if (isHopByHopHeader(h.first))
            continue;
        out += h.first + ": " + h.second + "\r\n";
    }
    out += "Content-Length: " + std::to_string(resp.body.size()) + "\r\n";
    out += "Connection: close\r\n\r\n";
    sendAllParts(clientFd, out.data(), out.size(),
                 reinterpret_cast<const char*>(resp.body.data()), resp.body.size());
    ::close(clientFd);
}

} // namespace lethe
