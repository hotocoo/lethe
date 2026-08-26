#include "network/policy_proxy.h"

#include <arpa/inet.h>
#include <atomic>
#include <cctype>
#include <cstring>
#include <netinet/in.h>
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
bool readHead(int fd, std::string& out) {
    out.clear();
    char c;
    while (out.size() < kMaxHeadBytes) {
        ssize_t r = ::recv(fd, &c, 1, 0);
        if (r <= 0) return false;
        out.push_back(c);
        if (out.size() >= 4 &&
            out.compare(out.size() - 4, 4, "\r\n\r\n") == 0)
            return true;
    }
    return false;
}

} // namespace

PolicyProxyServer::~PolicyProxyServer() { stop(); }

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
    running_ = true;
    acceptThread_ = std::thread([this] { acceptLoop(); });
    return true;
}

void PolicyProxyServer::stop() {
    if (!running_.exchange(false)) return;
    if (listenFd_ >= 0) {
        ::shutdown(listenFd_, SHUT_RDWR);
        ::close(listenFd_);
        listenFd_ = -1;
    }
    if (acceptThread_.joinable()) acceptThread_.join();
}

void PolicyProxyServer::acceptLoop() {
    while (running_) {
        int fd = ::accept(listenFd_, nullptr, nullptr);
        if (fd < 0) break;
        std::thread([this, fd] { serveConnection(fd); }).detach();
    }
}

HttpClient::PolicyDialConfig PolicyProxyServer::dialConfig() const {
    HttpClient::PolicyDialConfig cfg;
    cfg.tls = opts_.tls;
    cfg.dohProvider = opts_.dohProvider;
    cfg.privateNet = opts_.privateNet;
    cfg.vpnTunnel = opts_.vpnTunnel;
    cfg.vpnUdp = static_cast<UdpTransport*>(opts_.udpTransport);
    cfg.relayEndpointHost = opts_.relayHost;
    cfg.relayEndpointPort = opts_.relayPort;
    return cfg;
}

void PolicyProxyServer::serveConnection(int clientFd) {
    std::string head;
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
    const std::string method = line.substr(0, sp1);
    const std::string target = sp2 == std::string::npos
                                   ? ""
                                   : line.substr(sp1 + 1, sp2 - sp1 - 1);
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
            while (!done.load(std::memory_order_relaxed)) {
                ssize_t r = ::recv(clientFd, buf, sizeof(buf), 0);
                if (r <= 0) break;
                if (!stream->write(buf, static_cast<size_t>(r))) break;
            }
            stream->shutdownWrite();
            done.store(true, std::memory_order_relaxed);
        });
        uint8_t buf[16384];
        while (!done.load(std::memory_order_relaxed)) {
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
