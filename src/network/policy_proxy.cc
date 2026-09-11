#include "network/policy_proxy.h"
#include "config.h"

#include <arpa/inet.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <charconv>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/sha.h>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <fcntl.h>
#include <iostream>
#include <list>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <string_view>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <fcntl.h>
#if defined(__APPLE__)
#include <sys/event.h>
#endif
#include <thread>
#include <unordered_map>
#include <unistd.h>
#include <signal.h>

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

bool headerValueHasToken(std::string_view value, std::string_view token) {
    if (value.empty() || token.empty()) return false;
    for (size_t start = 0; start < value.size();) {
        while (start < value.size() && (value[start] == ' ' || value[start] == '\t' || value[start] == ',')) ++start;
        size_t end = start;
        while (end < value.size() && value[end] != ',') ++end;
        size_t first = start;
        while (first < end && (value[first] == ' ' || value[first] == '\t')) ++first;
        size_t last = end;
        while (last > first && (value[last - 1] == ' ' || value[last - 1] == '\t')) --last;
        if (last - first == token.size()) {
            bool match = true;
            for (size_t i = 0; i < token.size(); ++i) {
                if (::tolower(static_cast<unsigned char>(value[first + i])) !=
                    ::tolower(static_cast<unsigned char>(token[i]))) {
                    match = false;
                    break;
                }
            }
            if (match) return true;
        }
        start = end < value.size() ? end + 1 : value.size();
    }
    return false;
}

// The request header block is already resident in memory.  Parse the small
// set of proxy-control fields we need in one pass instead of rescanning the
// entire block once per field.  This is deliberately limited to metadata;
// ordinary request headers are still opaque to the policy proxy.
struct ProxyRequestMeta {
    std::string_view proxyAuthorization;
    std::string_view internalAuthToken;
    std::string_view connection;
    std::string_view proxyConnection;
    std::string_view contentLength;
    std::string_view transferEncoding;
};

inline bool equalsAsciiInsensitive(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        unsigned char ca = static_cast<unsigned char>(a[i]);
        unsigned char cb = static_cast<unsigned char>(b[i]);
        if (ca >= 'A' && ca <= 'Z') ca = static_cast<unsigned char>(ca + 32);
        if (cb >= 'A' && cb <= 'Z') cb = static_cast<unsigned char>(cb + 32);
        if (ca != cb) return false;
    }
    return true;
}

ProxyRequestMeta parseProxyRequestMeta(std::string_view head) {
    ProxyRequestMeta meta;
    size_t pos = head.find("\r\n");
    while (pos != std::string::npos && pos + 2 < head.size()) {
        const size_t end = head.find("\r\n", pos + 2);
        const size_t lineEnd = end == std::string::npos ? head.size() : end;
        const std::string_view line = head.substr(pos + 2, lineEnd - pos - 2);
        const size_t colon = line.find(':');
        if (colon != std::string::npos) {
            const std::string_view name = line.substr(0, colon);
            size_t valuePos = colon + 1;
            while (valuePos < line.size() &&
                   (line[valuePos] == ' ' || line[valuePos] == '\t')) {
                ++valuePos;
            }
            const std::string_view value = line.substr(valuePos);
            // The proxy only needs six request metadata fields. Dispatch by
            // length first so ordinary headers pay at most one integer
            // comparison and the hot fields avoid constructing a lambda and
            // repeatedly invoking locale-backed tolower().
            switch (name.size()) {
            case 10:
                if (equalsAsciiInsensitive(name, "connection"))
                    meta.connection = value;
                break;
            case 14:
                if (equalsAsciiInsensitive(name, "content-length"))
                    meta.contentLength = value;
                break;
            case 16:
                if (equalsAsciiInsensitive(name, "proxy-connection"))
                    meta.proxyConnection = value;
                break;
            case 17:
                if (equalsAsciiInsensitive(name, "transfer-encoding"))
                    meta.transferEncoding = value;
                break;
            case 19:
                if (equalsAsciiInsensitive(name, "proxy-authorization"))
                    meta.proxyAuthorization = value;
                else if (equalsAsciiInsensitive(name, "x-lethe-proxy-auth"))
                    meta.internalAuthToken = value;
                break;
            default:
                break;
            }
        }
        if (end == std::string::npos) break;
        pos = end;
    }
    return meta;
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

std::string base64EncodeBytes(const unsigned char* data, size_t len) {
    if (len == 0) return {};
    std::string out;
    out.resize(4 * ((len + 2) / 3));
    const int n = EVP_EncodeBlock(reinterpret_cast<unsigned char*>(out.data()), data,
                                   static_cast<int>(len));
    if (n < 0) return {};
    out.resize(static_cast<size_t>(n));
    return out;
}

bool writeProxyCertificate(const std::string& keyPath,
                           const std::string& certPath,
                           std::string& spkiSha256) {
    EVP_PKEY* key = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "prime256v1");
    if (!key) return false;
    X509* cert = X509_new();
    bool ok = cert != nullptr;
    if (ok) ok = X509_set_version(cert, 2) == 1;
    if (ok) ok = ASN1_INTEGER_set(X509_get_serialNumber(cert), 1) == 1;
    if (ok) ok = X509_gmtime_adj(X509_get_notBefore(cert), -60) != nullptr;
    if (ok) ok = X509_gmtime_adj(X509_get_notAfter(cert), 24 * 60 * 60) != nullptr;
    if (ok) ok = X509_set_pubkey(cert, key) == 1;
    if (ok) {
        X509_NAME* name = X509_get_subject_name(cert);
        ok = X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                        reinterpret_cast<const unsigned char*>("127.0.0.1"),
                                        -1, -1, 0) == 1;
        if (ok) ok = X509_set_issuer_name(cert, name) == 1;
    }
    if (ok) {
        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);
        X509_EXTENSION* san = X509V3_EXT_conf_nid(
            nullptr, &ctx, NID_subject_alt_name,
            const_cast<char*>("IP:127.0.0.1,DNS:localhost"));
        if (!san) ok = false;
        else {
            ok = X509_add_ext(cert, san, -1) == 1;
            X509_EXTENSION_free(san);
        }
    }
    if (ok) ok = X509_sign(cert, key, EVP_sha256()) > 0;

    if (ok) {
        FILE* keyFile = std::fopen(keyPath.c_str(), "wb");
        FILE* certFile = std::fopen(certPath.c_str(), "wb");
        if (!keyFile || !certFile) ok = false;
        if (keyFile) {
            if (PEM_write_PrivateKey(keyFile, key, nullptr, nullptr, 0, nullptr, nullptr) != 1)
                ok = false;
            std::fclose(keyFile);
        }
        if (certFile) {
            if (PEM_write_X509(certFile, cert) != 1) ok = false;
            std::fclose(certFile);
        }
    }

    if (ok) {
        unsigned char* der = nullptr;
        const int derLen = i2d_PUBKEY(X509_get0_pubkey(cert), &der);
        unsigned char digest[SHA256_DIGEST_LENGTH];
        ok = derLen > 0 && SHA256(der, static_cast<size_t>(derLen), digest) != nullptr;
        if (der) OPENSSL_free(der);
        if (ok) spkiSha256 = base64EncodeBytes(digest, sizeof(digest));
    }
    X509_free(cert);
    EVP_PKEY_free(key);
    return ok && !spkiSha256.empty();
}

int reserveLoopbackPort() {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 0;
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = 0;
    ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        ::close(fd);
        return 0;
    }
    socklen_t len = sizeof(addr);
    if (::getsockname(fd, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
        ::close(fd);
        return 0;
    }
    const int port = ntohs(addr.sin_port);
    ::close(fd);
    return port;
}

std::string findNghttpx() {
    if (const char* overridePath = std::getenv("LETHE_NGHTTPX_PATH");
        overridePath && *overridePath && ::access(overridePath, X_OK) == 0) {
        return overridePath;
    }
    constexpr const char* candidates[] = {
        "/opt/homebrew/bin/nghttpx",
        "/usr/local/bin/nghttpx",
        "/usr/bin/nghttpx",
    };
    for (const char* path : candidates) {
        if (::access(path, X_OK) == 0) return path;
    }
    return {};
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
    // RFC 9110 hop-by-hop fields must never cross the policy boundary.
    // Keep this allocation-free because it runs for every upstream response.
    // Length is a strong discriminator for ordinary fields (content-type,
    // cache-control, et al.), so avoid the previous nine-candidate scan.
    auto equalsAsciiInsensitive = [name](std::string_view candidate) {
        if (name.size() != candidate.size()) return false;
        for (size_t i = 0; i < name.size(); ++i) {
            unsigned char a = static_cast<unsigned char>(name[i]);
            unsigned char b = static_cast<unsigned char>(candidate[i]);
            if (a >= 'A' && a <= 'Z') a = static_cast<unsigned char>(a + ('a' - 'A'));
            if (b >= 'A' && b <= 'Z') b = static_cast<unsigned char>(b + ('a' - 'A'));
            if (a != b) return false;
        }
        return true;
    };
    switch (name.size()) {
    case 2:  return equalsAsciiInsensitive("te");
    case 7:  return equalsAsciiInsensitive("trailer") ||
                     equalsAsciiInsensitive("upgrade");
    case 10: return equalsAsciiInsensitive("connection") ||
                     equalsAsciiInsensitive("keep-alive");
    case 14: return equalsAsciiInsensitive("content-length");
    case 17: return equalsAsciiInsensitive("transfer-encoding");
    case 19: return equalsAsciiInsensitive("proxy-authenticate");
    case 21: return equalsAsciiInsensitive("proxy-authorization");
    default: return false;
    }
}

// Read until CRLFCRLF or cap. False on EOF/error/oversize/timeout.
// Reads in 4KB chunks for efficiency instead of byte-by-byte. The bounded
// wait is important because this socket is serviced by a fixed worker pool:
// a local peer must not be able to pin every worker with a slowloris header.
bool readHead(int fd, std::string& out) {
    out.clear();
    char buf[4096];
    while (out.size() < kMaxHeadBytes) {
        const size_t remaining = kMaxHeadBytes - out.size();
        const size_t want = remaining < sizeof(buf) ? remaining : sizeof(buf);
        // The delimiter can only begin in the last three bytes already in
        // `out` or inside the newly received chunk. Searching the entire
        // accumulated header after every recv() turns a fragmented large
        // header into O(n^2) scanning on the proxy worker hot path. Keep the
        // security cap unchanged, but make delimiter detection incremental.
        const size_t previousSize = out.size();
        ssize_t r = ::recv(fd, buf, want, 0);
        if (r < 0 && errno == EINTR) continue;
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) return false;
        if (r <= 0) return false;
        out.append(buf, static_cast<size_t>(r));
        const size_t searchStart = previousSize > 3 ? previousSize - 3 : 0;
        const size_t pos = out.find("\r\n\r\n", searchStart);
        if (pos != std::string::npos) {
            out.resize(pos + 4);
            return true;
        }
    }
    return false;
}

} // namespace

// Shared event-driven reactor for the hot plain-HTTP proxy path. The worker
// that owns a browser connection still performs authentication and the full
// policy-gated upstream dial before handing the descriptor over. From that
// point onward there is no worker blocked on upstream recv()/send(): one
// kqueue loop multiplexes all active HTTP request/response pairs.
class PolicyProxyServer::HttpForwardReactor {
public:
    HttpForwardReactor(const HttpClient::PolicyDialConfig& cfg,
                       std::string expectedCredential,
                       std::atomic<bool>* stopping)
        : cfg_(cfg), expectedCredential_(std::move(expectedCredential)),
          stopping_(stopping) {}

    ~HttpForwardReactor() { stop(); }

    bool start() {
#if defined(__APPLE__)
        if (running_) return true;
        kq_ = ::kqueue();
        if (kq_ < 0) return false;
        if (::pipe(wake_) != 0) {
            ::close(kq_); kq_ = -1;
            return false;
        }
        for (int fd : wake_) {
            const int flags = ::fcntl(fd, F_GETFL, 0);
            if (flags >= 0) ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
            ::fcntl(fd, F_SETFD, FD_CLOEXEC);
        }
        struct kevent ev{};
        EV_SET(&ev, static_cast<uintptr_t>(wake_[0]), EVFILT_READ,
               EV_ADD | EV_ENABLE, 0, 0, nullptr);
        if (::kevent(kq_, &ev, 1, nullptr, 0, nullptr) != 0) {
            stop();
            return false;
        }
        running_ = true;
        thread_ = std::thread([this] { run(); });
        return true;
#else
        return false;
#endif
    }

    void stop() {
#if defined(__APPLE__)
        if (!running_.exchange(false)) return;
        if (wake_[1] >= 0) {
            const char byte = 'x';
            (void)::write(wake_[1], &byte, 1);
        }
        if (thread_.joinable()) thread_.join();
        for (auto& c : conns_) closeConn(c.get());
        conns_.clear();
        if (wake_[0] >= 0) ::close(wake_[0]);
        if (wake_[1] >= 0) ::close(wake_[1]);
        wake_[0] = wake_[1] = -1;
        if (kq_ >= 0) ::close(kq_);
        kq_ = -1;
#endif
    }

    bool submit(int clientFd, std::string initialHead,
                PolicyStreamPtr upstream) {
#if defined(__APPLE__)
        if (!running_ || !upstream || upstream->nativeFd() < 0) return false;
        Task task{clientFd, std::move(initialHead), std::move(upstream)};
        {
            std::lock_guard<std::mutex> lk(mtx_);
            pending_.push_back(std::move(task));
        }
        bool expected = false;
        if (wakeSignaled_.compare_exchange_strong(
                expected, true, std::memory_order_acq_rel,
                std::memory_order_relaxed)) {
            const char byte = 'x';
            if (::write(wake_[1], &byte, 1) != 1) {
                wakeSignaled_.store(false, std::memory_order_release);
                return false;
            }
        }
        return true;
#else
        (void)clientFd; (void)initialHead; (void)upstream;
        return false;
#endif
    }

private:
    struct Task {
        int clientFd;
        std::string head;
        PolicyStreamPtr upstream;
    };

    struct Conn {
        struct Watch {
            Conn* conn;
            bool upstream;
        };

        int clientFd = -1;
        PolicyStreamPtr upstream;
        Watch clientWatch{this, false};
        Watch upstreamWatch{this, true};
        std::string clientIn;
        std::string upstreamIn;
        std::string clientOut;
        size_t clientOutPos = 0;
        std::string upstreamOut;
        size_t upstreamOutPos = 0;
        size_t bodyRemaining = 0;
        bool chunked = false;
        bool chunkDone = false;
        bool responseHeadersDone = false;
        bool responseClose = false;
        bool requestPending = false;
        bool clientEof = false;
        bool upstreamEof = false;
        bool clientWriteArmed = false;
        bool upstreamWriteArmed = false;
    };

    HttpClient::PolicyDialConfig cfg_;
    std::string expectedCredential_;
    std::atomic<bool>* stopping_ = nullptr;
    std::mutex mtx_;
    std::deque<Task> pending_;
    std::vector<std::unique_ptr<Conn>> conns_;
    // kqueue events carry a stable Watch pointer, so readiness dispatch is
    // O(1) pointer chasing rather than a hash lookup on every read/write
    // event. Watches live inside Conn and therefore remain valid until the
    // connection is retired after the current kevent batch.
    std::thread thread_;
    std::atomic<bool> running_{false};
    std::atomic<bool> wakeSignaled_{false};
    int kq_ = -1;
    int wake_[2] = {-1, -1};

#if defined(__APPLE__)
    static bool setNonBlocking(int fd) {
        const int flags = ::fcntl(fd, F_GETFL, 0);
        return flags >= 0 && ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
    }

    static bool sendError(int fd, const std::string& response) {
        return sendAll(fd, response.data(), response.size());
    }

    static bool parseRequestLine(std::string_view head,
                                 std::string_view& method,
                                 std::string_view& target) {
        const size_t end = head.find("\r\n");
        const std::string_view line =
            head.substr(0, end == std::string::npos ? head.size() : end);
        const size_t sp1 = line.find(' ');
        const size_t sp2 = sp1 == std::string::npos ? std::string::npos
                                                     : line.find(' ', sp1 + 1);
        if (sp1 == std::string::npos || sp2 == std::string::npos) return false;
        method = line.substr(0, sp1);
        target = line.substr(sp1 + 1, sp2 - sp1 - 1);
        return !method.empty() && !target.empty();
    }

    static bool parseHttpTarget(std::string_view target, std::string& host,
                                int& port, std::string& path) {
        if (target.rfind("http://", 0) != 0) return false;
        std::string_view authorityPath = target.substr(7);
        const size_t slash = authorityPath.find('/');
        std::string_view authority = authorityPath.substr(
            0, slash == std::string::npos ? authorityPath.size() : slash);
        path = slash == std::string::npos ? "/"
                                          : std::string(authorityPath.substr(slash));
        if (authority.empty()) return false;
        if (authority.front() == '[') {
            const size_t close = authority.find(']');
            if (close == std::string::npos) return false;
            host = std::string(authority.substr(1, close - 1));
            port = 80;
            if (close + 1 < authority.size()) {
                if (authority[close + 1] != ':') return false;
                const auto p = std::from_chars(authority.data() + close + 2,
                                               authority.data() + authority.size(), port);
                if (p.ec != std::errc{} || p.ptr != authority.data() + authority.size() ||
                    port < 1 || port > 65535) return false;
            }
            return !host.empty();
        }
        const size_t colon = authority.rfind(':');
        port = 80;
        if (colon != std::string::npos) {
            host = std::string(authority.substr(0, colon));
            const auto p = std::from_chars(authority.data() + colon + 1,
                                           authority.data() + authority.size(), port);
            if (p.ec != std::errc{} || p.ptr != authority.data() + authority.size() ||
                port < 1 || port > 65535) return false;
        } else {
            host = std::string(authority);
        }
        return !host.empty();
    }

    static std::string buildWireRequest(std::string_view method,
                                        std::string_view target) {
        std::string host;
        int port = 80;
        std::string path;
        if (!parseHttpTarget(target, host, port, path)) return {};
        const std::string wireHost = host.find(':') != std::string::npos
            ? "[" + host + "]" : host;
        std::string out;
        out.reserve(480 + path.size() + host.size());
        out.append(method.data(), method.size());
        out += " ";
        out += path;
        out += " HTTP/1.1\r\nHost: ";
        out += wireHost;
        out += "\r\nUser-Agent: ";
        out += lethe::USER_AGENT_STRING;
        out += "\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";
        out += "Accept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\n";
        out += "Connection: keep-alive\r\n\r\n";
        return out;
    }

    bool authOk(const ProxyRequestMeta& meta) const {
        if (expectedCredential_.empty()) return true;
        const std::string_view presented = meta.proxyAuthorization;
        bool ok = presented.size() == expectedCredential_.size();
        unsigned diff = ok ? 0u : 1u;
        for (size_t i = 0; i < expectedCredential_.size(); ++i) {
            const unsigned char actual = i < presented.size()
                ? static_cast<unsigned char>(presented[i]) : 0;
            diff |= static_cast<unsigned>(actual ^
                static_cast<unsigned char>(expectedCredential_[i]));
        }
        return diff == 0;
    }

    static void addEvent(int kq, int fd, int16_t filter, uint16_t flags,
                         void* udata = nullptr) {
        struct kevent ev{};
        EV_SET(&ev, static_cast<uintptr_t>(fd), filter, flags, 0, 0, udata);
        (void)::kevent(kq, &ev, 1, nullptr, 0, nullptr);
    }

    void arm(Conn* c) {
        uint16_t flags = EV_ADD | EV_ENABLE | EV_CLEAR;
        addEvent(kq_, c->clientFd, EVFILT_READ, flags, &c->clientWatch);
        const int ufd = c->upstream->nativeFd();
        addEvent(kq_, ufd, EVFILT_READ, flags, &c->upstreamWatch);
        if (c->upstreamOutPos < c->upstreamOut.size()) {
            addEvent(kq_, ufd, EVFILT_WRITE, flags, &c->upstreamWatch);
            c->upstreamWriteArmed = true;
        }
    }

    void updateWrite(Conn* c) {
        const int cfd = c->clientFd;
        const int ufd = c->upstream->nativeFd();
        const bool wantClientWrite = c->clientOutPos < c->clientOut.size();
        const bool wantUpstreamWrite = c->upstreamOutPos < c->upstreamOut.size();

        // EV_CLEAR read filters remain registered for the lifetime of the
        // connection. Do the same for write filters, changing their
        // registration only when the desired state actually changes. The
        // old implementation issued two kqueue syscalls after every read
        // and write even when neither output queue changed; at high fan-out
        // that bookkeeping became a measurable fraction of reactor CPU.
        if (wantClientWrite != c->clientWriteArmed) {
            if (wantClientWrite)
                addEvent(kq_, cfd, EVFILT_WRITE, EV_ADD | EV_ENABLE | EV_CLEAR,
                         &c->clientWatch);
            else
                addEvent(kq_, cfd, EVFILT_WRITE, EV_DELETE);
            c->clientWriteArmed = wantClientWrite;
        }
        if (wantUpstreamWrite != c->upstreamWriteArmed) {
            if (wantUpstreamWrite)
                addEvent(kq_, ufd, EVFILT_WRITE, EV_ADD | EV_ENABLE | EV_CLEAR,
                         &c->upstreamWatch);
            else
                addEvent(kq_, ufd, EVFILT_WRITE, EV_DELETE);
            c->upstreamWriteArmed = wantUpstreamWrite;
        }
    }

    void closeConn(Conn* c) {
        if (!c) return;
        if (c->clientFd >= 0) {
            addEvent(kq_, c->clientFd, EVFILT_READ, EV_DELETE);
            addEvent(kq_, c->clientFd, EVFILT_WRITE, EV_DELETE);
            ::shutdown(c->clientFd, SHUT_RDWR);
            ::close(c->clientFd);
            c->clientFd = -1;
            c->clientWriteArmed = false;
        }
        if (c->upstream) {
            const int fd = c->upstream->nativeFd();
            if (fd >= 0) {
                addEvent(kq_, fd, EVFILT_READ, EV_DELETE);
                    addEvent(kq_, fd, EVFILT_WRITE, EV_DELETE);
            }
            c->upstreamWriteArmed = false;
            c->upstream->cancel();
            c->upstream.reset();
        }
    }

    bool startRequest(Conn* c, std::string_view head) {
        std::string_view method, target;
        const bool parsed = parseRequestLine(head, method, target);
        // parseProxyRequestMeta() is already required for the authorization
        // field. Reuse that single scan instead of reparsing the complete
        // header block on every reactor request.
        const ProxyRequestMeta meta = parseProxyRequestMeta(head);
        const bool authenticated = parsed && authOk(meta);
        if (!parsed || (method != "GET" && method != "HEAD") || !authenticated) {
            if (!authenticated) {
                const std::string r = proxyAuthRequiredResponse(false);
                c->clientOut = r;
                c->clientOutPos = 0;
            } else {
                const std::string r = forbiddenResponse("HTTP reactor request not supported");
                c->clientOut = r;
                c->clientOutPos = 0;
            }
            c->responseClose = true;
            updateWrite(c);
            return false;
        }
        const std::string wire = buildWireRequest(method, target);
        if (wire.empty()) {
            const std::string r = forbiddenResponse("invalid HTTP target");
            c->clientOut = r;
            c->clientOutPos = 0;
            c->responseClose = true;
            updateWrite(c);
            return false;
        }
        c->upstreamOut = wire;
        c->upstreamOutPos = 0;
        c->responseHeadersDone = false;
        c->responseClose = false;
        c->bodyRemaining = 0;
        c->chunked = false;
        c->chunkDone = false;
        c->requestPending = true;
        updateWrite(c);
        return true;
    }

    static std::string filteredResponseHead(std::string_view raw,
                                            bool& close,
                                            bool& chunked,
                                            size_t& contentLength) {
        close = false; chunked = false; contentLength = 0;
        const size_t split = raw.find("\r\n\r\n");
        if (split == std::string::npos) return {};
        const std::string_view block = raw.substr(0, split + 2);
        std::string out;
        out.reserve(block.size() + 32);
        size_t pos = 0;
        const size_t firstEnd = block.find("\r\n");
        if (firstEnd == std::string::npos) return {};
        out.append(block.data(), firstEnd + 2);
        pos = firstEnd + 2;
        while (pos < block.size()) {
            const size_t end = block.find("\r\n", pos);
            if (end == std::string::npos || end == pos) break;
            const std::string_view line = block.substr(pos, end - pos);
            const size_t colon = line.find(':');
            if (colon == std::string::npos) return {};
            const std::string_view name = line.substr(0, colon);
            std::string_view value = line.substr(colon + 1);
            while (!value.empty() && (value.front() == ' ' || value.front() == '\t'))
                value.remove_prefix(1);
            while (!value.empty() && (value.back() == ' ' || value.back() == '\t'))
                value.remove_suffix(1);

            // Header filtering is on the response hot path.  Do not create
            // a lowercase name/value (or repeatedly erase from a temporary
            // string) just to classify a field.  The comparison is bounded
            // by the small fixed set of hop-by-hop names and is allocation-
            // free for ordinary responses.
            const auto ieq = [](std::string_view a, std::string_view b) {
                if (a.size() != b.size()) return false;
                for (size_t i = 0; i < a.size(); ++i) {
                    if (static_cast<unsigned char>(a[i]) >= 0x80 ||
                        static_cast<unsigned char>(b[i]) >= 0x80 ||
                        std::tolower(static_cast<unsigned char>(a[i])) !=
                        std::tolower(static_cast<unsigned char>(b[i]))) return false;
                }
                return true;
            };
            const auto hasToken = [&](std::string_view haystack,
                                      std::string_view token) {
                size_t start = 0;
                while (start < haystack.size()) {
                    while (start < haystack.size() &&
                           (haystack[start] == ' ' || haystack[start] == '\t' ||
                            haystack[start] == ',')) ++start;
                    size_t endToken = start;
                    while (endToken < haystack.size() && haystack[endToken] != ',')
                        ++endToken;
                    size_t first = start;
                    size_t last = endToken;
                    while (first < last && (haystack[first] == ' ' || haystack[first] == '\t')) ++first;
                    while (last > first && (haystack[last - 1] == ' ' || haystack[last - 1] == '\t')) --last;
                    if (ieq(haystack.substr(first, last - first), token)) return true;
                    start = endToken + (endToken < haystack.size() ? 1 : 0);
                }
                return false;
            };

            if (ieq(name, "connection") || ieq(name, "keep-alive") ||
                ieq(name, "proxy-authenticate") || ieq(name, "proxy-authorization") ||
                ieq(name, "te") || ieq(name, "trailer") || ieq(name, "upgrade")) {
                if (ieq(name, "connection") && hasToken(value, "close")) close = true;
            } else if (ieq(name, "transfer-encoding")) {
                if (hasToken(value, "chunked")) chunked = true;
                out.append(line.data(), line.size());
                out.append("\r\n");
            } else if (ieq(name, "content-length")) {
                size_t n = 0;
                const auto p = std::from_chars(value.data(), value.data() + value.size(), n);
                if (p.ec != std::errc{} || p.ptr != value.data() + value.size()) return {};
                contentLength = n;
                out.append(line.data(), line.size());
                out.append("\r\n");
            } else {
                out.append(line.data(), line.size());
                out.append("\r\n");
            }
            pos = end + 2;
        }
        if (!chunked && contentLength == 0) {
            // A zero-length response is self-delimiting. Unknown/no framing
            // is treated as close-delimited by the caller.
        }
        out += "\r\n";
        return out;
    }

    bool parseResponseHeaders(Conn* c) {
        const size_t end = c->upstreamIn.find("\r\n\r\n");
        if (end == std::string::npos) return false;
        bool close = false, chunked = false;
        size_t contentLength = 0;
        const std::string out = filteredResponseHead(c->upstreamIn, close, chunked, contentLength);
        if (out.empty()) return false;
        c->clientOut += out;
        c->upstreamIn.erase(0, end + 4);
        c->responseHeadersDone = true;
        c->responseClose = close;
        c->chunked = chunked;
        c->bodyRemaining = contentLength;
        if (chunked) {
            // The reactor preserves chunk framing; completion is recognized
            // conservatively below. This is only a framing boundary, never a
            // policy decision.
            c->chunkDone = false;
        } else if (contentLength == 0) {
            c->requestPending = false;
            if (c->responseClose) c->clientEof = true;
        }
        return true;
    }

    void readFd(Conn* c, bool upstream) {
        char buf[64 * 1024];
        const int fd = upstream ? c->upstream->nativeFd() : c->clientFd;
        for (;;) {
            const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
            if (n > 0) {
                if (upstream) c->upstreamIn.append(buf, static_cast<size_t>(n));
                else c->clientIn.append(buf, static_cast<size_t>(n));
                continue;
            }
            if (n == 0) {
                if (upstream) c->upstreamEof = true;
                else c->clientEof = true;
            } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
                if (upstream) c->upstreamEof = true;
                else c->clientEof = true;
            }
            break;
        }
    }

    void writeFd(Conn* c, bool upstream) {
        std::string& data = upstream ? c->upstreamOut : c->clientOut;
        size_t& pos = upstream ? c->upstreamOutPos : c->clientOutPos;
        const int fd = upstream ? c->upstream->nativeFd() : c->clientFd;
        while (pos < data.size()) {
            const ssize_t n = ::send(fd, data.data() + pos, data.size() - pos, MSG_NOSIGNAL);
            if (n > 0) { pos += static_cast<size_t>(n); continue; }
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) break;
            if (n <= 0) {
                if (upstream) c->upstreamEof = true;
                else c->clientEof = true;
                break;
            }
        }
        if (pos == data.size()) { data.clear(); pos = 0; }
        updateWrite(c);
    }

    void consumeResponse(Conn* c) {
        if (!c->responseHeadersDone) {
            if (c->upstreamIn.find("\r\n\r\n") != std::string::npos) {
                if (!parseResponseHeaders(c)) {
                    c->responseClose = true;
                    c->clientOut = forbiddenResponse("malformed upstream response");
                    c->clientOutPos = 0;
                    c->upstreamIn.clear();
                    updateWrite(c);
                    return;
                }
            }
        }
        if (!c->responseHeadersDone) return;

        if (c->chunked) {
            // We can safely stream a chunked body and identify its terminal
            // zero chunk without decoding it. Trailers remain part of the
            // forwarded framing; after the terminal CRLF the connection may
            // be reused.
            c->clientOut += c->upstreamIn;
            if (c->upstreamIn.find("0\r\n\r\n") != std::string::npos) {
                c->chunkDone = true;
                c->requestPending = false;
                c->upstreamIn.clear();
            } else {
                c->upstreamIn.clear();
            }
        } else if (c->bodyRemaining > 0) {
            const size_t n = std::min(c->bodyRemaining, c->upstreamIn.size());
            c->clientOut.append(c->upstreamIn.data(), n);
            c->upstreamIn.erase(0, n);
            c->bodyRemaining -= n;
            if (c->bodyRemaining == 0) c->requestPending = false;
        } else if (c->upstreamEof) {
            c->clientOut += c->upstreamIn;
            c->upstreamIn.clear();
            c->requestPending = false;
            c->responseClose = true;
        }
        updateWrite(c);
    }

    void maybeStartNext(Conn* c) {
        if (c->requestPending || c->clientOutPos < c->clientOut.size()) return;
        if (c->responseClose || c->clientEof || c->upstreamEof) return;
        const size_t end = c->clientIn.find("\r\n\r\n");
        if (end == std::string::npos) return;
        std::string head = c->clientIn.substr(0, end + 4);
        c->clientIn.erase(0, end + 4);
        startRequest(c, head);
    }

    void drainPending() {
        std::deque<Task> tasks;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            tasks.swap(pending_);
        }
        while (!tasks.empty()) {
            Task task = std::move(tasks.front());
            tasks.pop_front();
            if (task.clientFd < 0 || !task.upstream) continue;
            if (!setNonBlocking(task.clientFd) ||
                !setNonBlocking(task.upstream->nativeFd())) {
                ::close(task.clientFd);
                continue;
            }
            auto c = std::make_unique<Conn>();
            c->clientFd = task.clientFd;
            c->upstream = std::move(task.upstream);
            if (!startRequest(c.get(), task.head)) {
                // startRequest may have queued a deterministic 403/407.
            }
            Conn* raw = c.get();
            conns_.push_back(std::move(c));
            arm(raw);
            updateWrite(raw);
        }
    }

    void run() {
        std::array<struct kevent, 256> events{};
        while (running_ && !(stopping_ && stopping_->load(std::memory_order_relaxed))) {
            const int n = ::kevent(kq_, nullptr, 0, events.data(),
                                   static_cast<int>(events.size()), nullptr);
            if (n < 0) {
                if (errno == EINTR) continue;
                break;
            }
            for (int i = 0; i < n; ++i) {
                const auto& ev = events[static_cast<size_t>(i)];
                if (static_cast<int>(ev.ident) == wake_[0]) {
                    char buf[128];
                    while (::read(wake_[0], buf, sizeof(buf)) > 0) {}
                    wakeSignaled_.store(false, std::memory_order_release);
                    drainPending();
                    continue;
                }
                auto* watch = static_cast<Conn::Watch*>(ev.udata);
                if (!watch || !watch->conn) continue;
                Conn* c = watch->conn;
                if (c->clientFd < 0 || !c->upstream) continue;
                const int cfd = c->clientFd;
                const int ufd = c->upstream->nativeFd();
                const bool up = watch->upstream;
                if (static_cast<int>(ev.ident) != (up ? ufd : cfd)) continue;
                    if (ev.filter == EVFILT_READ) {
                        readFd(c, up);
                        if (up) consumeResponse(c);
                        else if (!c->requestPending && !c->responseHeadersDone) maybeStartNext(c);
                    } else if (ev.filter == EVFILT_WRITE) {
                        writeFd(c, up);
                        if (up) consumeResponse(c);
                        else maybeStartNext(c);
                    }
                    if (ev.flags & EV_ERROR) {
                        if (up) c->upstreamEof = true;
                        else c->clientEof = true;
                    }
                    // readFd()/writeFd()/consumeResponse()/maybeStartNext()
                    // already reconcile write-filter state. Avoid a second
                    // kqueue kevent() pass for every readiness notification.
            }
            for (auto it = conns_.begin(); it != conns_.end();) {
                Conn* c = it->get();
                if (c->clientFd < 0 ||
                    ((c->clientEof || c->responseClose) &&
                     c->clientOutPos == c->clientOut.size())) {
                    closeConn(c);
                    it = conns_.erase(it);
                } else {
                    maybeStartNext(c);
                    ++it;
                }
            }
        }
        for (auto& c : conns_) closeConn(c.get());
        conns_.clear();
    }
#endif
};

// Shared event-driven CONNECT reactor. Chromium opens many independent
// CONNECT streams for a fan-out page; giving each tunnel a native thread
// makes the proxy's concurrency ceiling the thread scheduler. Direct
// PolicyStreams expose a socket, so all of those byte pumps can instead be
// multiplexed by a small number of kqueue loops. Policy authorization and
// destination gating still happen synchronously before a stream is admitted.
class PolicyProxyServer::TunnelReactor {
public:
    explicit TunnelReactor(std::atomic<bool>* stopping) : stopping_(stopping) {}
    ~TunnelReactor() { stop(); }

    bool start() {
#if defined(__APPLE__)
        kq_ = ::kqueue();
        if (kq_ < 0 || ::pipe(wake_) != 0) { stop(); return false; }
        for (int fd : wake_) {
            const int flags = ::fcntl(fd, F_GETFL, 0);
            if (flags >= 0) ::fcntl(fd, F_SETFL, flags | O_NONBLOCK);
            ::fcntl(fd, F_SETFD, FD_CLOEXEC);
        }
        struct kevent ev{};
        EV_SET(&ev, static_cast<uintptr_t>(wake_[0]), EVFILT_READ,
               EV_ADD | EV_ENABLE, 0, 0, nullptr);
        if (::kevent(kq_, &ev, 1, nullptr, 0, nullptr) != 0) { stop(); return false; }
        running_.store(true, std::memory_order_release);
        thread_ = std::thread([this] { run(); });
        return true;
#else
        return false;
#endif
    }

    void stop() {
#if defined(__APPLE__)
        if (!running_.exchange(false)) return;
        if (wake_[1] >= 0) { const char c = 'x'; (void)::write(wake_[1], &c, 1); }
        if (thread_.joinable()) thread_.join();
        for (auto& c : conns_) closeConn(c.get());
        conns_.clear();
        if (wake_[0] >= 0) ::close(wake_[0]);
        if (wake_[1] >= 0) ::close(wake_[1]);
        wake_[0] = wake_[1] = -1;
        if (kq_ >= 0) ::close(kq_);
        kq_ = -1;
#endif
    }

    bool submit(int clientFd, PolicyStreamPtr stream) {
#if defined(__APPLE__)
        if (!running_ || !stream || stream->nativeFd() < 0) return false;
        {
            std::lock_guard<std::mutex> lk(mtx_);
            pending_.push_back(Task{clientFd, std::move(stream)});
        }
        bool expected = false;
        if (wakeSignaled_.compare_exchange_strong(
                expected, true, std::memory_order_acq_rel,
                std::memory_order_relaxed)) {
            const char c = 'x';
            if (::write(wake_[1], &c, 1) != 1) {
                wakeSignaled_.store(false, std::memory_order_release);
                return false;
            }
        }
        return true;
#else
        (void)clientFd; (void)stream; return false;
#endif
    }

private:
    struct Task { int clientFd; PolicyStreamPtr stream; };
    struct Conn {
        int clientFd = -1;
        PolicyStreamPtr stream;
        // HTTPS tunnel traffic is dominated by bursts of TLS records. Keep
        // enough room for several records so one kqueue wake can drain a
        // meaningful batch instead of bouncing between read/write events.
        // Memory cost is bounded per live tunnel and replaces the old 64 KiB
        // buffers; CONNECT streams already carry a substantially larger
        // lifetime cost than these buffers.
        std::array<uint8_t, 256 * 1024> c2u{};
        std::array<uint8_t, 256 * 1024> u2c{};
        size_t c2uPos = 0, c2uLen = 0, u2cPos = 0, u2cLen = 0;
        bool clientReadOpen = true;
        bool upstreamReadOpen = true;
        bool clientWriteArmed = false;
        bool upstreamWriteArmed = false;
    };

    std::atomic<bool>* stopping_ = nullptr;
    std::atomic<bool> running_{false};
    std::mutex mtx_;
    std::deque<Task> pending_;
    std::list<std::unique_ptr<Conn>> conns_;
    std::unordered_map<Conn*, std::list<std::unique_ptr<Conn>>::iterator> connMap_;
    std::unordered_map<int, Conn*> fdMap_;
    std::thread thread_;
    int kq_ = -1;
    std::atomic<bool> wakeSignaled_{false};
    int wake_[2] = {-1, -1};

#if defined(__APPLE__)
    static bool nonBlocking(int fd) {
        const int f = ::fcntl(fd, F_GETFL, 0);
        return f >= 0 && ::fcntl(fd, F_SETFL, f | O_NONBLOCK) == 0;
    }
    void event(int fd, int16_t filter, uint16_t flags, Conn* c = nullptr) {
        struct kevent ev{};
        EV_SET(&ev, static_cast<uintptr_t>(fd), filter, flags, 0, 0, c);
        (void)::kevent(kq_, &ev, 1, nullptr, 0, nullptr);
    }
    void update(Conn* c) {
        const int u = c->stream->nativeFd();
        const uint16_t rw = EV_ADD | EV_ENABLE | EV_CLEAR;
        // Read filters are armed once per connection. Likewise, only change
        // write-filter registration when a buffer transitions empty/nonempty;
        // re-registering both write filters on every packet burns kqueue
        // syscalls without changing readiness state.
        const bool wantClientWrite = c->u2cPos < c->u2cLen;
        const bool wantUpstreamWrite = c->c2uPos < c->c2uLen;
        if (wantClientWrite != c->clientWriteArmed) {
            event(c->clientFd, EVFILT_WRITE, wantClientWrite ? rw : EV_DELETE, c);
            c->clientWriteArmed = wantClientWrite;
        }
        if (wantUpstreamWrite != c->upstreamWriteArmed) {
            event(u, EVFILT_WRITE, wantUpstreamWrite ? rw : EV_DELETE, c);
            c->upstreamWriteArmed = wantUpstreamWrite;
        }
    }
    void closeConn(Conn* c) {
        if (!c) return;
        if (c->clientFd >= 0) {
            event(c->clientFd, EVFILT_READ, EV_DELETE, c);
            event(c->clientFd, EVFILT_WRITE, EV_DELETE);
            ::shutdown(c->clientFd, SHUT_RDWR);
            ::close(c->clientFd);
            fdMap_.erase(c->clientFd);
            c->clientFd = -1;
            c->clientWriteArmed = false;
        }
        if (c->stream) {
            const int fd = c->stream->nativeFd();
            if (fd >= 0) {
                event(fd, EVFILT_READ, EV_DELETE, c);
                event(fd, EVFILT_WRITE, EV_DELETE);
                fdMap_.erase(fd);
            }
            c->upstreamWriteArmed = false;
            c->stream->cancel();
            c->stream.reset();
        }
    }

    void eraseConn(Conn* c) {
        if (!c) return;
        // Resolve liveness before closeConn touches the object: a Conn that is
        // no longer in connMap_ has already been destroyed, and closing it
        // again would dereference freed memory.
        auto it = connMap_.find(c);
        if (it == connMap_.end()) return;
        closeConn(c);
        conns_.erase(it->second);
        connMap_.erase(it);
    }

    void drainPending() {
        std::deque<Task> tasks;
        { std::lock_guard<std::mutex> lk(mtx_); tasks.swap(pending_); }
        while (!tasks.empty()) {
            Task t = std::move(tasks.front()); tasks.pop_front();
            if (t.clientFd < 0 || !t.stream || !nonBlocking(t.clientFd) ||
                !nonBlocking(t.stream->nativeFd())) {
                if (t.clientFd >= 0) ::close(t.clientFd);
                continue;
            }
            auto c = std::make_unique<Conn>();
            c->clientFd = t.clientFd;
            c->stream = std::move(t.stream);
            Conn* raw = c.get();
            conns_.push_back(std::move(c));
            auto connIt = std::prev(conns_.end());
            connMap_[raw] = connIt;
            event(raw->clientFd, EVFILT_READ, EV_ADD | EV_ENABLE | EV_CLEAR, raw);
            event(raw->stream->nativeFd(), EVFILT_READ, EV_ADD | EV_ENABLE | EV_CLEAR, raw);
            update(raw);
        }
    }
    void readSide(Conn* c, bool client) {
        const int fd = client ? c->clientFd : c->stream->nativeFd();
        auto& buf = client ? c->c2u : c->u2c;
        size_t& pos = client ? c->c2uPos : c->u2cPos;
        size_t& len = client ? c->c2uLen : c->u2cLen;
        if (pos != len) return;
        // kqueue reports readiness, so repeatedly drain until EAGAIN. The
        // previous one-recv-per-event path created unnecessary kqueue wakeups
        // for bursty HTTPS traffic and inflated tail latency under fan-out.
        const ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
        if (n > 0) { pos = 0; len = static_cast<size_t>(n); return; }
        if (n == 0 || (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
            if (client) {
                c->clientReadOpen = false;
                c->stream->shutdownWrite();
            } else {
                c->upstreamReadOpen = false;
                ::shutdown(c->clientFd, SHUT_WR);
            }
        }
    }
    void writeSide(Conn* c, bool client) {
        const int fd = client ? c->clientFd : c->stream->nativeFd();
        auto& buf = client ? c->u2c : c->c2u;
        size_t& pos = client ? c->u2cPos : c->c2uPos;
        size_t& len = client ? c->u2cLen : c->c2uLen;
        if (pos == len) return;
        while (pos < len) {
            const ssize_t n = ::send(fd, buf.data() + pos, len - pos, MSG_NOSIGNAL);
            if (n > 0) { pos += static_cast<size_t>(n); continue; }
            if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) return;
            if (client) c->clientReadOpen = false; else c->upstreamReadOpen = false;
            return;
        }
    }
    void run() {
        std::array<struct kevent, 512> events{};
        while (running_ && !(stopping_ && stopping_->load(std::memory_order_relaxed))) {
            const int n = ::kevent(kq_, nullptr, 0, events.data(),
                                   static_cast<int>(events.size()), nullptr);
            if (n < 0) { if (errno == EINTR) continue; break; }
            for (int i = 0; i < n; ++i) {
                const auto& ev = events[static_cast<size_t>(i)];
                if (static_cast<int>(ev.ident) == wake_[0]) {
                    char b[128]; while (::read(wake_[0], b, sizeof(b)) > 0) {}
                    wakeSignaled_.store(false, std::memory_order_release);
                    drainPending(); continue;
                }
                Conn* c = static_cast<Conn*>(ev.udata);
                if (!c || c->clientFd < 0 || !c->stream) continue;
                const bool client = static_cast<int>(ev.ident) == c->clientFd;
                if (!client && static_cast<int>(ev.ident) != c->stream->nativeFd()) continue;
                if (ev.filter == EVFILT_READ) readSide(c, client);
                else if (ev.filter == EVFILT_WRITE) writeSide(c, client);
                update(c);
            }
            // Do not scan every active tunnel after every kevent batch. With
            // hundreds of CONNECT streams that turns an O(events) reactor
            // into O(events * connections). Close and erase only the
            // connections whose readiness event actually made them terminal.
            for (int i = 0; i < n; ++i) {
                const auto& ev = events[static_cast<size_t>(i)];
                if (static_cast<int>(ev.ident) == wake_[0]) continue;
                Conn* c = static_cast<Conn*>(ev.udata);
                // One connection owns up to four registrations (client and
                // upstream fd, each for read and write), so the same Conn* can
                // appear several times in a single kevent batch. Once the
                // first of those events erases it, every later event in the
                // same batch holds a dangling pointer. Look the pointer up in
                // connMap_ -- which is a well-defined operation on a freed
                // address -- before dereferencing it.
                if (!c || connMap_.find(c) == connMap_.end()) continue;
                if (c->clientFd < 0 || !c->stream) continue;
                const bool drained = c->c2uPos == c->c2uLen && c->u2cPos == c->u2cLen;
                if (!c->clientReadOpen && !c->upstreamReadOpen && drained)
                    eraseConn(c);
            }
        }
        for (auto& c : conns_) closeConn(c.get());
        connMap_.clear();
        conns_.clear();
    }
#endif
};

PolicyProxyServer::PolicyProxyServer() = default;

PolicyProxyServer::~PolicyProxyServer() { stop(); }

bool PolicyProxyServer::startHttpsProxyFrontend() {
    // Chromium can negotiate HTTP/2 to an HTTPS proxy, but proxy Basic auth
    // is not a safe authentication mechanism for this h2 frontend: a 407
    // challenge can be treated as unsupported and cause proxy fallback.
    // Do not expose an authenticated policy backend behind that failure mode.
    // Client-certificate authentication is the intended production path;
    // CEF certificate provisioning is not wired yet, so fail closed here.
    if (const char* authMode = std::getenv("LETHE_CEF_HTTPS_PROXY_AUTH");
        !authMode || std::string_view(authMode) != "client-cert") {
        std::cerr << "[lethe-proxy] secure HTTP/2 frontend requires CEF client-certificate auth; "
                     "Basic proxy auth is intentionally rejected for h2" << std::endl;
        return false;
    }
    const char* clientCaEnv = std::getenv("LETHE_CEF_PROXY_CLIENT_CA");
    std::string clientCaPath = clientCaEnv ? clientCaEnv : "";
    if (clientCaPath.empty()) {
        if (const char* home = std::getenv("HOME"); home && *home) {
            clientCaPath = std::string(home) +
                "/Library/Application Support/Lethe CEF/CEF Proxy/client-ca.crt";
        }
    }
    if (clientCaPath.empty() || ::access(clientCaPath.c_str(), R_OK) != 0) {
        std::cerr << "[lethe-proxy] secure HTTP/2 frontend requires the provisioned "
                     "CEF client CA; set LETHE_CEF_PROXY_CLIENT_CA to its PEM path"
                  << std::endl;
        return false;
    }
    const std::string nghttpx = findNghttpx();
    if (nghttpx.empty()) {
        std::cerr << "[lethe-proxy] secure HTTP/2 frontend requested but nghttpx was not found"
                  << std::endl;
        return false;
    }

    char dirTemplate[] = "/tmp/lethe-secure-proxy-XXXXXX";
    char* dir = ::mkdtemp(dirTemplate);
    if (!dir) return false;
    const std::string base(dir);
    httpsProxyKeyPath_ = base + "/proxy.key";
    httpsProxyCertPath_ = base + "/proxy.crt";
    if (!writeProxyCertificate(httpsProxyKeyPath_, httpsProxyCertPath_,
                               httpsProxySpkiSha256_)) {
        stopHttpsProxyFrontend();
        return false;
    }

    ::chmod(httpsProxyKeyPath_.c_str(), 0600);
    ::chmod(httpsProxyCertPath_.c_str(), 0600);

    const int port = reserveLoopbackPort();
    if (port <= 0) {
        stopHttpsProxyFrontend();
        return false;
    }

    const std::string frontend = "127.0.0.1," + std::to_string(port);
    const std::string backend = "127.0.0.1," + std::to_string(port_);
    httpsProxyMrubyPath_ = base + "/auth.rb";
    {
        FILE* f = std::fopen(httpsProxyMrubyPath_.c_str(), "wb");
        if (!f) {
            stopHttpsProxyFrontend();
            return false;
        }
        const std::string script =
            "class LetheAuth\n"
            "  def on_req(env)\n"
            "    if env.tls_client_subject_name != 'Lethe CEF Proxy Client'\n"
            "      env.resp.status = 403\n"
            "      env.resp.return 'client certificate rejected'\n"
            "      return\n"
            "    end\n"
            "    env.req.set_header('x-lethe-proxy-auth', '" + opts_.authToken + "')\n"
            "  end\n"
            "end\n"
            "LetheAuth.new\n";
        const size_t written = std::fwrite(script.data(), 1, script.size(), f);
        std::fclose(f);
        if (written != script.size()) {
            stopHttpsProxyFrontend();
            return false;
        }
        ::chmod(httpsProxyMrubyPath_.c_str(), 0600);
    }
    const std::string configPath = base + "/nghttpx.conf";
    httpsProxyConfigPath_ = configPath;
    {
        FILE* f = std::fopen(configPath.c_str(), "wb");
        if (!f) {
            stopHttpsProxyFrontend();
            return false;
        }
        const std::string config =
            "http2-proxy=yes\n"
            "frontend=" + frontend + "\n"
            "backend=" + backend + "\n"
            "private-key-file=" + httpsProxyKeyPath_ + "\n"
            "certificate-file=" + httpsProxyCertPath_ + "\n"
            "verify-client=yes\n"
            "verify-client-cacert=" + clientCaPath + "\n"
            "mruby-file=" + httpsProxyMrubyPath_ + "\n"
            "frontend-http2-max-concurrent-streams=1000\n"
            "frontend-http2-window-size=1048576\n"
            "frontend-http2-connection-window-size=16777216\n"
            "backend-connections-per-host=64\n"
            "workers=2\n"
            "errorlog-file=" +
            (std::getenv("LETHE_DEBUG") ? "/tmp/lethe-nghttpx-error.log\n"
                                          : "/dev/stderr\n");
        const size_t written = std::fwrite(config.data(), 1, config.size(), f);
        std::fclose(f);
        if (written != config.size()) {
            stopHttpsProxyFrontend();
            return false;
        }
        ::chmod(configPath.c_str(), 0600);
    }
    std::vector<std::string> args = {
        nghttpx, "--conf=" + configPath
    };
    if (std::getenv("LETHE_DEBUG") != nullptr) {
        args.push_back("--accesslog-file=/tmp/lethe-nghttpx-access.log");
        args.push_back("--accesslog-format=$alpn $request $status");
    }

    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (auto& arg : args) argv.push_back(arg.data());
    argv.push_back(nullptr);

    int stderrPipe[2] = {-1, -1};
    if (::pipe(stderrPipe) != 0) {
        stopHttpsProxyFrontend();
        return false;
    }
    pid_t pid = ::fork();
    if (pid == 0) {
        ::close(stderrPipe[0]);
        ::dup2(stderrPipe[1], STDERR_FILENO);
        ::close(stderrPipe[1]);
        ::execv(argv[0], argv.data());
        _exit(127);
    }
    if (pid < 0) {
        ::close(stderrPipe[0]);
        ::close(stderrPipe[1]);
        stopHttpsProxyFrontend();
        return false;
    }
    ::close(stderrPipe[1]);
    const int flags = ::fcntl(stderrPipe[0], F_GETFL, 0);
    if (flags >= 0) ::fcntl(stderrPipe[0], F_SETFL, flags | O_NONBLOCK);
    httpsProxyPid_ = static_cast<int>(pid);
    httpsProxyPort_ = port;

    // Wait for the TLS listener to accept connections. This is bounded so a
    // broken helper cannot stall browser startup indefinitely.
    for (int i = 0; i < 100; ++i) {
        char logBuf[2048];
        const ssize_t logN = ::read(stderrPipe[0], logBuf, sizeof(logBuf) - 1);
        if (logN > 0) {
            logBuf[logN] = '\0';
            const std::string log(logBuf, static_cast<size_t>(logN));
        }
        int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        bool ready = false;
        if (fd >= 0) {
            sockaddr_in addr{};
            addr.sin_family = AF_INET;
            addr.sin_port = htons(static_cast<uint16_t>(port));
            ::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
            ready = ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
            ::close(fd);
        }
        if (ready) {
            ::close(stderrPipe[0]);
            // The configuration contains the per-launch policy capability.
            // Remove it as soon as nghttpx has parsed it so the token is not
            // left on disk and is not recoverable from the child argv.
            ::unlink(configPath.c_str());
            ::unlink(httpsProxyMrubyPath_.c_str());
            std::cout << "[lethe-proxy] secure HTTP/2 frontend: 127.0.0.1:"
                      << port << std::endl;
            return true;
        }
        int status = 0;
        const pid_t rc = ::waitpid(static_cast<pid_t>(httpsProxyPid_), &status, WNOHANG);
        if (rc == static_cast<pid_t>(httpsProxyPid_)) {
            httpsProxyPid_ = -1;
            break;
        }
        ::usleep(10000);
    }
    ::close(stderrPipe[0]);
    ::unlink(configPath.c_str());
    stopHttpsProxyFrontend();
    return false;
}

void PolicyProxyServer::stopHttpsProxyFrontend() {
    if (httpsProxyPid_ > 0) {
        ::kill(static_cast<pid_t>(httpsProxyPid_), SIGTERM);
        int status = 0;
        for (int i = 0; i < 100; ++i) {
            const pid_t rc = ::waitpid(static_cast<pid_t>(httpsProxyPid_), &status, WNOHANG);
            if (rc == static_cast<pid_t>(httpsProxyPid_)) break;
            ::usleep(10000);
        }
        if (::waitpid(static_cast<pid_t>(httpsProxyPid_), &status, WNOHANG) == 0) {
            ::kill(static_cast<pid_t>(httpsProxyPid_), SIGKILL);
            ::waitpid(static_cast<pid_t>(httpsProxyPid_), &status, 0);
        }
    }
    httpsProxyPid_ = -1;
    httpsProxyPort_.store(0, std::memory_order_relaxed);
    if (!httpsProxyKeyPath_.empty()) ::unlink(httpsProxyKeyPath_.c_str());
    if (!httpsProxyCertPath_.empty()) ::unlink(httpsProxyCertPath_.c_str());
    if (!httpsProxyConfigPath_.empty()) ::unlink(httpsProxyConfigPath_.c_str());
    if (!httpsProxyKeyPath_.empty()) {
        std::string dir = httpsProxyKeyPath_;
        const size_t slash = dir.rfind('/');
        if (slash != std::string::npos) {
            dir.resize(slash);
            ::rmdir(dir.c_str());
        }
    }
    httpsProxyKeyPath_.clear();
    httpsProxyCertPath_.clear();
    httpsProxyConfigPath_.clear();
    httpsProxySpkiSha256_.clear();
}

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
    // The proxy is a per-launch capability boundary. Never let its listening
    // socket leak into a child process created by the browser/application.
    if (::fcntl(listenFd_, F_SETFD, FD_CLOEXEC) != 0) {
        lastError_ = "fcntl(FD_CLOEXEC) failed";
        ::close(listenFd_);
        listenFd_ = -1;
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
    // Match the bounded application queue. A small kernel listen backlog can
    // otherwise reject bursts before our own 256-connection admission
    // control gets a chance to return a deterministic 503.
    if (::bind(listenFd_, reinterpret_cast<sockaddr*>(&addr),
               sizeof(addr)) != 0 ||
        ::listen(listenFd_, 256) != 0) {
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
        // CONNECT tunnels have their own native tunnel workers. A modest
        // amount of over-subscription is nevertheless useful for the HTTP
        // request pool because workers spend time in socket I/O while the
        // browser fans out many short-lived subresources. On the M4 Max
        // 16-core reference host, a fresh 3-run extreme-net sweep measured
        // 32 workers at 5.66k/5.89k/6.00k RPS versus 20 workers at
        // 5.18k/5.46k/5.60k RPS. Keep the default bounded and derive it from
        // hardware rather than hard-coding the reference host's count.
        workerCount_ = hc == 0
            ? 32
            : std::clamp<size_t>(static_cast<size_t>(hc) * 3, 16, 32);
    }
    // Cap at a sane number: each worker is a real thread. The automatic
    // policy never exceeds 32; an explicit setting may still be used when
    // profiling a different host/workload.
    if (workerCount_ > 32) workerCount_ = 32;
    workers_.reserve(workerCount_);
    for (size_t i = 0; i < workerCount_; ++i) {
        workers_.emplace_back([this] { workerLoop(); });
    }
    // CONNECT admission has a materially different cost profile from a
    // normal proxy request: dialPolicyChecked() may block on DoH and TCP
    // establishment. Keep that latency off the request pool so a browser
    // opening dozens of HTTPS origins does not serialize CONNECT admission
    // behind the ordinary HTTP worker count. The pool is bounded; the
    // authenticated policy gate itself remains unchanged.
    {
        unsigned hc = std::thread::hardware_concurrency();
        // CONNECT admission is I/O-bound, but the tunnel itself is already
        // event-driven on macOS. A 4x hardware-concurrency admission pool
        // therefore spends CPU scheduling threads that mostly wait on the
        // same upstream dial path. The current M4 Max sweep showed 32
        // admission workers preserve page-load behavior while removing half
        // the idle thread footprint of the old 64-worker default.
        connectWorkerCount_ = hc == 0
            ? 16
            : std::clamp<size_t>(static_cast<size_t>(hc) * 2, 16, 32);
        if (const char* env = std::getenv("LETHE_CONNECT_WORKERS")) {
            char* end = nullptr;
            const unsigned long n = std::strtoul(env, &end, 10);
            if (end != env && *end == '\0' && n >= 1)
                connectWorkerCount_ = std::clamp<size_t>(n, 1, 128);
        }
        connectWorkers_.reserve(connectWorkerCount_);
        for (size_t i = 0; i < connectWorkerCount_; ++i) {
            connectWorkers_.emplace_back([this] { connectWorkerLoop(); });
        }
    }
    if (opts_.enableHttpReactor) {
        const size_t shardCount = std::clamp<size_t>(opts_.httpReactorShards, 1, 8);
        bool reactorOk = true;
        for (size_t i = 0; i < shardCount; ++i) {
            auto reactor = std::make_unique<HttpForwardReactor>(
                dialConfig(), expectedAuthCredential_, &stopping_);
            if (!reactor->start()) {
                reactorOk = false;
                break;
            }
            httpReactors_.push_back(std::move(reactor));
        }
        if (!reactorOk || httpReactors_.size() != shardCount) {
            for (auto& reactor : httpReactors_) reactor->stop();
            httpReactors_.clear();
            std::cerr << "[lethe-proxy] HTTP reactor unavailable; using worker forwarding"
                      << std::endl;
        } else {
            std::cout << "[lethe-proxy] HTTP forwarding reactor: kqueue shards="
                      << httpReactors_.size() << std::endl;
        }
    }
    // CONNECT is the dominant CEF HTTPS path. Keep it event-driven too:
    // HTTP/1.1 CONNECT itself is only the admission handshake; once the
    // tunnel is established, a shared kqueue reactor removes the old
    // one-thread-per-origin ceiling.
#if defined(__APPLE__)
    {
        const size_t shardCount = std::clamp<size_t>(opts_.httpReactorShards, 1, 8);
        bool reactorOk = true;
        for (size_t i = 0; i < shardCount; ++i) {
            auto reactor = std::make_unique<TunnelReactor>(&stopping_);
            if (!reactor->start()) { reactorOk = false; break; }
            tunnelReactors_.push_back(std::move(reactor));
        }
        if (!reactorOk || tunnelReactors_.size() != shardCount) {
            for (auto& reactor : tunnelReactors_) reactor->stop();
            tunnelReactors_.clear();
            std::cerr << "[lethe-proxy] CONNECT reactor unavailable; using tunnel workers"
                      << std::endl;
        } else {
            std::cout << "[lethe-proxy] CONNECT reactor: kqueue shards="
                      << tunnelReactors_.size() << std::endl;
        }
    }
#endif
    std::cout << "[lethe-proxy] worker pool: " << workerCount_ << " threads"
              << std::endl;
    running_ = true;
    acceptThread_ = std::thread([this] { acceptLoop(); });
    if (opts_.enableHttpsProxy && !startHttpsProxyFrontend()) {
        lastError_ = "secure HTTP/2 proxy frontend failed to start";
        stop();
        return false;
    }
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

void PolicyProxyServer::reapTunnelWorkers() {
    std::vector<std::thread> finished;
    {
        std::lock_guard<std::mutex> lk(tunnelWorkers_mtx_);
        for (auto it = tunnelWorkers_.begin(); it != tunnelWorkers_.end();) {
            if (!it->done->load(std::memory_order_acquire)) {
                ++it;
                continue;
            }
            if (it->thread.joinable()) finished.emplace_back(std::move(it->thread));
            it = tunnelWorkers_.erase(it);
        }
    }
    // Join outside the bookkeeping lock. Completed threads should return
    // immediately, and this keeps stop()/new CONNECTs from serializing on
    // thread destruction.
    for (auto& t : finished) if (t.joinable()) t.join();
}

void PolicyProxyServer::stop() {
    if (!running_.exchange(false)) return;
    stopHttpsProxyFrontend();
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
    {
        std::lock_guard<std::mutex> lk(connectQueue_mtx_);
        for (auto& task : connectQueue_) {
            if (task.clientFd >= 0) {
                ::shutdown(task.clientFd, SHUT_RDWR);
                ::close(task.clientFd);
                untrackFd(task.clientFd);
                task.clientFd = -1;
            }
        }
        connectQueue_.clear();
        for (size_t i = 0; i < connectWorkers_.size(); ++i)
            connectQueue_.push_back(ConnectTask{-1, {}, 0});
    }
    connectQueue_cv_.notify_all();
    for (auto& t : connectWorkers_) if (t.joinable()) t.join();
    connectWorkers_.clear();
    for (auto& reactor : httpReactors_) reactor->stop();
    for (auto& reactor : tunnelReactors_) reactor->stop();
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
    httpReactors_.clear();
    tunnelReactors_.clear();
    {
        std::lock_guard<std::mutex> lk(tunnelWorkers_mtx_);
        for (auto& t : tunnelWorkers_) if (t.thread.joinable()) t.thread.join();
        tunnelWorkers_.clear();
    }
}

void PolicyProxyServer::connectWorkerLoop() {
    for (;;) {
        ConnectTask task;
        {
            std::unique_lock<std::mutex> lk(connectQueue_mtx_);
            connectQueue_cv_.wait(lk, [&] { return !connectQueue_.empty(); });
            task = std::move(connectQueue_.front());
            connectQueue_.pop_front();
        }
        if (task.clientFd == -1) return;
        if (isStopping()) {
            ::close(task.clientFd);
            untrackFd(task.clientFd);
            continue;
        }
        serveConnect(task.clientFd, std::move(task.host), task.port);
    }
}

void PolicyProxyServer::serveConnect(int clientFd, std::string host, int port) {
    const HttpClient::PolicyDialConfig cfg = dialConfig();
    HttpClient::PolicyDialConfig rawCfg = cfg;
    rawCfg.rawTunnel = true;
    std::string err;

    auto t0 = std::chrono::steady_clock::now();
    auto stream = HttpClient::dialPolicyChecked(rawCfg, "https", host, port, err);
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
        untrackFd(clientFd);
        return;
    }

    static constexpr char kEstablished[] =
        "HTTP/1.1 200 Connection Established\r\n\r\n";
    if (!sendAll(clientFd, kEstablished, sizeof(kEstablished) - 1)) {
        stream->cancel();
        ::close(clientFd);
        untrackFd(clientFd);
        return;
    }

    if (!tunnelReactors_.empty() && stream->nativeFd() >= 0) {
        const size_t idx =
            tunnelReactorRoundRobin_.fetch_add(1, std::memory_order_relaxed) %
            tunnelReactors_.size();
        if (tunnelReactors_[idx]->submit(clientFd, std::move(stream))) {
            untrackFd(clientFd);
            return;
        }
    }

    // Relay-backed streams or an unavailable reactor retain the bounded
    // fallback. The admission thread is no longer part of this lifetime.
    auto done = std::make_shared<std::atomic<bool>>(false);
    std::thread tunnel([this, clientFd, stream = std::move(stream), done]() mutable {
        std::atomic<bool> tunnelDone{false};
        std::thread up([&] {
            uint8_t buf[262144];
            while (!tunnelDone.load(std::memory_order_relaxed) && !isStopping()) {
                ssize_t r = ::recv(clientFd, buf, sizeof(buf), 0);
                if (r <= 0) break;
                if (!stream->write(buf, static_cast<size_t>(r))) break;
            }
            stream->shutdownWrite();
            tunnelDone.store(true, std::memory_order_relaxed);
        });
        uint8_t buf[262144];
        while (!tunnelDone.load(std::memory_order_relaxed) && !isStopping()) {
            ssize_t r = stream->read(buf, sizeof(buf), 5000);
            if (r <= 0) break;
            if (!sendAll(clientFd, reinterpret_cast<const char*>(buf),
                         static_cast<size_t>(r))) break;
        }
        tunnelDone.store(true, std::memory_order_relaxed);
        stream->cancel();
        ::shutdown(clientFd, SHUT_RDWR);
        up.join();
        ::close(clientFd);
        untrackFd(clientFd);
        done->store(true, std::memory_order_release);
    });
    reapTunnelWorkers();
    {
        std::lock_guard<std::mutex> lk(tunnelWorkers_mtx_);
        if (tunnelWorkers_.size() >= kMaxTunnelWorkers) {
            // The CONNECT was authenticated and policy-checked, but the
            // fallback worker ceiling is exhausted. Close rather than grow
            // an unbounded thread set.
            ::shutdown(clientFd, SHUT_RDWR);
            tunnel.join();
            untrackFd(clientFd);
            return;
        }
        tunnelWorkers_.push_back(TunnelWorker{std::move(tunnel), std::move(done)});
    }
}

void PolicyProxyServer::acceptLoop() {
    while (running_) {
        int fd = ::accept(listenFd_, nullptr, nullptr);
        if (fd < 0) break;
        if (::fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
            ::close(fd);
            continue;
        }
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
        if (fd == -1) return;
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
    // Header reads are blocking, but bounded. SO_RCVTIMEO removes one poll()
    // syscall from every proxy request while retaining the slowloris guard.
    timeval headerTimeout{};
    headerTimeout.tv_sec = 5;
    headerTimeout.tv_usec = 0;
    ::setsockopt(clientFd, SOL_SOCKET, SO_RCVTIMEO,
                 &headerTimeout, sizeof(headerTimeout));
    // A local browser normally drains proxy responses immediately. Keep a
    // bounded write timeout as well so an untrusted local peer cannot hold a
    // request worker indefinitely by accepting bytes slowly. CONNECT tunnels
    // are handled by their own poll-driven loop and are intentionally not
    // subject to this response-write timeout.
    timeval writeTimeout{};
    writeTimeout.tv_sec = 15;
    writeTimeout.tv_usec = 0;
    ::setsockopt(clientFd, SOL_SOCKET, SO_SNDTIMEO,
                 &writeTimeout, sizeof(writeTimeout));
    // Loopback leg of the tunnel: engine <-> proxy. Small TLS records must
    // not sit in Nagle's buffer waiting for an ACK.
    int nodelay = 1;
    ::setsockopt(clientFd, IPPROTO_TCP, TCP_NODELAY, &nodelay, sizeof(nodelay));

    // HTTP/1.1 proxy connections are persistent by default. Keep the
    // downstream leg alive for body-less GET/HEAD requests so a browser can
    // reuse its proxy sockets while the thread-local HttpClient reuses the
    // corresponding origin connection. Requests with a body or explicit
    // close remain single-shot until full request-body framing is added.
    // Keep the request buffer on the worker's stack lifetime rather than
    // allocating a fresh heap buffer for every persistent request. readHead()
    // clears the string but retains its capacity, which is especially useful
    // for the many small subresource requests generated by a modern page.
    std::string head;
    head.reserve(4096);
    thread_local std::string responseHead;
    responseHead.reserve(1024);

    for (;;) {
    // method, target, and proxy metadata are string_views into the request
    // head, so the head must outlive the authentication retry loop.
    std::string_view method;
    std::string_view target;
    bool requestHttp11 = false;
    ProxyRequestMeta meta;
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
        const size_t versionPos = line.rfind("HTTP/");
        requestHttp11 = versionPos != std::string_view::npos &&
            line.size() >= versionPos + 8 && line.substr(versionPos) == "HTTP/1.1";

        // Authenticate FIRST: an unauthenticated peer gets no policy work,
        // no DoH traffic and no upstream socket - nothing it can measure.
        // Chromium owns Proxy-Authorization for CONNECT and CEF does not
        // expose a safe way to pre-stamp it on every new proxy connection.
        // Do not replace it with a normal request header: for HTTPS that
        // header would travel inside the end-to-end tunnel to the origin.
        meta = parseProxyRequestMeta(head);
        if (opts_.authToken.empty()) break;
        if (!meta.internalAuthToken.empty()) {
            const std::string_view presented = meta.internalAuthToken;
            const std::string& expectedToken = opts_.authToken;
            bool ok = presented.size() == expectedToken.size();
            unsigned diff = ok ? 0 : 1;
            for (size_t i = 0; i < expectedToken.size(); ++i) {
                const unsigned char actual =
                    i < presented.size() ? static_cast<unsigned char>(presented[i]) : 0;
                diff |= static_cast<unsigned>(actual ^
                    static_cast<unsigned char>(expectedToken[i]));
            }
            if (diff == 0) break;
        }
        const std::string_view presented = meta.proxyAuthorization;
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
    continue;
    }
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

        // CONNECT admission can block on DoH/TCP setup. Do not spend one of
        // the ordinary request workers waiting for that operation. Transfer
        // ownership to the bounded CONNECT admission pool; it performs the
        // exact same policy gate and then hands direct streams to the kqueue
        // tunnel reactor.
        guard.self = nullptr;
        {
            std::lock_guard<std::mutex> lk(connectQueue_mtx_);
            if (connectQueue_.size() >= kMaxQueuedConnections) {
                static constexpr char kBusy[] =
                    "HTTP/1.1 503 Service Unavailable\r\n"
                    "Connection: close\r\nContent-Length: 0\r\n\r\n";
                sendAll(clientFd, kBusy, sizeof(kBusy) - 1);
                ::close(clientFd);
                untrackFd(clientFd);
                guard.self = nullptr;
                return;
            }
            trackFd(clientFd);
            connectQueue_.push_back(ConnectTask{clientFd, std::move(host), port});
        }
        connectQueue_cv_.notify_one();
        return;
    }

    const HttpClient::PolicyDialConfig cfg = dialConfig();

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

    // Reuse the single header scan performed above for both authentication
    // and connection framing metadata.
    const std::string_view requestConnection = meta.connection;
    const std::string_view proxyConnection = meta.proxyConnection;
    const bool clientRequestedClose =
        headerValueHasToken(requestConnection, "close") ||
        headerValueHasToken(proxyConnection, "close");
    const bool hasRequestBody =
        !meta.contentLength.empty() || !meta.transferEncoding.empty();
    const bool downstreamKeepAlive = requestHttp11 && !clientRequestedClose &&
        !hasRequestBody && (method == "GET" || method == "HEAD");

    // Hand off body-less plain HTTP after authentication and policy-gated
    // upstream establishment. The worker does not remain blocked on the
    // response; the shared kqueue reactor owns both sockets. CONNECT and
    // anything requiring the existing HttpClient response semantics remain
    // on the established paths below.
    if (!httpReactors_.empty() && downstreamKeepAlive &&
        (method == "GET" || method == "HEAD")) {
        const size_t slash = target.find('/', 7);
        const std::string_view authority = target.substr(
            7, slash == std::string::npos ? target.size() - 7 : slash - 7);
        if (!authority.empty()) {
            std::string host;
            int port = 80;
            std::string path;
            if (target.rfind("http://", 0) == 0) {
                // Mirror the reactor's strict target parser here so the
                // policy dial cannot be redirected to a different endpoint
                // than the wire request it will later emit.
                if (authority.front() == '[') {
                    const size_t close = authority.find(']');
                    if (close != std::string::npos) {
                        host = std::string(authority.substr(1, close - 1));
                        if (close + 1 < authority.size() && authority[close + 1] == ':') {
                            const auto p = std::from_chars(
                                authority.data() + close + 2,
                                authority.data() + authority.size(), port);
                            if (p.ec != std::errc{} ||
                                p.ptr != authority.data() + authority.size()) host.clear();
                        }
                    }
                } else {
                    const size_t colon = authority.rfind(':');
                    if (colon == std::string::npos) host = std::string(authority);
                    else {
                        host = std::string(authority.substr(0, colon));
                        const auto p = std::from_chars(
                            authority.data() + colon + 1,
                            authority.data() + authority.size(), port);
                        if (p.ec != std::errc{} ||
                            p.ptr != authority.data() + authority.size()) host.clear();
                    }
                }
                path = slash == std::string::npos ? "/" : std::string(target.substr(slash));
            }
            if (!host.empty() && port >= 1 && port <= 65535) {
                std::string err;
                auto stream = HttpClient::dialPolicyChecked(cfg, "http", host, port, err);
                if (stream && stream->nativeFd() >= 0) {
                    const size_t idx =
                        httpReactorRoundRobin_.fetch_add(1, std::memory_order_relaxed) %
                        httpReactors_.size();
                    if (httpReactors_[idx]->submit(clientFd, std::move(head),
                                                   std::move(stream))) {
                    guard.self = nullptr;
                    return;
                    }
                }
                if (!stream && getenv("LETHE_DEBUG")) {
                    std::cout << "[lethe-proxy] HTTP reactor policy/dial fallback: "
                              << err << std::endl;
                }
            }
        }
    }

    // -- v0.2.x perf: thread-local per-origin client pool ----------------
    // A single client per worker only reuses a connection when the browser's
    // downstream proxy socket happens to land on the same worker AND origin.
    // Modern pages fan out across several proxy connections, so keep a tiny
    // bounded set of origin clients per worker. Each HttpClient remains
    // thread-confined; there is no cross-thread locking on the hot path.
    // Four entries are enough to capture the common document + CDN pattern
    // without turning the proxy into a large idle-socket cache.
    struct ThreadClient {
        std::string origin;
        std::unique_ptr<HttpClient> client;
    };
    thread_local std::vector<ThreadClient> clientPool;
    constexpr size_t kMaxThreadClients = 4;

    const size_t slash = target.find('/', 7);
    const std::string_view poolKey =
        target.substr(0, slash == std::string::npos ? target.size() : slash);
    auto poolIt = std::find_if(clientPool.begin(), clientPool.end(),
        [&](const ThreadClient& entry) {
            return entry.origin.size() == poolKey.size() &&
                   std::memcmp(entry.origin.data(), poolKey.data(), poolKey.size()) == 0;
        });
    if (poolIt == clientPool.end()) {
        if (clientPool.size() >= kMaxThreadClients) {
            // Evict the oldest entry. Its destructor closes any idle origin
            // connection, bounding file descriptors and TLS state per worker.
            clientPool.erase(clientPool.begin());
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
        clientPool.push_back(ThreadClient{std::string(poolKey), std::move(client)});
        poolIt = clientPool.end() - 1;
    }
    HttpClient* client = poolIt->client.get();

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

    responseHead.clear();
    std::string& out = responseHead;
    out.reserve(512 + resp.headers.size() * 48);
    out += "HTTP/1.1 ";
    out += std::to_string(resp.statusCode);
    out += " OK\r\n";
    for (const auto& h : resp.headers) {
        // Hop-by-hop and framing headers are re-derived, never forwarded.
        if (isHopByHopHeader(h.first))
            continue;
        // Append in place.  operator+(string,string) creates a temporary for
        // every upstream header and is surprisingly visible at thousands of
        // tiny responses per second.
        out += h.first;
        out += ": ";
        out += h.second;
        out += "\r\n";
    }
    out += "Content-Length: " + std::to_string(resp.body.size()) + "\r\n";
    out += std::string("Connection: ") +
           (downstreamKeepAlive ? "keep-alive" : "close") + "\r\n\r\n";
    sendAllParts(clientFd, out.data(), out.size(),
                 reinterpret_cast<const char*>(resp.body.data()), resp.body.size());
    if (!downstreamKeepAlive) {
        ::close(clientFd);
        return;
    }
    // The response body is fully buffered before this point, so the
    // downstream message is self-delimited and the next request can safely
    // begin on the same socket. This is the persistence condition required
    // by RFC 9112; body-bearing requests intentionally take the close path.
    }
    return;
}

} // namespace lethe
