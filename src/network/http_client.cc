// http_client.cc - HTTP/HTTPS client with live socket I/O
//
// Implements real network fetching:
//   - TCP connect with timeout (IPv4/IPv6 via getaddrinfo)
//   - TLS handshake via OpenSSL (SNI, version policy, certificate verification)
//   - HTTP/1.1 request writing and response parsing
//   - Content-Length, chunked transfer-encoding, and read-until-close bodies
//   - gzip/deflate response decompression (zlib)
//   - Redirect following (3xx + Location, up to 5 hops)

#include "network/http_client.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cctype>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <netdb.h>
#include <sstream>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>

#ifdef HAVE_OPENSSL
#include <openssl/err.h>
#endif

#include "config.h"

namespace lethe {

namespace {

constexpr size_t kReadChunkSize = 16384;
constexpr size_t kMaxResponseSize = 32 * 1024 * 1024; // 32 MiB safety cap
constexpr int kMaxRedirects = 5;

std::string toLowerCopy(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string trimCopy(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

std::string getHeader(const std::map<std::string, std::string>& headers,
                      const std::string& name) {
    auto it = headers.find(toLowerCopy(name));
    if (it == headers.end()) return "";
    return it->second;
}

// Resolve an absolute or relative Location header against a base URL.
std::string resolveUrl(const std::string& base, const std::string& location) {
    if (location.empty()) return base;
    // Already an absolute URL.
    if (location.rfind("http://", 0) == 0 || location.rfind("https://", 0) == 0) {
        return location;
    }

    // Extract "scheme://host[:port]" (the origin) from the base URL.
    size_t schemeEnd = base.find("://");
    if (schemeEnd == std::string::npos) return location;
    std::string scheme = base.substr(0, schemeEnd + 3); // e.g. "http://"
    size_t hostStart = schemeEnd + 3;
    size_t hostEnd = base.find('/', hostStart);
    std::string authority = (hostEnd == std::string::npos)
                                ? base.substr(hostStart)
                                : base.substr(hostStart, hostEnd - hostStart);
    std::string origin = scheme + authority; // e.g. "http://127.0.0.1:8080"

    if (location.rfind("//", 0) == 0) {
        // Protocol-relative: //host/path
        return scheme + location;
    }
    if (location.rfind("/", 0) == 0) {
        // Absolute path: /path
        return origin + location;
    }
    // Relative path: append under the origin root.
    return origin + "/" + location;
}

} // namespace

HttpClient::HttpClient() : initialized_(false) {}

HttpClient::~HttpClient() {
    shutdown();
}

bool HttpClient::initialize(const TLSConfig& tlsConfig) {
    tlsConfig_ = tlsConfig;

#ifdef HAVE_OPENSSL
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
#endif

    std::cout << "[lethe] HTTP client initialized (TLS "
              << tlsConfig_.getMinVersion() << "+)" << std::endl;

    initialized_ = true;
    return true;
}

HttpResponse HttpClient::sendRequest(const HttpRequest& req) {
    HttpResponse resp;

    if (!initialized_) {
        resp.error = "HTTP client not initialized";
        return resp;
    }
    if (req.url.empty()) {
        resp.error = "Empty URL";
        return resp;
    }

    std::string currentUrl = req.url;
    HttpRequest currentReq = req;

    for (int redirect = 0; redirect <= kMaxRedirects; redirect++) {
        std::string scheme, host, path;
        int port = 0;
        parseUrl(currentUrl, scheme, host, path, port);

        if (host.empty()) {
            resp.error = "Invalid URL: " + currentUrl;
            return resp;
        }

        // Built-in VPN routing policy — fail closed. A destination covered
        // by the tunnel's allowed CIDRs must never be fetched in plaintext:
        // if the tunnel is configured for this host but not connected, the
        // request is blocked rather than silently leaked.
        if (vpnTunnel_ && vpnTunnel_->shouldRouteThroughVpn(host) && !isVpnActive()) {
            closeConnection();
            resp.error = "Blocked: " + host + " requires the VPN tunnel "
                         "(allowed CIDR match) but the tunnel is down";
            std::cerr << "[lethe-http] " << resp.error << std::endl;
            return resp;
        }
        const bool viaVpn = isVpnActive() && vpnTunnel_->shouldRouteThroughVpn(host);

        std::cout << "[lethe-http] "
                  << (currentReq.method == HttpMethod::GET ? "GET" : "REQ")
                  << " " << currentUrl << (viaVpn ? " (via VPN)" : "") << std::endl;

        if (!connectToHost(host, port, scheme, currentReq.timeout)) {
            resp.error = "Connection failed to " + host + ":" + std::to_string(port);
            return resp;
        }

        std::string httpRequest = buildHttpRequest(currentReq, host, path, port);
        if (!writeAll(httpRequest.data(), httpRequest.size())) {
            closeConnection();
            resp.error = "Failed to write request to " + host;
            return resp;
        }

        if (!readFullResponse(resp)) {
            closeConnection();
            if (resp.error.empty()) resp.error = "Failed to read response from " + host;
            return resp;
        }

        closeConnection();

        // Follow redirects.
        if (resp.statusCode >= 300 && resp.statusCode < 400) {
            std::string location = getHeader(resp.headers, "location");
            if (location.empty()) {
                resp.error = "Redirect without Location header";
                return resp;
            }
            if (redirect == kMaxRedirects) {
                resp.error = "Too many redirects";
                return resp;
            }
            currentUrl = resolveUrl(currentUrl, location);
            // Redirects to a different host with POST become GET.
            if (currentReq.method == HttpMethod::POST) {
                currentReq.method = HttpMethod::GET;
                currentReq.body.clear();
            }
            continue;
        }

        resp.finalUrl = currentUrl;
        return resp;
    }

    resp.error = "Too many redirects";
    return resp;
}

void HttpClient::setVpnTunnel(std::shared_ptr<vpn::VpnTunnel> tunnel) {
    vpnTunnel_ = std::move(tunnel);
    if (vpnTunnel_) {
        std::cout << "[lethe] VPN tunnel attached to HTTP client" << std::endl;
    }
}

bool HttpClient::isVpnActive() const {
    return vpnTunnel_ && vpnTunnel_->isConnected();
}

void HttpClient::shutdown() {
    closeConnection();
    if (initialized_) {
        initialized_ = false;
        std::cout << "[lethe] HTTP client shut down" << std::endl;
    }
}

// --- Connection management ---

bool HttpClient::connectToHost(const std::string& host, int port,
                               const std::string& scheme,
                               const std::chrono::seconds timeout) {
    closeConnection();
    ioTimeout_ = std::chrono::duration_cast<std::chrono::milliseconds>(timeout);

    addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* res = nullptr;
    std::string portStr = std::to_string(port);
    int rc = ::getaddrinfo(host.c_str(), portStr.c_str(), &hints, &res);
    if (rc != 0 || !res) {
        std::cerr << "[lethe-http] DNS resolution failed for " << host
                  << ": " << gai_strerror(rc) << std::endl;
        return false;
    }

    int connectedFd = -1;
    for (addrinfo* rp = res; rp && connectedFd < 0; rp = rp->ai_next) {
        int fd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        // Non-blocking connect + select to enforce the timeout.
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        int crc = ::connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (crc == 0) {
            fcntl(fd, F_SETFL, flags);
            connectedFd = fd;
        } else if (errno == EINPROGRESS) {
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(fd, &wfds);
            timeval tv;
            tv.tv_sec = static_cast<time_t>(timeout.count() / 1000);
            tv.tv_usec = static_cast<suseconds_t>((timeout.count() % 1000) * 1000);
            int sel = ::select(fd + 1, nullptr, &wfds, nullptr, &tv);
            if (sel > 0) {
                int soError = 0;
                socklen_t soLen = sizeof(soError);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &soLen) == 0 &&
                    soError == 0) {
                    fcntl(fd, F_SETFL, flags);
                    connectedFd = fd;
                }
            }
        }
        if (connectedFd < 0) {
            ::close(fd);
        }
    }
    ::freeaddrinfo(res);

    if (connectedFd < 0) {
        std::cerr << "[lethe-http] Connect failed to " << host << ":" << port << std::endl;
        return false;
    }
    socketFd_ = connectedFd;

    if (scheme == "https") {
#ifdef HAVE_OPENSSL
        usingTls_ = true;

        sslCtx_ = SSL_CTX_new(TLS_client_method());
        if (!sslCtx_) {
            std::cerr << "[lethe-http] Failed to create SSL context" << std::endl;
            closeConnection();
            return false;
        }

        // Version policy: map config codes onto OpenSSL constants.
        // Config uses 0x0303=TLS1.2, 0x0304=TLS1.3 (0x0305 treated as 1.3).
        int minVer = tlsConfig_.getMinVersion();
        SSL_CTX_set_min_proto_version(
            sslCtx_, minVer >= 0x0304 ? TLS1_3_VERSION : TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(sslCtx_, TLS1_3_VERSION);

        // Certificate verification.
        if (tlsConfig_.isVerifyCertificates()) {
            SSL_CTX_set_verify(sslCtx_, SSL_VERIFY_PEER, nullptr);
            const std::string& caPath = tlsConfig_.getCaBundlePath();
            if (!caPath.empty()) {
                if (!SSL_CTX_load_verify_locations(sslCtx_, caPath.c_str(), nullptr)) {
                    std::cerr << "[lethe-http] Failed to load CA bundle: " << caPath
                              << std::endl;
                    SSL_CTX_free(sslCtx_);
                    sslCtx_ = nullptr;
                    closeConnection();
                    return false;
                }
            }
            // Empty caPath => OpenSSL uses the system default store.
        } else {
            SSL_CTX_set_verify(sslCtx_, SSL_VERIFY_NONE, nullptr);
        }

        ssl_ = SSL_new(sslCtx_);
        if (!ssl_) {
            SSL_CTX_free(sslCtx_);
            sslCtx_ = nullptr;
            closeConnection();
            return false;
        }
        SSL_set_fd(ssl_, socketFd_);
        SSL_set_tlsext_host_name(ssl_, host.c_str());

        // Enforce the timeout on the underlying socket for the handshake.
        timeval tv;
        tv.tv_sec = static_cast<time_t>(ioTimeout_.count() / 1000);
        tv.tv_usec = static_cast<suseconds_t>((ioTimeout_.count() % 1000) * 1000);
        setsockopt(socketFd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(socketFd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

        int ok = SSL_connect(ssl_);
        if (ok != 1) {
            int err = SSL_get_error(ssl_, ok);
            std::cerr << "[lethe-http] TLS handshake failed with " << host
                      << " (SSL error " << err << ")" << std::endl;
            closeConnection();
            return false;
        }

        const SSL* sslConst = ssl_;
        std::cout << "[lethe-http] TLS established with " << host << " ("
                  << SSL_get_version(sslConst) << ")" << std::endl;
#else
        std::cerr << "[lethe-http] HTTPS requested but OpenSSL is unavailable"
                  << std::endl;
        closeConnection();
        return false;
#endif
    }

    return true;
}

void HttpClient::closeConnection() {
#ifdef HAVE_OPENSSL
    if (ssl_) {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
        ssl_ = nullptr;
    }
    if (sslCtx_) {
        SSL_CTX_free(sslCtx_);
        sslCtx_ = nullptr;
    }
#endif
    if (socketFd_ >= 0) {
        ::close(socketFd_);
        socketFd_ = -1;
    }
    usingTls_ = false;
}

// --- Raw I/O ---

int HttpClient::rawRead(uint8_t* buf, size_t len) {
    if (socketFd_ < 0) return -1;

#ifdef HAVE_OPENSSL
    if (usingTls_ && ssl_) {
        int n = SSL_read(ssl_, buf, static_cast<int>(len));
        if (n > 0) return n;
        int err = SSL_get_error(ssl_, n);
        if (err == SSL_ERROR_ZERO_RETURN) return 0; // clean close
        if (err == SSL_ERROR_SYSCALL) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return -2;
            if (errno == 0) return 0; // peer closed
            return -1;
        }
        if (err == SSL_ERROR_WANT_READ) return -2; // timeout
        return -1;
    }
#endif

    // Plain TCP with select-based timeout.
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(socketFd_, &rfds);
    timeval tv;
    tv.tv_sec = static_cast<time_t>(ioTimeout_.count() / 1000);
    tv.tv_usec = static_cast<suseconds_t>((ioTimeout_.count() % 1000) * 1000);

    int sel = ::select(socketFd_ + 1, &rfds, nullptr, nullptr, &tv);
    if (sel < 0) {
        if (errno == EINTR) return -2;
        return -1;
    }
    if (sel == 0) return -2; // timeout

    ssize_t n = ::recv(socketFd_, buf, len, 0);
    if (n < 0) {
        if (errno == EINTR) return -2;
        return -1;
    }
    return static_cast<int>(n);
}

bool HttpClient::writeAll(const char* data, size_t len) {
    if (socketFd_ < 0) return false;
    size_t total = 0;
    while (total < len) {
        ssize_t n;
#ifdef HAVE_OPENSSL
        if (usingTls_ && ssl_) {
            n = SSL_write(ssl_, data + total, static_cast<int>(len - total));
            if (n <= 0) {
                std::cerr << "[lethe-http] SSL_write failed (error "
                          << SSL_get_error(ssl_, n) << ")" << std::endl;
                return false;
            }
        } else
#endif
        {
            n = ::send(socketFd_, data + total, len - total, 0);
            if (n < 0) {
                if (errno == EINTR) continue;
                std::cerr << "[lethe-http] send failed: " << strerror(errno)
                          << std::endl;
                return false;
            }
        }
        total += static_cast<size_t>(n);
    }
    return true;
}

bool HttpClient::readLine(std::string& out) {
    out.clear();
    while (true) {
        uint8_t c = 0;
        int n = rawRead(&c, 1);
        if (n < 0) return false; // error or timeout
        if (n == 0) {
            // EOF: return whatever we have (final line without newline).
            return !out.empty();
        }
        if (c == '\n') {
            if (!out.empty() && out.back() == '\r') out.pop_back();
            return true;
        }
        out += static_cast<char>(c);
        if (out.size() > 65536) return false; // pathological header guard
    }
}

// --- Response parsing ---

bool HttpClient::readFullResponse(HttpResponse& resp) {
    // Status line: "HTTP/1.1 200 OK"
    std::string statusLine;
    if (!readLine(statusLine)) {
        resp.error = "Failed to read status line";
        return false;
    }
    std::istringstream iss(statusLine);
    std::string httpVersion, reason;
    if (!(iss >> httpVersion >> resp.statusCode >> reason)) {
        resp.error = "Malformed status line: " + statusLine;
        return false;
    }

    // Headers until the blank line.
    std::string line;
    while (readLine(line) && !line.empty()) {
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = toLowerCopy(trimCopy(line.substr(0, colon)));
            std::string value = trimCopy(line.substr(colon + 1));
            resp.headers[key] = value;
        }
    }

    // Body.
    std::string transferEncoding = toLowerCopy(getHeader(resp.headers, "transfer-encoding"));
    std::string contentLengthStr = getHeader(resp.headers, "content-length");

    if (transferEncoding.find("chunked") != std::string::npos) {
        if (!readChunkedBody(resp)) {
            resp.error = "Failed to read chunked body";
            return false;
        }
    } else if (!contentLengthStr.empty()) {
        size_t contentLength = 0;
        try {
            contentLength = std::stoul(contentLengthStr);
        } catch (...) {
            resp.error = "Invalid Content-Length: " + contentLengthStr;
            return false;
        }
        if (!readBodyOfLength(resp, contentLength)) {
            resp.error = "Failed to read body";
            return false;
        }
    } else {
        if (!readBodyUntilClose(resp)) {
            resp.error = "Failed to read body";
            return false;
        }
    }

    maybeDecompressBody(resp);

    resp.success = (resp.statusCode >= 200 && resp.statusCode < 300);
    return true;
}

bool HttpClient::readBodyOfLength(HttpResponse& resp, size_t length) {
    resp.body.reserve(std::min(length, kMaxResponseSize));
    size_t remaining = length;
    std::vector<uint8_t> chunk(kReadChunkSize);
    while (remaining > 0) {
        size_t want = std::min(remaining, chunk.size());
        int n = rawRead(chunk.data(), want);
        if (n < 0) return false;
        if (n == 0) return false; // premature EOF
        resp.body.insert(resp.body.end(),
                         reinterpret_cast<char*>(chunk.data()),
                         reinterpret_cast<char*>(chunk.data() + n));
        remaining -= static_cast<size_t>(n);
        if (resp.body.size() > kMaxResponseSize) {
            std::cerr << "[lethe-http] Response too large, aborting" << std::endl;
            return false;
        }
    }
    return true;
}

bool HttpClient::readChunkedBody(HttpResponse& resp) {
    while (true) {
        // Read the chunk-size line.
        std::string sizeLine;
        if (!readLine(sizeLine)) return false;
        if (sizeLine.empty()) return true; // no more chunks (malformed but done)

        // Strip chunk extensions after ';'.
        size_t semicolon = sizeLine.find(';');
        if (semicolon != std::string::npos) sizeLine = sizeLine.substr(0, semicolon);
        sizeLine = trimCopy(sizeLine);

        size_t chunkSize = 0;
        try {
            chunkSize = std::stoul(sizeLine, nullptr, 16);
        } catch (...) {
            std::cerr << "[lethe-http] Invalid chunk size: " << sizeLine << std::endl;
            return false;
        }

        if (chunkSize == 0) {
            // Trailer section: read until blank line.
            std::string trailer;
            while (readLine(trailer) && !trailer.empty()) {
                // ignore trailers
            }
            return true;
        }

        if (!readBodyOfLength(resp, chunkSize)) return false;

        // Consume the CRLF after each chunk.
        uint8_t c1 = 0, c2 = 0;
        if (rawRead(&c1, 1) != 1 || rawRead(&c2, 1) != 1) return false;
    }
}

bool HttpClient::readBodyUntilClose(HttpResponse& resp) {
    std::vector<uint8_t> chunk(kReadChunkSize);
    while (true) {
        int n = rawRead(chunk.data(), chunk.size());
        if (n < 0) return n == -2 ? false : false; // timeout or error
        if (n == 0) return true; // clean EOF
        resp.body.insert(resp.body.end(),
                         reinterpret_cast<char*>(chunk.data()),
                         reinterpret_cast<char*>(chunk.data() + n));
        if (resp.body.size() > kMaxResponseSize) {
            std::cerr << "[lethe-http] Response too large, aborting" << std::endl;
            return false;
        }
    }
}

void HttpClient::maybeDecompressBody(HttpResponse& resp) {
    std::string encoding = toLowerCopy(getHeader(resp.headers, "content-encoding"));
    if (encoding.empty() || resp.body.empty()) return;

    std::vector<char> out;
    out.reserve(resp.body.size());

    if (encoding.find("gzip") != std::string::npos) {
        z_stream zs;
        std::memset(&zs, 0, sizeof(zs));
        // 15 + 16: window bits + gzip format.
        if (inflateInit2(&zs, 15 + 16) != Z_OK) return;

        zs.next_in = reinterpret_cast<Bytef*>(resp.body.data());
        zs.avail_in = static_cast<uInt>(resp.body.size());

        std::vector<Bytef> buf(kReadChunkSize);
        int ret;
        do {
            zs.next_out = buf.data();
            zs.avail_out = static_cast<uInt>(buf.size());
            ret = inflate(&zs, Z_NO_FLUSH);
            if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR) {
                inflateEnd(&zs);
                return; // not actually gzip; keep original body
            }
            size_t have = buf.size() - zs.avail_out;
            out.insert(out.end(), buf.begin(), buf.begin() + have);
        } while (ret != Z_STREAM_END && zs.avail_in > 0);

        inflateEnd(&zs);
        resp.body = std::move(out);
    } else if (encoding.find("deflate") != std::string::npos) {
        z_stream zs;
        std::memset(&zs, 0, sizeof(zs));
        if (inflateInit2(&zs, 15) != Z_OK) return;

        zs.next_in = reinterpret_cast<Bytef*>(resp.body.data());
        zs.avail_in = static_cast<uInt>(resp.body.size());

        std::vector<Bytef> buf(kReadChunkSize);
        int ret;
        do {
            zs.next_out = buf.data();
            zs.avail_out = static_cast<uInt>(buf.size());
            ret = inflate(&zs, Z_NO_FLUSH);
            if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR) {
                inflateEnd(&zs);
                return;
            }
            size_t have = buf.size() - zs.avail_out;
            out.insert(out.end(), buf.begin(), buf.begin() + have);
        } while (ret != Z_STREAM_END && zs.avail_in > 0);

        inflateEnd(&zs);
        resp.body = std::move(out);
    }
}

// --- URL / request building ---

void HttpClient::parseUrl(const std::string& url, std::string& scheme,
                          std::string& host, std::string& path, int& port) {
    scheme.clear();
    host.clear();
    path = "/";
    port = 0;

    size_t schemeEnd = url.find("://");
    std::string rest = url;
    if (schemeEnd != std::string::npos) {
        scheme = toLowerCopy(url.substr(0, schemeEnd));
        rest = url.substr(schemeEnd + 3);
    }

    // Split host[:port] from path.
    size_t hostEnd = rest.find('/');
    std::string hostPort = (hostEnd == std::string::npos)
                               ? rest
                               : rest.substr(0, hostEnd);
    if (hostEnd != std::string::npos) {
        path = rest.substr(hostEnd);
    }

    // Split host and explicit port.
    size_t colon = hostPort.find(':');
    if (colon != std::string::npos) {
        host = hostPort.substr(0, colon);
        try {
            port = std::stoi(hostPort.substr(colon + 1));
        } catch (...) {
            port = 0;
        }
    } else {
        host = hostPort;
    }

    // Strip userinfo if present.
    size_t at = host.find('@');
    if (at != std::string::npos) host = host.substr(at + 1);

    // Default ports.
    if (port == 0) {
        if (scheme == "https") port = 443;
        else port = 80;
    }
}

std::string HttpClient::buildHttpRequest(const HttpRequest& req,
                                         const std::string& host,
                                         const std::string& path,
                                         int port) {
    (void)port;
    std::string method = "GET";
    switch (req.method) {
        case HttpMethod::GET: method = "GET"; break;
        case HttpMethod::POST: method = "POST"; break;
        case HttpMethod::PUT: method = "PUT"; break;
        case HttpMethod::DELETE: method = "DELETE"; break;
        case HttpMethod::HEAD: method = "HEAD"; break;
        case HttpMethod::PATCH: method = "PATCH"; break;
    }

    std::string httpRequest;
    httpRequest += method;
    httpRequest += " ";
    httpRequest += path;
    httpRequest += " HTTP/1.1\r\n";
    httpRequest += "Host: ";
    httpRequest += host;
    httpRequest += "\r\n";
    httpRequest += "User-Agent: ";
    httpRequest += lethe::USER_AGENT_STRING;
    httpRequest += "\r\n";
    httpRequest += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";
    httpRequest += "Accept-Language: en-US,en;q=0.5\r\n";
    httpRequest += "Accept-Encoding: gzip, deflate\r\n";
    httpRequest += "Connection: close\r\n";

    for (const auto& header : req.headers) {
        httpRequest += header.first;
        httpRequest += ": ";
        httpRequest += header.second;
        httpRequest += "\r\n";
    }

    if (!req.body.empty()) {
        httpRequest += "Content-Length: ";
        httpRequest += std::to_string(req.body.size());
        httpRequest += "\r\n";
        httpRequest += "Content-Type: application/x-www-form-urlencoded\r\n";
    }

    httpRequest += "\r\n";

    if (!req.body.empty()) {
        httpRequest += req.body;
    }

    return httpRequest;
}

} // namespace lethe

