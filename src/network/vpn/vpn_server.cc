// vpn_server.cc — Reference implementation of a Lethe VPN server

#include "network/vpn/vpn_server.h"
#include "network/vpn/vpn_relay.h"

#include <cstring>
#include <iostream>

#ifdef _WIN32
#else
#include <fcntl.h>
#include <netdb.h>
#include <sys/select.h>
#include <unistd.h>
#endif

namespace lethe {
namespace vpn {

VpnServer::VpnServer() = default;

VpnServer::~VpnServer() {
    stop();
}

bool VpnServer::configure(const Key& serverPrivateKey) {
    if (serverPrivateKey == Key{}) return false;
    if (!derivePublicKey(serverPrivateKey, serverPublicKey_)) return false;
    serverPrivateKey_ = serverPrivateKey;
    configured_ = true;
    std::cout << "[lethe-vpn-server] Configured (public key: "
              << toHex(serverPublicKey_) << ")" << std::endl;
    return true;
}

bool VpnServer::start(const std::string& host, int port) {
    if (!configured_) {
        std::cerr << "[lethe-vpn-server] Not configured" << std::endl;
        return false;
    }

    transport_ = std::make_unique<UdpTransport>();
    if (!transport_->bind(host, port)) {
        std::cerr << "[lethe-vpn-server] Bind failed: " << transport_->lastError()
                  << std::endl;
        transport_.reset();
        return false;
    }

    running_ = true;
    std::cout << "[lethe-vpn-server] Listening on " << host << ":" << transport_->localPort()
              << std::endl;
    return true;
}

void VpnServer::stop() {
    running_ = false;
    if (transport_) {
        transport_->close();
        transport_.reset();
    }
    std::lock_guard<std::mutex> lock(mutex_);
    clients_.clear();
}

int VpnServer::process(std::chrono::milliseconds timeout) {
    if (!transport_ || !running_) return 0;

    // Opportunistic housekeeping: evict clients idle past the timeout.
    sweepIdleClients();

    int processed = 0;
    std::string fromHost;
    int fromPort = 0;
    std::vector<uint8_t> buf;
    int n = transport_->recvFrom(buf, timeout, fromHost, fromPort);
    if (n < 0) {
        return 0; // timeout or error
    }
    handleDatagram(buf.data(), static_cast<size_t>(n), fromHost, fromPort);
    processed++;
    return processed;
}

void VpnServer::run() {
    while (running_) {
        // Process with a short timeout so we can check running_ frequently.
        process(std::chrono::milliseconds(200));
    }
}

bool VpnServer::sendToClient(const std::string& clientKey,
                             const uint8_t* data, size_t len) {
    if (!transport_ || !running_) return false;

    // Encrypt and snapshot the endpoint under the lock.
    std::vector<uint8_t> ciphertext;
    std::string host;
    int port = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = clients_.find(clientKey);
        if (it == clients_.end()) return false;
        ClientSession& session = it->second;
        if (!session.connected || !session.tunnel) return false;
        if (!session.tunnel->encryptDataPacket(data, len, ciphertext)) {
            return false;
        }
        host = session.host;
        port = session.port;
    }

    // Send outside the lock (encryption already done).
    return transport_->sendTo(host, port, ciphertext);
}

bool VpnServer::sendToClient(const std::string& clientKey,
                             const std::vector<uint8_t>& data) {
    return sendToClient(clientKey, data.data(), data.size());
}

size_t VpnServer::clientCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    for (const auto& [key, session] : clients_) {
        if (session.connected) count++;
    }
    return count;
}

std::vector<std::string> VpnServer::connectedClients() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> keys;
    for (const auto& [key, session] : clients_) {
        if (session.connected) keys.push_back(key);
    }
    return keys;
}

void VpnServer::setDataCallback(DataCallback cb) {
    dataCallback_ = std::move(cb);
}

// --- One-shot TCP relay (HTTP-over-tunnel) -----------------------------------

void VpnServer::setRelayEnabled(bool enabled) {
    relayEnabled_ = enabled;
}

void VpnServer::setMaxRelayResponseBytes(size_t n) {
    maxRelayResponseBytes_ = n;
}

namespace {

// Connect TCP to host:port with a timeout. Returns -1 on failure.
int connectTcpWithTimeout(const std::string& host, int port,
                          std::chrono::milliseconds timeout) {
    addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    const int rc = ::getaddrinfo(host.c_str(), std::to_string(port).c_str(),
                                 &hints, &res);
    if (rc != 0 || !res) return -1;

    int fd = -1;
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
        fd = ::socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) continue;

        // Non-blocking connect bounded by select().
        const int fl = ::fcntl(fd, F_GETFL, 0);
        ::fcntl(fd, F_SETFL, fl | O_NONBLOCK);
        if (::connect(fd, ai->ai_addr, ai->ai_addrlen) == 0) {
            ::fcntl(fd, F_SETFL, fl);
            break;
        }
        fd_set wfds;
        FD_ZERO(&wfds);
        FD_SET(fd, &wfds);
        timeval tv;
        tv.tv_sec = static_cast<long>(timeout.count() / 1000);
        tv.tv_usec = static_cast<suseconds_t>((timeout.count() % 1000) * 1000);
        if (::select(fd + 1, nullptr, &wfds, nullptr, &tv) > 0) {
            int soErr = 0;
            socklen_t len = sizeof(soErr);
            ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &soErr, &len);
            if (soErr == 0) {
                ::fcntl(fd, F_SETFL, fl);
                break;
            }
        }
        ::close(fd);
        fd = -1;
    }
    ::freeaddrinfo(res);
    return fd;
}

} // namespace

void VpnServer::handleRelayRequest(const std::string& clientKey,
                                   const std::vector<uint8_t>& plaintext) {
    relayedRequests_.fetch_add(1);

    relay::Request req;
    auto fail = [&]() {
        // Always terminate the exchange: an empty END chunk signals failure.
        (void)sendToClient(
            clientKey,
            relay::encodeChunk(nullptr, 0, true, req.xid));
    };

    if (!relay::parseRequest(plaintext.data(), plaintext.size(), req)) {
        std::cerr << "[lethe-vpn-server] Malformed relay request" << std::endl;
        fail();
        return;
    }

    const int fd = connectTcpWithTimeout(
        req.host, req.port, std::chrono::milliseconds(2000));
    if (fd < 0) {
        std::cerr << "[lethe-vpn-server] Relay connect failed to "
                  << req.host << ":" << req.port << std::endl;
        fail();
        return;
    }

    // Forward the request payload.
    size_t sent = 0;
    while (sent < req.payload.size()) {
        const ssize_t n = ::send(fd, req.payload.data() + sent,
                                 req.payload.size() - sent, 0);
        if (n <= 0) break;
        sent += static_cast<size_t>(n);
    }

    // Stream the origin's response back in MTU-sized chunks. Exactly one
    // END chunk terminates every exchange.
    timeval tv;
    tv.tv_sec = 2; // idle read bound: origins that never close end here
    tv.tv_usec = 0;
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    std::vector<char> buf(1200);
    size_t total = 0;
    bool done = false;
    while (!done) {
        const ssize_t n = ::recv(fd, buf.data(), buf.size(), 0);
        if (n <= 0) break; // clean EOF, timeout, or error: end of stream
        size_t usable = static_cast<size_t>(n);
        if (total + usable > maxRelayResponseBytes_) {
            usable = maxRelayResponseBytes_ - total;
            done = true; // response cap reached: stop after this chunk
        }
        (void)sendToClient(clientKey,
                           relay::encodeChunk(
                               reinterpret_cast<uint8_t*>(buf.data()),
                               usable, false, req.xid));
        total += usable;
        if (total >= maxRelayResponseBytes_) done = true;
    }
    (void)sendToClient(clientKey,
                       relay::encodeChunk(nullptr, 0, true, req.xid));
    ::close(fd);
}

int VpnServer::port() const {
    return transport_ ? transport_->localPort() : 0;
}

std::string VpnServer::host() const {
    return "0.0.0.0"; // bound address host (informational)
}

void VpnServer::handleDatagram(const uint8_t* data, size_t len,
                               const std::string& fromHost, int fromPort) {
    // AUTHENTICATE FIRST for known sessions: a connected client's datagrams
    // are always data packets. Trying handshake parsing before decryption
    // lets arbitrary ciphertext masquerade as an Init (structural match)
    // and silently swallow real traffic - so session lookup comes first.
    bool isData = false;
    bool decryptFailed = false;
    std::vector<uint8_t> plaintext;
    std::string keyHex;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ClientSession* session = findSessionByAddress(fromHost, fromPort);
        if (session && session->connected && session->tunnel) {
            if (session->tunnel->decryptDataPacket(data, len, plaintext)) {
                session->lastSeenTime = std::chrono::steady_clock::now();
                keyHex = session->keyHex;
                isData = true;
            } else {
                decryptFailed = true;
            }
        }
    }

    if (isData) {
        // Relay requests are recognized by magic and never reach the
        // callback. Delivery happens outside the lock: handlers may
        // re-enter the server.
        if (relayEnabled_ &&
            plaintext.size() >= sizeof(relay::kMagic) &&
            std::memcmp(plaintext.data(), relay::kMagic,
                        sizeof(relay::kMagic)) == 0) {
            handleRelayRequest(keyHex, plaintext);
            return;
        }
        if (dataCallback_) {
            dataCallback_(keyHex, plaintext.data(), plaintext.size());
        }
        return;
    }

    // Not decryptable as data for a known session: it is either garbage or
    // a genuine (re)handshake from that address - e.g. a rekey whose fresh
    // ephemerals cannot decrypt under the old session's keys. Fall back to
    // handshake parsing; anything else is dropped.
    HandshakeMessage msg;
    if (HandshakeMessage::deserialize(data, len, msg) &&
        msg.type == HandshakeType::Init) {
        handleHandshakeInit(msg, fromHost, fromPort);
        return;
    }

    std::cerr << "[lethe-vpn-server] Dropping undecryptable datagram from "
              << fromHost << ":" << fromPort << std::endl;
}

void VpnServer::handleHandshakeInit(const HandshakeMessage& msg,
                                    const std::string& fromHost, int fromPort) {
    std::string keyHex = toHex(msg.index);

    // Admission control: rate limit per source host and cap total clients.
    // Rejected handshakes are dropped silently (WireGuard behavior): no
    // response means no amplification for attackers.
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!admitHandshakeLocked(fromHost)) {
            return;
        }
        // If this address already has a session, it's a re-handshake; replace it.
        ClientSession* existing = findSessionByAddress(fromHost, fromPort);
        if (existing) {
            clients_.erase(existing->keyHex);
        }
    }

    // Create a new server-role tunnel for this client.
    auto tunnel = std::make_unique<VpnTunnel>();
    if (!tunnel->configureServer(serverPrivateKey_)) {
        std::cerr << "[lethe-vpn-server] Failed to configure client tunnel" << std::endl;
        return;
    }

    HandshakeMessage response;
    if (!tunnel->processHandshakeInit(msg, response)) {
        std::cerr << "[lethe-vpn-server] Handshake rejected from " << fromHost
                  << ":" << fromPort << std::endl;
        return;
    }

    // Store the session.
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ClientSession session;
        session.tunnel = std::move(tunnel);
        session.host = fromHost;
        session.port = fromPort;
        session.keyHex = keyHex;
        session.connected = true;
        session.lastSeenTime = std::chrono::steady_clock::now();
        clients_[keyHex] = std::move(session);
    }

    // Send the response back to the client.
    std::vector<uint8_t> respData = response.serialize();
    if (transport_) {
        transport_->sendTo(fromHost, fromPort, respData);
    }

    std::cout << "[lethe-vpn-server] Client connected: " << keyHex
              << " (" << fromHost << ":" << fromPort << ")" << std::endl;
}

VpnServer::ClientSession* VpnServer::findSessionByAddress(const std::string& host, int port) {
    for (auto& [key, session] : clients_) {
        if (session.host == host && session.port == port) {
            return &session;
        }
    }
    return nullptr;
}

// --- DoS hardening -----------------------------------------------------------

void VpnServer::setClientIdleTimeout(std::chrono::milliseconds ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    clientIdleTimeout_ = ms;
}

void VpnServer::setMaxClients(size_t n) {
    std::lock_guard<std::mutex> lock(mutex_);
    maxClients_ = n;
}

void VpnServer::setHandshakeRateLimit(size_t maxPerWindow,
                                      std::chrono::milliseconds window) {
    std::lock_guard<std::mutex> lock(mutex_);
    maxHandshakesPerWindow_ = maxPerWindow;
    rateLimitWindow_ = window;
}

size_t VpnServer::sweepIdleClients() {
    size_t evicted = 0;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto now = std::chrono::steady_clock::now();
        for (auto it = clients_.begin(); it != clients_.end();) {
            const ClientSession& session = it->second;
            const bool idle = session.lastSeenTime.time_since_epoch().count() != 0 &&
                now - session.lastSeenTime > clientIdleTimeout_;
            if (idle) {
                it = clients_.erase(it);
                evicted++;
            } else {
                ++it;
            }
        }
    }
    if (evicted > 0) {
        std::cout << "[lethe-vpn-server] Evicted " << evicted
                  << " idle client(s)" << std::endl;
    }
    return evicted;
}

bool VpnServer::admitHandshakeLocked(const std::string& fromHost) {
    // Cap concurrent clients.
    if (clients_.size() >= maxClients_) {
        return false;
    }

    const auto now = std::chrono::steady_clock::now();

    // Bound the rate-map memory: spoofed-source floods must not grow it
    // forever. Prune expired buckets past the cap; still full => fail closed.
    constexpr size_t MAX_RATE_BUCKETS = 4096;
    if (handshakeRates_.size() >= MAX_RATE_BUCKETS) {
        for (auto it = handshakeRates_.begin(); it != handshakeRates_.end();) {
            if (it->second.count == 0 ||
                now - it->second.windowStart > rateLimitWindow_) {
                it = handshakeRates_.erase(it);
            } else {
                ++it;
            }
        }
        if (handshakeRates_.size() >= MAX_RATE_BUCKETS) {
            return false;
        }
    }

    // Token-window rate limit per source host.
    RateBucket& bucket = handshakeRates_[fromHost];
    if (bucket.count > 0 && now - bucket.windowStart > rateLimitWindow_) {
        bucket.windowStart = now;
        bucket.count = 0;
    }
    if (bucket.count == 0) {
        bucket.windowStart = now;
    }
    if (bucket.count >= maxHandshakesPerWindow_) {
        return false;
    }
    bucket.count++;
    return true;
}

} // namespace vpn
} // namespace lethe

