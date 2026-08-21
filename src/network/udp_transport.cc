// udp_transport.cc — UDP network transport for Lethe
//
// POSIX UDP socket implementation used by the built-in VPN client and the
// reference VPN server. Supports IPv4 and IPv6 via getaddrinfo, datagram
// send/recv with timeouts, and a convenience sendAndReceive() for
// handshake-style exchanges.

#include "network/udp_transport.h"

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <iostream>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

namespace lethe {

namespace {

// Convert a sockaddr_storage to a host string + port (no DNS lookups).
bool addressToString(const sockaddr_storage* addr, std::string& outHost, int& outPort) {
    char hostBuf[INET6_ADDRSTRLEN] = {0};
    if (addr->ss_family == AF_INET) {
        const auto* a4 = reinterpret_cast<const sockaddr_in*>(addr);
        if (!::inet_ntop(AF_INET, &a4->sin_addr, hostBuf, sizeof(hostBuf))) return false;
        outPort = ntohs(a4->sin_port);
    } else if (addr->ss_family == AF_INET6) {
        const auto* a6 = reinterpret_cast<const sockaddr_in6*>(addr);
        if (!::inet_ntop(AF_INET6, &a6->sin6_addr, hostBuf, sizeof(hostBuf))) return false;
        outPort = ntohs(a6->sin6_port);
    } else {
        return false;
    }
    outHost = hostBuf;
    return true;
}

// True if the host is a loopback address (IPv4 127.x or IPv6 ::1).
bool isLoopbackHost(const std::string& host) {
    if (host == "::1" || host == "0:0:0:0:0:0:0:1") return true;
    return host.rfind("127.", 0) == 0;
}

} // namespace

UdpTransport::UdpTransport() = default;

UdpTransport::~UdpTransport() {
    close();
}

bool UdpTransport::resolve(const std::string& host, int port,
                           sockaddr_storage& outAddr, socklen_t& outLen) const {
    addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_protocol = IPPROTO_UDP;

    addrinfo* res = nullptr;
    std::string portStr = std::to_string(port);
    int rc = ::getaddrinfo(host.empty() ? nullptr : host.c_str(), portStr.c_str(), &hints, &res);
    if (rc != 0 || !res) {
        lastError_ = std::string("getaddrinfo: ") + gai_strerror(rc);
        return false;
    }

    std::memcpy(&outAddr, res->ai_addr, res->ai_addrlen);
    outLen = res->ai_addrlen;
    ::freeaddrinfo(res);
    return true;
}

bool UdpTransport::bind(const std::string& host, int port) {
    close();

    sockaddr_storage addr;
    socklen_t addrLen = 0;
    if (!resolve(host, port, addr, addrLen)) {
        return false;
    }

    socket_ = ::socket(addr.ss_family, SOCK_DGRAM, 0);
    if (socket_ < 0) {
        lastError_ = std::string("socket: ") + strerror(errno);
        return false;
    }

    int reuse = 1;
    ::setsockopt(socket_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    if (::bind(socket_, reinterpret_cast<sockaddr*>(&addr), addrLen) < 0) {
        lastError_ = std::string("bind: ") + strerror(errno);
        ::close(socket_);
        socket_ = -1;
        return false;
    }

    // Discover the actual bound port (port 0 => OS-assigned ephemeral).
    sockaddr_storage boundAddr;
    socklen_t boundLen = sizeof(boundAddr);
    if (::getsockname(socket_, reinterpret_cast<sockaddr*>(&boundAddr), &boundLen) == 0) {
        int p = 0;
        std::string h;
        if (addressToString(&boundAddr, h, p)) {
            localPort_ = p;
            localHost_ = h;
        }
    }

    return true;
}

bool UdpTransport::sendTo(const std::string& host, int port,
                          const uint8_t* data, size_t len) {
    if (socket_ < 0) {
        lastError_ = "socket not open";
        return false;
    }
    if (!data && len > 0) {
        lastError_ = "null data with non-zero length";
        return false;
    }

    sockaddr_storage addr;
    socklen_t addrLen = 0;
    if (!resolve(host, port, addr, addrLen)) {
        return false;
    }

    ssize_t sent = ::sendto(socket_, data, len, 0,
                            reinterpret_cast<sockaddr*>(&addr), addrLen);
    if (sent < 0) {
        lastError_ = std::string("sendto: ") + strerror(errno);
        return false;
    }
    return static_cast<size_t>(sent) == len;
}

bool UdpTransport::sendTo(const std::string& host, int port,
                          const std::vector<uint8_t>& data) {
    return sendTo(host, port, data.data(), data.size());
}

int UdpTransport::recvFrom(uint8_t* buf, size_t bufLen,
                           std::chrono::milliseconds timeout,
                           std::string& fromHost, int& fromPort) {
    if (socket_ < 0) {
        lastError_ = "socket not open";
        return -1;
    }
    if (!buf && bufLen > 0) {
        lastError_ = "null buffer with non-zero length";
        return -1;
    }

    // Apply the receive timeout.
    timeval tv;
    tv.tv_sec = static_cast<time_t>(timeout.count() / 1000);
    tv.tv_usec = static_cast<suseconds_t>((timeout.count() % 1000) * 1000);
    ::setsockopt(socket_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_storage addr;
    std::memset(&addr, 0, sizeof(addr));
    socklen_t addrLen = sizeof(addr);
    ssize_t n = ::recvfrom(socket_, buf, bufLen, 0,
                           reinterpret_cast<sockaddr*>(&addr), &addrLen);
    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            lastError_ = "recv timeout";
        } else {
            lastError_ = std::string("recvfrom: ") + strerror(errno);
        }
        return -1;
    }

    if (!addressToString(&addr, fromHost, fromPort)) {
        lastError_ = "unsupported address family";
        return -1;
    }
    return static_cast<int>(n);
}

int UdpTransport::recvFrom(std::vector<uint8_t>& outBuf,
                           std::chrono::milliseconds timeout,
                           std::string& fromHost, int& fromPort) {
    constexpr size_t MAX_DGRAM = 65536;
    std::vector<uint8_t> tmp(MAX_DGRAM);
    int n = recvFrom(tmp.data(), tmp.size(), timeout, fromHost, fromPort);
    if (n >= 0) {
        tmp.resize(static_cast<size_t>(n));
        outBuf = std::move(tmp);
    }
    return n;
}

int UdpTransport::sendAndReceive(const std::string& host, int port,
                                 const std::vector<uint8_t>& sendBuf,
                                 std::vector<uint8_t>& outBuf,
                                 std::chrono::milliseconds timeout,
                                 bool onlyFromSender) {
    if (!sendTo(host, port, sendBuf)) {
        return -1;
    }

    // Canonical expected sender for filtering (loopback variants are
    // considered equivalent so "localhost" works across stacks).
    std::string expectedHost;
    int expectedPort = 0;
    bool haveExpected = false;
    if (onlyFromSender) {
        sockaddr_storage addr;
        socklen_t addrLen = 0;
        if (resolve(host, port, addr, addrLen)) {
            haveExpected = addressToString(&addr, expectedHost, expectedPort);
        }
    }

    auto deadline = std::chrono::steady_clock::now() + timeout;
    while (true) {
        auto now = std::chrono::steady_clock::now();
        if (now >= deadline) {
            lastError_ = "sendAndReceive timeout";
            return -1;
        }
        auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now);
        std::string fromHost;
        int fromPort = 0;
        int n = recvFrom(outBuf, remaining, fromHost, fromPort);
        if (n < 0) {
            return -1;
        }

        if (!onlyFromSender) {
            return n;
        }
        if (!haveExpected) {
            // Could not resolve; accept anything.
            return n;
        }
        bool samePort = (fromPort == expectedPort);
        bool sameHost = (fromHost == expectedHost);
        bool bothLoopback = isLoopbackHost(fromHost) && isLoopbackHost(expectedHost);
        if (samePort && (sameHost || bothLoopback)) {
            return n;
        }
        // Not from the expected sender; discard and keep waiting.
    }
}

void UdpTransport::close() {
    if (socket_ >= 0) {
        ::close(socket_);
        socket_ = -1;
    }
    localPort_ = 0;
    localHost_.clear();
}

} // namespace lethe

