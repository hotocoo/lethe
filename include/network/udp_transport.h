#ifndef LETHE_NETWORK_UDP_TRANSPORT_H
#define LETHE_NETWORK_UDP_TRANSPORT_H

// udp_transport.h — UDP network transport for Lethe
//
// Thin, portable wrapper around POSIX UDP sockets used by the built-in VPN
// (client and reference server). Provides:
//   - bind()            : bind a local socket (optionally to a fixed port)
//   - sendTo()          : send a datagram to a remote endpoint
//   - recvFrom()        : receive a datagram with a timeout
//   - sendAndReceive()  : send and wait for the next datagram (handshake style)
//
// Host resolution uses getaddrinfo, so both "127.0.0.1" and hostnames work.
// No telemetry. POSIX sockets only (macOS / Linux / BSD).

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

// POSIX socket types (sockaddr_storage, socklen_t, etc.).
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

namespace lethe {

class UdpTransport {
public:
    UdpTransport();
    ~UdpTransport();

    // Non-copyable, non-movable (owns a socket fd).
    UdpTransport(const UdpTransport&) = delete;
    UdpTransport& operator=(const UdpTransport&) = delete;

    // Bind the local socket. If port is 0, the OS assigns an ephemeral port.
    // Returns false on failure (e.g. port already in use).
    bool bind(const std::string& host, int port);

    // Send a datagram to the given remote endpoint.
    bool sendTo(const std::string& host, int port,
                const uint8_t* data, size_t len);
    bool sendTo(const std::string& host, int port,
                const std::vector<uint8_t>& data);

    // Receive a datagram, waiting up to timeout for data.
    // On success, fills fromHost/fromPort with the sender's address and
    // returns the number of bytes received. Returns -1 on timeout or error.
    int recvFrom(uint8_t* buf, size_t bufLen,
                 std::chrono::milliseconds timeout,
                 std::string& fromHost, int& fromPort);
    int recvFrom(std::vector<uint8_t>& outBuf,
                 std::chrono::milliseconds timeout,
                 std::string& fromHost, int& fromPort);

    // Convenience for handshake-style exchanges: send a datagram and wait for
    // the next one to arrive (optionally only from the same endpoint).
    // Returns the number of bytes received, or -1 on timeout/error.
    int sendAndReceive(const std::string& host, int port,
                       const std::vector<uint8_t>& sendBuf,
                       std::vector<uint8_t>& outBuf,
                       std::chrono::milliseconds timeout,
                       bool onlyFromSender = true);

    // The local port this transport is bound to (0 if not bound).
    int localPort() const { return localPort_; }

    // The underlying socket fd (for select()/poll() integration); -1 when
    // not bound.
    int nativeFd() const { return socket_; }

    // The local host this transport is bound to (empty if not bound).
    std::string localHost() const { return localHost_; }

    // Whether the transport currently owns a socket.
    bool isOpen() const { return socket_ >= 0; }

    // Close the socket (idempotent).
    void close();

    // Last error message (for diagnostics; empty if none).
    std::string lastError() const { return lastError_; }

private:
    int socket_ = -1;
    int localPort_ = 0;
    std::string localHost_;
    mutable std::string lastError_;  // mutable: settable from const diagnostics

    // Resolve host:port into a sockaddr_storage; returns false on failure.
    bool resolve(const std::string& host, int port,
                 struct sockaddr_storage& outAddr, socklen_t& outLen) const;
};

} // namespace lethe

#endif // LETHE_NETWORK_UDP_TRANSPORT_H
