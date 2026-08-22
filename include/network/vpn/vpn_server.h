#ifndef LETHE_NETWORK_VPN_VPN_SERVER_H
#define LETHE_NETWORK_VPN_VPN_SERVER_H

// vpn_server.h — Reference implementation of a Lethe VPN server
//
// A real UDP-based VPN server that:
//   - binds a UDP endpoint (host:port)
//   - performs WireGuard-style handshakes with any number of clients
//   - maintains per-client tunnels (per-client data keys)
//   - delivers decrypted client traffic to a callback
//   - sends encrypted traffic back to clients via sendToClient()
//
// The server is event-loop driven: call process(timeout) repeatedly (or
// run() for a blocking loop). This is the server half of the network
// transport layer that the built-in VPN client talks to.

#include <atomic>
#include <chrono>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>
#include "network/udp_transport.h"
#include "network/vpn/vpn_tunnel.h"

namespace lethe {
namespace vpn {

class VpnServer {
public:
    // Called with decrypted plaintext received from a client.
    // clientKey is the stable per-client identifier (handshake index hex).
    using DataCallback = std::function<void(const std::string& clientKey,
                                            const uint8_t* data, size_t len)>;

    VpnServer();
    ~VpnServer();

    VpnServer(const VpnServer&) = delete;
    VpnServer& operator=(const VpnServer&) = delete;

    // Configure with the server's private key. Must be called before start().
    bool configure(const Key& serverPrivateKey);

    // The server's public key (for clients to configure).
    const Key& publicKey() const { return serverPublicKey_; }

    // Start listening on host:port. Returns false on bind failure.
    bool start(const std::string& host, int port);

    // Stop the server and release the socket (idempotent).
    void stop();

    // Process pending datagrams, waiting up to timeout for new ones.
    // Returns the number of datagrams processed. Non-blocking loop step.
    int process(std::chrono::milliseconds timeout);

    // Run the event loop until stop() is called.
    void run();

    // Send encrypted data to a connected client (by clientKey).
    // Returns false if the client is unknown or not connected.
    bool sendToClient(const std::string& clientKey,
                      const uint8_t* data, size_t len);
    bool sendToClient(const std::string& clientKey,
                      const std::vector<uint8_t>& data);

    // Number of currently connected clients.
    size_t clientCount() const;

    // List of connected client keys.
    std::vector<std::string> connectedClients() const;

    // Set the callback invoked for each decrypted client datagram.
    void setDataCallback(DataCallback cb);

    // --- Streaming TCP relay (HTTP/HTTPS over the tunnel) ---
    // When enabled (default), decrypted client payloads carrying the relay
    // magic are interpreted as stream frames: OPEN connects a TCP origin,
    // DATA carries bytes both directions, END closes, OK/ERR report the
    // connect result. The event loop polls open origins and pushes their
    // bytes back as DATA frames. Payloads without the magic still reach
    // the data callback unchanged.
    void setRelayEnabled(bool enabled);
    bool relayEnabled() const { return relayEnabled_; }
    // Cap on total bytes streamed back per relay stream. Default: 256 KiB.
    void setMaxRelayResponseBytes(size_t n);
    // Concurrent relay streams allowed. Default: 256.
    void setMaxRelayStreams(size_t n);
    // Number of relay streams opened since start.
    size_t relayedRequests() const { return relayedRequests_.load(); }
    // Currently open relay streams.
    size_t openRelayStreams() const { return relayStreams_.size(); }

    // --- DoS hardening (all knobs have safe defaults) ---
    // Evict clients not seen for this long. Default: 180s.
    void setClientIdleTimeout(std::chrono::milliseconds ms);
    // Refuse new handshakes beyond this many concurrent clients.
    // Default: 1024. Excess handshakes are dropped silently.
    void setMaxClients(size_t n);
    // Allow at most maxPerWindow handshakes per source host per window.
    // Default: 16 per 10s. Excess handshakes are dropped silently.
    void setHandshakeRateLimit(size_t maxPerWindow, std::chrono::milliseconds window);
    // Evict idle clients now. Returns the number evicted. Called
    // automatically from process(); exposed for tests and admin sweeps.
    size_t sweepIdleClients();

    // The port the server is bound to (0 if not started).
    int port() const;

    // The host the server is bound to.
    std::string host() const;

private:
    struct ClientSession {
        std::unique_ptr<VpnTunnel> tunnel; // server-role tunnel for this client
        std::string host;                  // client source host
        int port = 0;                      // client source port
        std::string keyHex;                // handshake index hex (client id)
        bool connected = false;
        std::chrono::steady_clock::time_point lastSeenTime{}; // idle tracking
    };

    // Per-source-host handshake rate bucket.
    struct RateBucket {
        std::chrono::steady_clock::time_point windowStart{};
        size_t count = 0;
    };

    // Handshake admission control. Returns true if allowed. Caller must
    // hold mutex_.
    bool admitHandshakeLocked(const std::string& fromHost);

    void handleDatagram(const uint8_t* data, size_t len,
                        const std::string& fromHost, int fromPort);
    void handleHandshakeInit(const HandshakeMessage& msg,
                             const std::string& fromHost, int fromPort);
    ClientSession* findSessionByAddress(const std::string& host, int port);

    // Relay handling: frame dispatch, origin I/O, stream bookkeeping.
    // All relayStreams_ state lives on the event-loop thread only.
    void handleRelayFrame(const std::string& clientKey,
                          const std::vector<uint8_t>& plaintext);
    void closeRelayStream(uint32_t xid, bool notifyClient);
    void pumpStreamToClient(uint32_t xid);

    struct RelayStream {
        int fd = -1;
        std::string clientKey;
        size_t totalBytes = 0;
    };

    Key serverPrivateKey_{};
    Key serverPublicKey_{};
    bool configured_ = false;

    std::unique_ptr<UdpTransport> transport_;
    std::atomic<bool> running_{false};

    mutable std::mutex mutex_;
    std::map<std::string, ClientSession> clients_; // keyHex -> session
    std::map<std::string, RateBucket> handshakeRates_; // host -> bucket

    // Hardening knobs.
    std::chrono::milliseconds clientIdleTimeout_{std::chrono::seconds(180)};
    std::chrono::milliseconds rateLimitWindow_{std::chrono::seconds(10)};
    size_t maxHandshakesPerWindow_ = 16;
    size_t maxClients_ = 1024;

    // Relay settings + live streams (event-loop thread only).
    bool relayEnabled_ = true;
    size_t maxRelayResponseBytes_ = 256 * 1024;
    size_t maxRelayStreams_ = 256;
    std::map<uint32_t, RelayStream> relayStreams_;
    std::atomic<size_t> relayedRequests_{0};

    DataCallback dataCallback_;
};

} // namespace vpn
} // namespace lethe

#endif // LETHE_NETWORK_VPN_VPN_SERVER_H

