#ifndef LETHE_NETWORK_VPN_VPN_TUNNEL_H
#define LETHE_NETWORK_VPN_VPN_TUNNEL_H

// vpn_tunnel.h — Built-in VPN tunnel with WireGuard-style handshake
//
// Implements the Lethe built-in VPN as a state machine that performs a
// WireGuard-style handshake and then encrypts/decrypts data packets with
// ChaCha20-Poly1305. The tunnel can operate as a client or as a server so
// that the handshake protocol is fully testable in a loopback fashion.

#include <array>
#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>
#include "network/vpn/vpn_config.h"
#include "network/vpn/wireguard_cipher.h"

namespace lethe {
namespace vpn {

enum class TunnelState {
    Disconnected,
    Handshaking,
    Connected,
    Stale,
    Error
};

enum class TunnelRole {
    Client,
    Server
};

// Data packet wire format:
//   [0..7]   counter (uint64 little-endian)
//   [8..]    ChaCha20-Poly1305 ciphertext || 16-byte tag
// The explicit counter enables out-of-order delivery and makes replay
// rejection deterministic instead of relying on in-order arrival.

// WireGuard-style session limits.
constexpr uint64_t REJECT_AFTER_MESSAGES =
    0xFFFFFFFFFFFFFFFFull - (1ull << 13) - 1;              // ~2^64 packets
constexpr auto REJECT_AFTER_TIME = std::chrono::seconds(180); // session lifetime

// WireGuard-style handshake message types.
enum class HandshakeType : uint8_t {
    Init = 1,      // client -> server
    Response = 2   // server -> client
};

// WireGuard-style handshake message.
struct HandshakeMessage {
    HandshakeType type;
    Mac index{};              // HMAC index for handshake routing
    Key ephemeralPublicKey{}; // ephemeral public key
    HandshakeNonce nonce{};   // handshake nonce
    std::vector<uint8_t> encryptedData; // encrypted payload (Response only)

    // Serialize to wire format.
    std::vector<uint8_t> serialize() const;
    // Parse from wire format; returns false on malformed input.
    static bool deserialize(const uint8_t* data, size_t len, HandshakeMessage& out);
};

// A single tunnel endpoint (client or server side).
//
// The tunnel owns its handshake state and data keys. Two tunnels (one
// client, one server) can complete a handshake by exchanging HandshakeMessages,
// after which they can encrypt and decrypt data packets to each other.
class VpnTunnel {
public:
    VpnTunnel();
    ~VpnTunnel();

    // Configure the tunnel. For a client, use VpnConfig. For a server, the
    // server's private key is set via setServerPrivateKey.
    bool configureClient(const VpnConfig& config);
    bool configureServer(const Key& serverPrivateKey);

    // --- Handshake (client side) ---
    // Generate and return the Init handshake message to send to the server.
    bool createHandshakeInit(HandshakeMessage& outMessage);

    // Process a Response handshake message from the server. Completes the
    // handshake and derives data keys. Returns true on success.
    bool processHandshakeResponse(const HandshakeMessage& message);

    // --- Handshake (server side) ---
    // Process an Init handshake message from a client. Generates and returns
    // the Response handshake message. Returns false if the client is unknown.
    bool processHandshakeInit(const HandshakeMessage& message, HandshakeMessage& outResponse);

    // --- Data path ---
    // Encrypt an outgoing data packet. Returns false if not connected.
    bool encryptDataPacket(const uint8_t* plaintext, size_t len,
                           std::vector<uint8_t>& outCiphertext);

    // Decrypt an incoming data packet. Returns false if not connected or if
    // authentication fails (tampered packet).
    bool decryptDataPacket(const uint8_t* ciphertext, size_t len,
                           std::vector<uint8_t>& outPlaintext);

    // --- Routing ---
    // Decide whether a destination IP should be routed through the VPN based
    // on the allowed CIDRs. Returns true if traffic should go through tunnel.
    bool shouldRouteThroughVpn(const std::string& destIp) const;

    // --- Status ---
    TunnelState state() const { return state_; }
    TunnelRole role() const { return role_; }
    bool isConnected() const { return state_ == TunnelState::Connected; }
    int mtu() const { return mtu_; }
    const Key& localPublicKey() const { return localPublicKey_; }

    // Permanently wipe all secret key material (private, ephemeral, and
    // session keys) and drop the session. Called on disable/shutdown so
    // keys never linger in freed memory.
    void wipeSecrets();

    // Mark the tunnel stale (e.g. after a timeout without keepalive).
    void markStale();
    // Reconnect: reset to Handshaking state.
    void prepareRehandshake();

    // --- Session lifetime (WireGuard REJECT_AFTER_TIME) ---
    // After this long since the handshake completed, the tunnel refuses to
    // encrypt or decrypt and must rekey. Default: 180s (WireGuard standard).
    void setSessionLifetime(std::chrono::milliseconds ms);
    std::chrono::milliseconds sessionLifetime() const;
    bool isSessionExpired() const;
    // Milliseconds elapsed since the handshake completed (-1 if never done).
    int64_t millisecondsSinceHandshake() const;
    // Milliseconds since the last authenticated packet was received
    // (-1 if none received yet). Used for keepalive decisions.
    int64_t millisecondsSinceLastReceive() const;

private:
    // Anti-replay sliding window (WireGuard-standard 2048-packet bitmap).
    static constexpr size_t REPLAY_WINDOW_BITS = 2048;
    static constexpr size_t REPLAY_WINDOW_WORDS = REPLAY_WINDOW_BITS / 64;

    // Replay decision before decryption. Returns true if the counter is
    // fresh (new or within window and unseen). Does not mutate state.
    bool replayIsFresh(uint64_t counter) const;
    // Record an authenticated packet: mark its bit and advance the window.
    void replayAccept(uint64_t counter);

    void setState(TunnelState s);
    bool deriveDataKeys(const Key& sharedSecret, bool iAmSender);
    // Session-expiry check; caller must hold mutex_.
    bool isSessionExpiredLocked() const;

    TunnelRole role_ = TunnelRole::Client;
    TunnelState state_ = TunnelState::Disconnected;

    Key localPrivateKey_{};
    Key localPublicKey_{};
    Key serverPublicKey_{};   // client's view of server

    // Ephemeral handshake keys
    Key ephemeralPrivateKey_{};
    Key ephemeralPublicKey_{};

    // Derived data keys
    Key senderKey_{};
    Key receiverKey_{};
    uint64_t sendCounter_ = 0;
    bool keysDerived_ = false;

    // Anti-replay window state (receiver side).
    std::array<uint64_t, REPLAY_WINDOW_WORDS> replayBitmap_{};
    uint64_t highestReceivedCounter_ = 0;
    bool replayWindowActive_ = false;

    // Session lifetime tracking.
    std::chrono::steady_clock::time_point handshakeTime_{};
    std::chrono::steady_clock::time_point lastReceiveTime_{};
    bool handshakeTimeValid_ = false;
    bool lastReceiveTimeValid_ = false;
    std::chrono::milliseconds sessionLifetime_{REJECT_AFTER_TIME};

    // Config
    int mtu_ = 1420;
    std::vector<std::string> allowedCidrs_;
    bool dnsOverVpn_ = true;

    mutable std::mutex mutex_;
};

// Simple CIDR match helper (IPv4).
bool ipInCidr(const std::string& ip, const std::string& cidr);

} // namespace vpn
} // namespace lethe

#endif // LETHE_NETWORK_VPN_VPN_TUNNEL_H

