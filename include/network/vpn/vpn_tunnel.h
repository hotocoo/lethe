#ifndef LETHE_NETWORK_VPN_VPN_TUNNEL_H
#define LETHE_NETWORK_VPN_VPN_TUNNEL_H

// vpn_tunnel.h — Built-in VPN tunnel with WireGuard-style handshake
//
// Implements the Lethe built-in VPN as a state machine that performs a
// WireGuard-style handshake and then encrypts/decrypts data packets with
// ChaCha20-Poly1305. The tunnel can operate as a client or as a server so
// that the handshake protocol is fully testable in a loopback fashion.

#include <array>
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

    // Mark the tunnel stale (e.g. after a timeout without keepalive).
    void markStale();
    // Reconnect: reset to Handshaking state.
    void prepareRehandshake();

private:
    void setState(TunnelState s);
    bool deriveDataKeys(const Key& sharedSecret, bool iAmSender);

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
    uint64_t recvCounter_ = 0;
    bool keysDerived_ = false;

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

