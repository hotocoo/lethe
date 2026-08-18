// vpn_tunnel.cc — Built-in VPN tunnel with WireGuard-style handshake
//
// Implements the Lethe built-in VPN handshake and data path. The handshake
// follows the WireGuard model: an ephemeral key exchange indexed by HMAC,
// producing a shared secret from which directional data keys are derived.

#include "network/vpn/vpn_tunnel.h"
#include <cstring>
#include <iostream>
#include <map>

namespace lethe {
namespace vpn {

// --- HandshakeMessage serialization ---------------------------------------
//
// Wire format (little-endian):
//   [0]        type (1 byte)
//   [1..32]    index (32 bytes, MAC)
//   [33..64]   ephemeralPublicKey (32 bytes)
//   [65..96]   nonce (32 bytes)
//   [97..]     encryptedData (variable length, Response only)

std::vector<uint8_t> HandshakeMessage::serialize() const {
    std::vector<uint8_t> buf;
    buf.reserve(97 + encryptedData.size());
    buf.push_back(static_cast<uint8_t>(type));
    buf.insert(buf.end(), index.begin(), index.end());
    buf.insert(buf.end(), ephemeralPublicKey.begin(), ephemeralPublicKey.end());
    buf.insert(buf.end(), nonce.begin(), nonce.end());
    buf.insert(buf.end(), encryptedData.begin(), encryptedData.end());
    return buf;
}

bool HandshakeMessage::deserialize(const uint8_t* data, size_t len, HandshakeMessage& out) {
    constexpr size_t MIN_LEN = 1 + KEY_BYTES + KEY_BYTES + HANDSHAKE_NONCE_BYTES;
    if (!data || len < MIN_LEN) return false;

    size_t off = 0;
    out.type = static_cast<HandshakeType>(data[off++]);
    std::memcpy(out.index.data(), data + off, KEY_BYTES); off += KEY_BYTES;
    std::memcpy(out.ephemeralPublicKey.data(), data + off, KEY_BYTES); off += KEY_BYTES;
    std::memcpy(out.nonce.data(), data + off, HANDSHAKE_NONCE_BYTES); off += HANDSHAKE_NONCE_BYTES;
    out.encryptedData.assign(data + off, data + len);
    return true;
}

// --- VpnTunnel --------------------------------------------------------------

namespace {
// Server-side pending handshake record.
struct PendingHandshake {
    Key clientEphemeralPublicKey{};
    Key serverEphemeralPrivateKey{};
    Key serverEphemeralPublicKey{};
    Key sharedSecret{};
};
} // namespace

VpnTunnel::VpnTunnel() = default;
VpnTunnel::~VpnTunnel() = default;

void VpnTunnel::setState(TunnelState s) {
    state_ = s;
}

bool VpnTunnel::configureClient(const VpnConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!config.isValid()) return false;

    role_ = TunnelRole::Client;
    serverPublicKey_ = config.serverPublicKey;
    mtu_ = config.mtu;
    allowedCidrs_ = config.allowedCidrs;
    dnsOverVpn_ = config.dnsOverVpn;

    // Use provided private key or generate one.
    if (config.privateKey != Key{}) {
        localPrivateKey_ = config.privateKey;
    } else {
        if (!generatePrivateKey(localPrivateKey_)) return false;
    }
    if (!derivePublicKey(localPrivateKey_, localPublicKey_)) return false;

    setState(TunnelState::Disconnected);
    keysDerived_ = false;
    std::cout << "[lethe-vpn] Client tunnel configured for " << config.endpoint() << std::endl;
    return true;
}

bool VpnTunnel::configureServer(const Key& serverPrivateKey) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (serverPrivateKey == Key{}) return false;

    role_ = TunnelRole::Server;
    localPrivateKey_ = serverPrivateKey;
    if (!derivePublicKey(localPrivateKey_, localPublicKey_)) return false;

    setState(TunnelState::Disconnected);
    keysDerived_ = false;
    std::cout << "[lethe-vpn] Server tunnel configured" << std::endl;
    return true;
}

// --- Handshake (client side) ---

bool VpnTunnel::createHandshakeInit(HandshakeMessage& outMessage) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (role_ != TunnelRole::Client) return false;

    // Generate ephemeral key pair.
    if (!generatePrivateKey(ephemeralPrivateKey_)) return false;
    if (!derivePublicKey(ephemeralPrivateKey_, ephemeralPublicKey_)) return false;

    // index = HMAC-SHA256(server_public_key, client_ephemeral_public_key)
    outMessage.index = hmacSha256(serverPublicKey_, ephemeralPublicKey_);

    outMessage.type = HandshakeType::Init;
    outMessage.ephemeralPublicKey = ephemeralPublicKey_;
    generateRandomHandshakeNonce(outMessage.nonce);
    outMessage.encryptedData.clear();

    setState(TunnelState::Handshaking);
    return true;
}

bool VpnTunnel::processHandshakeResponse(const HandshakeMessage& message) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (role_ != TunnelRole::Client || message.type != HandshakeType::Response) return false;

    // Verify the index matches what we sent.
    Mac expectedIndex = hmacSha256(serverPublicKey_, ephemeralPublicKey_);
    if (!constantTimeEquals(expectedIndex.data(), message.index.data(), KEY_BYTES)) {
        setState(TunnelState::Error);
        return false;
    }

    // Compute shared secret from our ephemeral private key and the server's
    // ephemeral public key.
    Key sharedSecret{};
    if (!ecdh(ephemeralPrivateKey_, message.ephemeralPublicKey, sharedSecret)) {
        setState(TunnelState::Error);
        return false;
    }

    // Derive directional data keys. Client is the initiator.
    if (!deriveDataKeys(sharedSecret, /*iAmInitiator=*/true)) {
        setState(TunnelState::Error);
        return false;
    }

    // Clear ephemeral keys (forward secrecy).
    ephemeralPrivateKey_.fill(0);
    ephemeralPublicKey_.fill(0);

    setState(TunnelState::Connected);
    std::cout << "[lethe-vpn] Handshake complete, tunnel connected" << std::endl;
    return true;
}

// --- Handshake (server side) ---

bool VpnTunnel::processHandshakeInit(const HandshakeMessage& message, HandshakeMessage& outResponse) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (role_ != TunnelRole::Server || message.type != HandshakeType::Init) return false;

    // Verify the index: HMAC-SHA256(server_public_key, client_ephemeral_public_key)
    Mac expectedIndex = hmacSha256(localPublicKey_, message.ephemeralPublicKey);
    if (!constantTimeEquals(expectedIndex.data(), message.index.data(), KEY_BYTES)) {
        return false; // Unknown or tampered handshake
    }

    // Generate server ephemeral key pair.
    if (!generatePrivateKey(ephemeralPrivateKey_)) return false;
    if (!derivePublicKey(ephemeralPrivateKey_, ephemeralPublicKey_)) return false;

    // Compute shared secret.
    Key sharedSecret{};
    if (!ecdh(ephemeralPrivateKey_, message.ephemeralPublicKey, sharedSecret)) return false;

    // Derive directional data keys. Server is the responder.
    if (!deriveDataKeys(sharedSecret, /*iAmInitiator=*/false)) return false;

    // Build encrypted handshake payload (server nonce + confirmation).
    // We encrypt a small confirmation blob with the sender key.
    std::vector<uint8_t> payload;
    payload.insert(payload.end(), ephemeralPublicKey_.begin(), ephemeralPublicKey_.end());
    HandshakeMessage tempNonce;
    generateRandomHandshakeNonce(tempNonce.nonce);
    payload.insert(payload.end(), tempNonce.nonce.begin(), tempNonce.nonce.end());

    if (!encryptPacket(senderKey_, 0, payload.data(), payload.size(), outResponse.encryptedData)) {
        return false;
    }

    outResponse.type = HandshakeType::Response;
    outResponse.index = message.index;
    outResponse.ephemeralPublicKey = ephemeralPublicKey_;
    outResponse.nonce = tempNonce.nonce;

    // Clear ephemeral keys (forward secrecy).
    ephemeralPrivateKey_.fill(0);
    ephemeralPublicKey_.fill(0);

    setState(TunnelState::Connected);
    std::cout << "[lethe-vpn] Server handshake complete, tunnel connected" << std::endl;
    return true;
}

bool VpnTunnel::deriveDataKeys(const Key& sharedSecret, bool iAmInitiator) {
    // Derive directional keys from the shared secret.
    // Direction "initiator->responder" uses info "lethe-vpn-i2r".
    // Direction "responder->initiator" uses info "lethe-vpn-r2i".
    Key i2rKey{}, r2iKey{};
    const uint8_t infoI2r[] = "lethe-vpn-i2r";
    const uint8_t infoR2I[] = "lethe-vpn-r2i";
    if (!hkdfSha256(sharedSecret.data(), KEY_BYTES, nullptr, 0, infoI2r, sizeof(infoI2r) - 1, i2rKey)) return false;
    if (!hkdfSha256(sharedSecret.data(), KEY_BYTES, nullptr, 0, infoR2I, sizeof(infoR2I) - 1, r2iKey)) return false;

    if (iAmInitiator) {
        senderKey_ = i2rKey;   // I send initiator->responder
        receiverKey_ = r2iKey; // I receive responder->initiator
    } else {
        senderKey_ = r2iKey;   // I send responder->initiator
        receiverKey_ = i2rKey; // I receive initiator->responder
    }

    sendCounter_ = 0;
    recvCounter_ = 0;
    keysDerived_ = true;
    return true;
}

// --- Data path ---

bool VpnTunnel::encryptDataPacket(const uint8_t* plaintext, size_t len,
                                  std::vector<uint8_t>& outCiphertext) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!keysDerived_ || state_ != TunnelState::Connected) return false;
    if (len > static_cast<size_t>(mtu_)) return false; // Exceeds MTU

    bool ok = encryptPacket(senderKey_, sendCounter_, plaintext, len, outCiphertext);
    if (ok) sendCounter_++;
    return ok;
}

bool VpnTunnel::decryptDataPacket(const uint8_t* ciphertext, size_t len,
                                  std::vector<uint8_t>& outPlaintext) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!keysDerived_ || state_ != TunnelState::Connected) return false;

    // Try to decrypt with the receiver key and the current receive counter.
    bool ok = decryptPacket(receiverKey_, recvCounter_, ciphertext, len, outPlaintext);
    if (ok) recvCounter_++;
    return ok;
}

// --- Routing ---

bool VpnTunnel::shouldRouteThroughVpn(const std::string& destIp) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (allowedCidrs_.empty()) return false;
    for (const auto& cidr : allowedCidrs_) {
        if (ipInCidr(destIp, cidr)) return true;
    }
    return false;
}

void VpnTunnel::markStale() {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ == TunnelState::Connected) {
        setState(TunnelState::Stale);
        std::cout << "[lethe-vpn] Tunnel marked stale" << std::endl;
    }
}

void VpnTunnel::prepareRehandshake() {
    std::lock_guard<std::mutex> lock(mutex_);
    keysDerived_ = false;
    senderKey_.fill(0);
    receiverKey_.fill(0);
    sendCounter_ = 0;
    recvCounter_ = 0;
    setState(TunnelState::Handshaking);
}

// --- CIDR matching (IPv4) ---

namespace {
bool parseIpv4(const std::string& ip, uint32_t& out) {
    uint32_t result = 0;
    int part = 0;
    uint32_t cur = 0;
    for (size_t i = 0; i < ip.size(); i++) {
        char c = ip[i];
        if (c >= '0' && c <= '9') {
            cur = cur * 10 + (c - '0');
            if (cur > 255) return false;
        } else if (c == '.') {
            if (part >= 3) return false;
            result = (result << 8) | cur;
            cur = 0;
            part++;
        } else {
            return false;
        }
    }
    if (part != 3) return false;
    result = (result << 8) | cur;
    out = result;
    return true;
}
} // namespace

bool ipInCidr(const std::string& ip, const std::string& cidr) {
    // Split CIDR into network and prefix length.
    size_t slash = cidr.find('/');
    std::string netPart = (slash == std::string::npos) ? cidr : cidr.substr(0, slash);
    int prefixLen = 32;
    if (slash != std::string::npos) {
        try { prefixLen = std::stoi(cidr.substr(slash + 1)); } catch (...) { return false; }
        if (prefixLen < 0 || prefixLen > 32) return false;
    }

    uint32_t ipNum, netNum;
    if (!parseIpv4(ip, ipNum) || !parseIpv4(netPart, netNum)) return false;

    if (prefixLen == 0) return true;
    uint32_t mask = (prefixLen == 32) ? 0xFFFFFFFF : (~0u << (32 - prefixLen));
    return (ipNum & mask) == (netNum & mask);
}

} // namespace vpn
} // namespace lethe

