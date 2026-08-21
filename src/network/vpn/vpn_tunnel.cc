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

    // Fresh keys start with a clean anti-replay window.
    for (auto& word : replayBitmap_) word = 0;
    highestReceivedCounter_ = 0;
    replayWindowActive_ = false;

    // Session lifetime starts at handshake completion.
    handshakeTime_ = std::chrono::steady_clock::now();
    handshakeTimeValid_ = true;
    lastReceiveTimeValid_ = false;

    keysDerived_ = true;
    return true;
}

// --- Data path ---

bool VpnTunnel::encryptDataPacket(const uint8_t* plaintext, size_t len,
                                  std::vector<uint8_t>& outCiphertext) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!keysDerived_ || state_ != TunnelState::Connected) return false;
    if (len > static_cast<size_t>(mtu_)) return false; // Exceeds MTU

    // WireGuard REJECT_AFTER_MESSAGES / REJECT_AFTER_TIME: refuse to send on
    // an exhausted or expired session. The peer must rekey.
    if (sendCounter_ >= REJECT_AFTER_MESSAGES) { setState(TunnelState::Stale); return false; }
    if (isSessionExpiredLocked()) { setState(TunnelState::Stale); return false; }

    // Encrypt into a scratch buffer (encryptPacket owns its output), then
    // prepend the wire header: 64-bit little-endian packet counter.
    std::vector<uint8_t> box;
    if (!encryptPacket(senderKey_, sendCounter_, plaintext, len, box)) {
        return false;
    }
    outCiphertext.assign(COUNTER_BYTES, 0);
    for (size_t i = 0; i < COUNTER_BYTES; i++) {
        outCiphertext[i] = static_cast<uint8_t>((sendCounter_ >> (8 * i)) & 0xFF);
    }
    outCiphertext.insert(outCiphertext.end(), box.begin(), box.end());
    sendCounter_++;
    return true;
}

bool VpnTunnel::decryptDataPacket(const uint8_t* ciphertext, size_t len,
                                  std::vector<uint8_t>& outPlaintext) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!keysDerived_ || state_ != TunnelState::Connected) return false;
    if (isSessionExpiredLocked()) { setState(TunnelState::Stale); return false; }

    // Parse the explicit wire counter.
    if (!ciphertext || len < COUNTER_BYTES + TAG_BYTES) return false;
    uint64_t counter = 0;
    for (size_t i = 0; i < COUNTER_BYTES; i++) {
        counter |= static_cast<uint64_t>(ciphertext[i]) << (8 * i);
    }

    // Replay rejection BEFORE decryption (cheap, constant work).
    if (counter >= REJECT_AFTER_MESSAGES) return false;
    if (!replayIsFresh(counter)) return false;

    // Authenticate + decrypt with the receiver key and the wire counter.
    const bool ok = decryptPacket(receiverKey_, counter,
                                  ciphertext + COUNTER_BYTES, len - COUNTER_BYTES,
                                  outPlaintext);
    if (!ok) return false; // Unauthenticated packets never move the window.

    replayAccept(counter);
    lastReceiveTime_ = std::chrono::steady_clock::now();
    lastReceiveTimeValid_ = true;
    return true;
}

// --- Anti-replay sliding window -------------------------------------------

bool VpnTunnel::replayIsFresh(uint64_t counter) const {
    if (!replayWindowActive_) return true; // First packet of the session.
    if (counter > highestReceivedCounter_) return true; // New packet.
    // Too old: outside the window behind the highest seen counter.
    if (counter + REPLAY_WINDOW_BITS <= highestReceivedCounter_) return false;
    // Within window: reject if already seen.
    const uint64_t offset = highestReceivedCounter_ - counter; // < WINDOW here
    const size_t word = static_cast<size_t>(offset / 64);
    const uint64_t bit = 1ull << (offset % 64);
    return (replayBitmap_[word] & bit) == 0;
}

void VpnTunnel::replayAccept(uint64_t counter) {
    if (!replayWindowActive_) {
        replayWindowActive_ = true;
        highestReceivedCounter_ = counter;
        replayBitmap_.fill(0);
        replayBitmap_[0] |= 1ull; // Mark offset 0 (counter == highest).
        return;
    }
    if (counter > highestReceivedCounter_) {
        // Advance the window. Bit at old offset o moves to new offset
        // o + advance, i.e. the bitmap shifts LEFT (toward higher offsets).
        const uint64_t advance = counter - highestReceivedCounter_;
        highestReceivedCounter_ = counter;
        if (advance >= REPLAY_WINDOW_BITS) {
            replayBitmap_.fill(0);
        } else {
            const size_t ws = static_cast<size_t>(advance / 64);
            const size_t bs = static_cast<size_t>(advance % 64);
            std::array<uint64_t, REPLAY_WINDOW_WORDS> next{};
            for (size_t w = 0; w < REPLAY_WINDOW_WORDS; w++) {
                uint64_t v = 0;
                const int64_t hi = static_cast<int64_t>(w) - static_cast<int64_t>(ws);
                const int64_t lo = hi - 1;
                if (bs == 0) {
                    if (hi >= 0 && hi < static_cast<int64_t>(REPLAY_WINDOW_WORDS)) {
                        v = replayBitmap_[static_cast<size_t>(hi)];
                    }
                } else {
                    if (hi >= 0 && hi < static_cast<int64_t>(REPLAY_WINDOW_WORDS)) {
                        v |= replayBitmap_[static_cast<size_t>(hi)] << bs;
                    }
                    if (lo >= 0 && lo < static_cast<int64_t>(REPLAY_WINDOW_WORDS)) {
                        v |= replayBitmap_[static_cast<size_t>(lo)] >> (64 - bs);
                    }
                }
                next[w] = v;
            }
            replayBitmap_ = next;
        }
    }
    const uint64_t offset = highestReceivedCounter_ - counter;
    replayBitmap_[static_cast<size_t>(offset / 64)] |= 1ull << (offset % 64);
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
    for (auto& word : replayBitmap_) word = 0;
    highestReceivedCounter_ = 0;
    replayWindowActive_ = false;
    handshakeTimeValid_ = false;
    lastReceiveTimeValid_ = false;
    setState(TunnelState::Handshaking);
}

// --- Session lifetime -------------------------------------------------------

bool VpnTunnel::isSessionExpiredLocked() const {
    if (!handshakeTimeValid_) return false;
    return std::chrono::steady_clock::now() - handshakeTime_ > sessionLifetime_;
}

void VpnTunnel::setSessionLifetime(std::chrono::milliseconds ms) {
    std::lock_guard<std::mutex> lock(mutex_);
    sessionLifetime_ = ms;
}

std::chrono::milliseconds VpnTunnel::sessionLifetime() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return sessionLifetime_;
}

bool VpnTunnel::isSessionExpired() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return isSessionExpiredLocked();
}

int64_t VpnTunnel::millisecondsSinceHandshake() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!handshakeTimeValid_) return -1;
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - handshakeTime_).count();
}

int64_t VpnTunnel::millisecondsSinceLastReceive() const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!lastReceiveTimeValid_) return -1;
    return std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - lastReceiveTime_).count();
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

