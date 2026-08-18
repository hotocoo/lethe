#ifndef LETHE_NETWORK_VPN_WIREGUARD_CIPHER_H
#define LETHE_NETWORK_VPN_WIREGUARD_CIPHER_H

// wireguard_cipher.h — Built-in VPN cryptography for Lethe
//
// WireGuard-style primitives implemented with OpenSSL 3.x:
//   - X25519 ECDH for key exchange
//   - ChaCha20-Poly1305 AEAD for packet encryption
//   - HMAC-SHA256 / SHA256 for indexing and integrity
//   - HKDF-SHA256 for key derivation
//
// All keys are fixed-size byte arrays (32 bytes) to avoid variable-length
// secret material on the stack. No telemetry, no external dependencies
// beyond OpenSSL.

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace lethe {
namespace vpn {

constexpr size_t KEY_BYTES = 32;      // X25519 key size
constexpr size_t NONCE_BYTES = 12;    // ChaCha20-Poly1305 nonce size
constexpr size_t TAG_BYTES = 16;      // Poly1305 auth tag size
constexpr size_t HANDSHAKE_NONCE_BYTES = 32; // handshake init/response nonces
constexpr size_t COUNTER_BYTES = 8;   // packet counter (little-endian u64)

using Key = std::array<uint8_t, KEY_BYTES>;
using Nonce = std::array<uint8_t, NONCE_BYTES>;
using HandshakeNonce = std::array<uint8_t, HANDSHAKE_NONCE_BYTES>;
using Mac = std::array<uint8_t, KEY_BYTES>; // SHA256/HMAC digest size

// --- Key generation -------------------------------------------------------

// Generate a random X25519 private key (crypto-secure RNG).
bool generatePrivateKey(Key& outKey);

// Derive the X25519 public key from a private key.
bool derivePublicKey(const Key& privateKey, Key& outPublicKey);

// --- ECDH -----------------------------------------------------------------

// Perform X25519 shared-secret computation (WireGuard handshake step).
bool ecdh(const Key& privateKey, const Key& theirPublicKey, Key& outSharedSecret);

// --- AEAD (ChaCha20-Poly1305) ---------------------------------------------

// Encrypt plaintext with ChaCha20-Poly1305. Output = ciphertext || tag.
bool encryptPacket(const Key& key, const uint64_t counter,
                   const uint8_t* plaintext, size_t len,
                   std::vector<uint8_t>& outCiphertext);

// Decrypt ChaCha20-Poly1305 ciphertext (ciphertext || tag). Returns false
// on authentication failure (tampered packet).
bool decryptPacket(const Key& key, const uint64_t counter,
                   const uint8_t* ciphertext, size_t len,
                   std::vector<uint8_t>& outPlaintext);

// --- Hashing / MAC ---------------------------------------------------------

// SHA256 digest.
Mac sha256(const uint8_t* data, size_t len);
Mac sha256(const std::vector<uint8_t>& data);

// HMAC-SHA256.
Mac hmacSha256(const Key& key, const uint8_t* data, size_t len);
Mac hmacSha256(const Key& key, const std::vector<uint8_t>& data);
Mac hmacSha256(const Key& key, const Key& data);

// HKDF-SHA256: derive an output key of KEY_BYTES from input key material.
bool hkdfSha256(const uint8_t* ikm, size_t ikmLen, const uint8_t* salt, size_t saltLen,
                const uint8_t* info, size_t infoLen, Key& outKey);

// --- Utilities --------------------------------------------------------------

// Constant-time comparison (timing-safe).
bool constantTimeEquals(const uint8_t* a, const uint8_t* b, size_t len);

// Hex-encode bytes (for config files / logs without leaking raw keys).
std::string toHex(const uint8_t* data, size_t len);
std::string toHex(const Key& key);

// Parse hex string into key; returns false on bad input.
bool fromHex(const std::string& hex, Key& outKey);

// Generate a random nonce.
void generateRandomNonce(Nonce& outNonce);
void generateRandomHandshakeNonce(HandshakeNonce& outNonce);

} // namespace vpn
} // namespace lethe

#endif // LETHE_NETWORK_VPN_WIREGUARD_CIPHER_H

