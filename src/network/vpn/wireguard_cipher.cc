// wireguard_cipher.cc — Built-in VPN cryptography implementation (OpenSSL 3.x)
//
// Real cryptographic primitives for the Lethe built-in VPN. Uses OpenSSL's
// EVP high-level API for X25519, ChaCha20-Poly1305, HMAC-SHA256, and HKDF.

#include "network/vpn/wireguard_cipher.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/kdf.h>
#include <openssl/hmac.h>
#include <cstring>
#include <stdexcept>

namespace lethe {
namespace vpn {

// --- Key generation -------------------------------------------------------

bool generatePrivateKey(Key& outKey) {
    EVP_PKEY* pkey = EVP_PKEY_Q_keygen(NULL, NULL, "X25519", NULL);
    if (!pkey) return false;

    size_t len = KEY_BYTES;
    bool ok = EVP_PKEY_get_raw_private_key(pkey, outKey.data(), &len) == 1 && len == KEY_BYTES;
    EVP_PKEY_free(pkey);
    return ok;
}

bool derivePublicKey(const Key& privateKey, Key& outPublicKey) {
    EVP_PKEY* pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                                  privateKey.data(), KEY_BYTES);
    if (!pkey) return false;

    size_t len = KEY_BYTES;
    bool ok = EVP_PKEY_get_raw_public_key(pkey, outPublicKey.data(), &len) == 1 && len == KEY_BYTES;
    EVP_PKEY_free(pkey);
    return ok;
}

// --- ECDH -----------------------------------------------------------------

bool ecdh(const Key& privateKey, const Key& theirPublicKey, Key& outSharedSecret) {
    EVP_PKEY* priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                                  privateKey.data(), KEY_BYTES);
    if (!priv) return false;

    EVP_PKEY* pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                                theirPublicKey.data(), KEY_BYTES);
    if (!pub) { EVP_PKEY_free(priv); return false; }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, NULL);
    size_t outLen = KEY_BYTES;
    bool ok = false;
    if (ctx) {
        ok = EVP_PKEY_derive_init(ctx) == 1 &&
             EVP_PKEY_derive_set_peer(ctx, pub) == 1 &&
             EVP_PKEY_derive(ctx, outSharedSecret.data(), &outLen) == 1 &&
             outLen == KEY_BYTES;
        EVP_PKEY_CTX_free(ctx);
    }

    EVP_PKEY_free(priv);
    EVP_PKEY_free(pub);
    return ok;
}

// --- AEAD (ChaCha20-Poly1305) ---------------------------------------------

bool encryptPacket(const Key& key, const uint64_t counter,
                   const uint8_t* plaintext, size_t len,
                   std::vector<uint8_t>& outCiphertext) {
    outCiphertext.assign(len + TAG_BYTES, 0);

    // Build 12-byte nonce: 4 zero bytes + 8-byte little-endian counter.
    uint8_t nonce[NONCE_BYTES] = {0};
    for (size_t i = 0; i < COUNTER_BYTES; i++) {
        nonce[NONCE_BYTES - 1 - i] = static_cast<uint8_t>((counter >> (8 * i)) & 0xFF);
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool ok = false;
    int outLen = 0, finalLen = 0;
    if (EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key.data(), nonce) == 1 &&
        EVP_EncryptUpdate(ctx, outCiphertext.data(), &outLen, plaintext, static_cast<int>(len)) == 1 &&
        EVP_EncryptFinal_ex(ctx, outCiphertext.data() + outLen, &finalLen) == 1) {
        // Get the authentication tag.
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, TAG_BYTES,
                                outCiphertext.data() + len) == 1) {
            ok = true;
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) outCiphertext.clear();
    return ok;
}

bool decryptPacket(const Key& key, const uint64_t counter,
                   const uint8_t* ciphertext, size_t len,
                   std::vector<uint8_t>& outPlaintext) {
    if (len < TAG_BYTES) return false;
    outPlaintext.assign(len - TAG_BYTES, 0);

    uint8_t nonce[NONCE_BYTES] = {0};
    for (size_t i = 0; i < COUNTER_BYTES; i++) {
        nonce[NONCE_BYTES - 1 - i] = static_cast<uint8_t>((counter >> (8 * i)) & 0xFF);
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return false;

    bool ok = false;
    int outLen = 0, finalLen = 0;
    if (EVP_DecryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key.data(), nonce) == 1) {
        // Set the authentication tag for verification.
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, TAG_BYTES,
                                const_cast<uint8_t*>(ciphertext + len - TAG_BYTES)) == 1 &&
            EVP_DecryptUpdate(ctx, outPlaintext.data(), &outLen,
                              ciphertext, static_cast<int>(len - TAG_BYTES)) == 1 &&
            EVP_DecryptFinal_ex(ctx, outPlaintext.data() + outLen, &finalLen) == 1) {
            ok = true;
        }
    }
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) outPlaintext.clear();
    return ok;
}

// --- Hashing / MAC ---------------------------------------------------------

Mac sha256(const uint8_t* data, size_t len) {
    Mac digest{};
    unsigned int outLen = 0;
    EVP_Digest(data, len, digest.data(), &outLen, EVP_sha256(), NULL);
    return digest;
}

Mac sha256(const std::vector<uint8_t>& data) {
    return sha256(data.data(), data.size());
}

Mac hmacSha256(const Key& key, const uint8_t* data, size_t len) {
    Mac digest{};
    unsigned int outLen = 0;
    HMAC(EVP_sha256(), key.data(), KEY_BYTES, data, len, digest.data(), &outLen);
    return digest;
}

Mac hmacSha256(const Key& key, const std::vector<uint8_t>& data) {
    return hmacSha256(key, data.data(), data.size());
}

Mac hmacSha256(const Key& key, const Key& data) {
    return hmacSha256(key, data.data(), data.size());
}

bool hkdfSha256(const uint8_t* ikm, size_t ikmLen, const uint8_t* salt, size_t saltLen,
                const uint8_t* info, size_t infoLen, Key& outKey) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL);
    if (!ctx) return false;

    bool ok = false;
    size_t outLen = KEY_BYTES;

    // Initialize and set the digest.
    if (EVP_PKEY_derive_init(ctx) != 1 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    // Set the salt (only if provided).
    if (salt != nullptr && saltLen > 0) {
        if (EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt, saltLen) != 1) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
    }

    // Set the input key material.
    if (EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm, ikmLen) != 1) {
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    // Set the info (only if provided).
    if (info != nullptr && infoLen > 0) {
        if (EVP_PKEY_CTX_add1_hkdf_info(ctx, info, infoLen) != 1) {
            EVP_PKEY_CTX_free(ctx);
            return false;
        }
    }

    // Derive the key.
    if (EVP_PKEY_derive(ctx, outKey.data(), &outLen) == 1 && outLen == KEY_BYTES) {
        ok = true;
    }

    EVP_PKEY_CTX_free(ctx);
    return ok;
}

// --- Utilities --------------------------------------------------------------

void secureCleanse(void* p, size_t n) {
    if (!p || n == 0) return;
#if defined(HAVE_OPENSSL)
    OPENSSL_cleanse(p, n);
#elif defined(__GNUC__)
    static void* (*volatile cleanse)(void*, int, size_t) = std::memset;
    cleanse(p, 0, n);
#else
    std::memset(p, 0, n);
#endif
}

bool constantTimeEquals(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    return diff == 0;
}

std::string toHex(const uint8_t* data, size_t len) {
    static const char* hex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; i++) {
        out.push_back(hex[data[i] >> 4]);
        out.push_back(hex[data[i] & 0x0F]);
    }
    return out;
}

std::string toHex(const Key& key) { return toHex(key.data(), key.size()); }

bool fromHex(const std::string& hex, Key& outKey) {
    if (hex.size() != KEY_BYTES * 2) return false;
    auto val = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    for (size_t i = 0; i < KEY_BYTES; i++) {
        int hi = val(hex[i * 2]);
        int lo = val(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        outKey[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

void generateRandomNonce(Nonce& outNonce) {
    RAND_bytes(outNonce.data(), NONCE_BYTES);
}

void generateRandomHandshakeNonce(HandshakeNonce& outNonce) {
    RAND_bytes(outNonce.data(), HANDSHAKE_NONCE_BYTES);
}

} // namespace vpn
} // namespace lethe

