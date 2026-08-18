// test_vpn_crypto.cc — Tests for the built-in VPN cryptography

#include "test_framework.h"
#include "network/vpn/wireguard_cipher.h"

using namespace lethe::vpn;

LETHE_TEST_CASE(VpnCrypto_KeyGeneration) {
    Key key1{};
    Key key2{};
    CHECK_TRUE(generatePrivateKey(key1));
    CHECK_TRUE(generatePrivateKey(key2));
    // Keys should be non-zero.
    CHECK_FALSE(key1 == Key{});
    CHECK_FALSE(key2 == Key{});
    // Two generated keys should differ.
    CHECK_FALSE(key1 == key2);
}

LETHE_TEST_CASE(VpnCrypto_PublicKeyDerivation) {
    Key priv{};
    Key pub{};
    CHECK_TRUE(generatePrivateKey(priv));
    CHECK_TRUE(derivePublicKey(priv, pub));
    CHECK_FALSE(pub == Key{});

    // Deriving again should give the same public key.
    Key pub2{};
    CHECK_TRUE(derivePublicKey(priv, pub2));
    CHECK_TRUE(constantTimeEquals(pub.data(), pub2.data(), KEY_BYTES));
}

LETHE_TEST_CASE(VpnCrypto_ECDH_Symmetric) {
    // Alice and Bob generate keys, compute shared secrets, should match.
    Key alicePriv{}, alicePub{};
    Key bobPriv{}, bobPub{};
    CHECK_TRUE(generatePrivateKey(alicePriv));
    CHECK_TRUE(generatePrivateKey(bobPriv));
    CHECK_TRUE(derivePublicKey(alicePriv, alicePub));
    CHECK_TRUE(derivePublicKey(bobPriv, bobPub));

    Key aliceShared{};
    Key bobShared{};
    CHECK_TRUE(ecdh(alicePriv, bobPub, aliceShared));
    CHECK_TRUE(ecdh(bobPriv, alicePub, bobShared));

    // Shared secrets must match.
    CHECK_TRUE(constantTimeEquals(aliceShared.data(), bobShared.data(), KEY_BYTES));
    CHECK_FALSE(aliceShared == Key{});
}

LETHE_TEST_CASE(VpnCrypto_Chacha20Poly1305_RoundTrip) {
    Key key{};
    CHECK_TRUE(generatePrivateKey(key));

    std::string plaintext = "Hello, Lethe VPN! This is a test message.";
    std::vector<uint8_t> ciphertext;

    CHECK_TRUE(encryptPacket(key, 0,
                             reinterpret_cast<const uint8_t*>(plaintext.data()),
                             plaintext.size(), ciphertext));

    // Ciphertext should be plaintext + tag.
    CHECK_EQ(ciphertext.size(), plaintext.size() + TAG_BYTES);

    // Ciphertext should differ from plaintext.
    CHECK_FALSE(constantTimeEquals(
        reinterpret_cast<const uint8_t*>(plaintext.data()),
        ciphertext.data(), plaintext.size()));

    // Decrypt.
    std::vector<uint8_t> decrypted;
    CHECK_TRUE(decryptPacket(key, 0, ciphertext.data(), ciphertext.size(), decrypted));

    std::string decryptedStr(decrypted.begin(), decrypted.end());
    CHECK_EQ(decryptedStr, plaintext);
}

LETHE_TEST_CASE(VpnCrypto_Chacha20Poly1305_TamperDetection) {
    Key key{};
    CHECK_TRUE(generatePrivateKey(key));

    std::string plaintext = "Sensitive data";
    std::vector<uint8_t> ciphertext;
    CHECK_TRUE(encryptPacket(key, 0,
                             reinterpret_cast<const uint8_t*>(plaintext.data()),
                             plaintext.size(), ciphertext));

    // Tamper with the ciphertext.
    ciphertext[0] ^= 0xFF;

    std::vector<uint8_t> decrypted;
    CHECK_FALSE(decryptPacket(key, 0, ciphertext.data(), ciphertext.size(), decrypted));
}

LETHE_TEST_CASE(VpnCrypto_Chacha20Poly1305_WrongKey) {
    Key key1{}, key2{};
    CHECK_TRUE(generatePrivateKey(key1));
    CHECK_TRUE(generatePrivateKey(key2));

    std::string plaintext = "Test message";
    std::vector<uint8_t> ciphertext;
    CHECK_TRUE(encryptPacket(key1, 0,
                             reinterpret_cast<const uint8_t*>(plaintext.data()),
                             plaintext.size(), ciphertext));

    // Decrypting with the wrong key should fail.
    std::vector<uint8_t> decrypted;
    CHECK_FALSE(decryptPacket(key2, 0, ciphertext.data(), ciphertext.size(), decrypted));
}

LETHE_TEST_CASE(VpnCrypto_Chacha20Poly1305_DifferentCounters) {
    Key key{};
    CHECK_TRUE(generatePrivateKey(key));

    std::string plaintext = "Same plaintext";
    std::vector<uint8_t> ct0, ct1;
    CHECK_TRUE(encryptPacket(key, 0,
                             reinterpret_cast<const uint8_t*>(plaintext.data()),
                             plaintext.size(), ct0));
    CHECK_TRUE(encryptPacket(key, 1,
                             reinterpret_cast<const uint8_t*>(plaintext.data()),
                             plaintext.size(), ct1));

    // Different counters should produce different ciphertexts.
    CHECK_FALSE(constantTimeEquals(ct0.data(), ct1.data(), ct0.size()));
}

LETHE_TEST_CASE(VpnCrypto_SHA256) {
    // Test SHA256 with a known value.
    std::string input = "abc";
    Mac digest = sha256(reinterpret_cast<const uint8_t*>(input.data()), input.size());
    std::string hex = toHex(digest.data(), digest.size());
    // SHA256("abc") = ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    CHECK_EQ(hex, std::string("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"));
}

LETHE_TEST_CASE(VpnCrypto_HMAC_SHA256) {
    Key key{};
    CHECK_TRUE(generatePrivateKey(key));

    std::string input = "The quick brown fox";
    Mac mac = hmacSha256(key, reinterpret_cast<const uint8_t*>(input.data()), input.size());
    CHECK_FALSE(mac == Mac{});

    // Same input and key should give same MAC.
    Mac mac2 = hmacSha256(key, reinterpret_cast<const uint8_t*>(input.data()), input.size());
    CHECK_TRUE(constantTimeEquals(mac.data(), mac2.data(), KEY_BYTES));

    // Different input should give different MAC.
    std::string input2 = "The quick brown fox jumps";
    Mac mac3 = hmacSha256(key, reinterpret_cast<const uint8_t*>(input2.data()), input2.size());
    CHECK_FALSE(constantTimeEquals(mac.data(), mac3.data(), KEY_BYTES));
}

LETHE_TEST_CASE(VpnCrypto_HKDF) {
    Key ikm{};
    CHECK_TRUE(generatePrivateKey(ikm));

    Key derived1{}, derived2{};
    const uint8_t info1[] = "lethe-vpn-test-1";
    const uint8_t info2[] = "lethe-vpn-test-2";

    CHECK_TRUE(hkdfSha256(ikm.data(), KEY_BYTES, nullptr, 0,
                          info1, sizeof(info1) - 1, derived1));
    CHECK_TRUE(hkdfSha256(ikm.data(), KEY_BYTES, nullptr, 0,
                          info2, sizeof(info2) - 1, derived2));

    // Different info should give different derived keys.
    CHECK_FALSE(constantTimeEquals(derived1.data(), derived2.data(), KEY_BYTES));

    // Same info should give same derived key.
    Key derived3{};
    CHECK_TRUE(hkdfSha256(ikm.data(), KEY_BYTES, nullptr, 0,
                          info1, sizeof(info1) - 1, derived3));
    CHECK_TRUE(constantTimeEquals(derived1.data(), derived3.data(), KEY_BYTES));
}

LETHE_TEST_CASE(VpnCrypto_HexEncoding) {
    Key key{};
    CHECK_TRUE(generatePrivateKey(key));

    std::string hex = toHex(key);
    CHECK_EQ(hex.size(), KEY_BYTES * 2);

    // Round-trip.
    Key decoded{};
    CHECK_TRUE(fromHex(hex, decoded));
    CHECK_TRUE(constantTimeEquals(key.data(), decoded.data(), KEY_BYTES));
}

LETHE_TEST_CASE(VpnCrypto_HexParsing_Invalid) {
    Key key{};
    // Invalid hex should fail.
    CHECK_FALSE(fromHex("zzzz", key));
    // Wrong length should fail.
    CHECK_FALSE(fromHex("abc", key));
    // Valid but wrong length for a key.
    CHECK_FALSE(fromHex("aabbccdd", key));
}

