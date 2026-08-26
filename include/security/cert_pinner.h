#ifndef LETHE_SECURITY_CERT_PINNER_H
#define LETHE_SECURITY_CERT_PINNER_H

// cert_pinner.h — Per-host certificate pinning (SPKI SHA-256).
//
// A host with pins accepts only TLS chains in which at least one
// certificate's SubjectPublicKeyInfo hashes (SHA-256) to one of the
// configured digests. Pinning is ADDITIVE to ordinary certificate
// verification: it never turns verification off, it only narrows what a
// verified chain may contain. Enforcement lives in HttpClient::startTls,
// which runs on every hop — redirect targets included — so every origin of
// a navigation chain is pinned by its own name.
//
// Pins use the HPKP-style wire spelling "sha256-<standard base64>" of the
// 32-byte SPKI digest. Matching is done on raw digest bytes.
//
// Scope: exact-host match only (no wildcard/subdomain coverage). Hosts are
// normalized to lowercase, mirroring DNS name semantics elsewhere in the
// client. The store is memory-only configuration — nothing persists.

#include <array>
#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace lethe {

class CertPinner {
public:
    static constexpr size_t kDigestSize = 32;

    using Digest = std::array<uint8_t, kDigestSize>;

    // Parse "sha256-<base64>" into the 32 raw digest bytes. Accepts both
    // padded and unpadded base64; rejects wrong prefixes, non-canonical
    // alphabets, and any decoded length other than 32 bytes.
    static bool parsePin(const std::string& pin, Digest& out);

    // Format 32 raw digest bytes as "sha256-<unpadded standard base64>".
    static std::string formatPin(const Digest& digest);

    // Add a pin for \p host ("sha256-..." spelling). Malformed pins are
    // rejected (returns false) rather than stored — a silently dropped pin
    // would quietly weaken the constraint.
    bool addPin(const std::string& host, const std::string& pin);

    // Add an already-parsed digest for \p host.
    void addPinDigest(const std::string& host, const Digest& digest);

    // True when \p host carries at least one pin (and is therefore
    // constrained). Host comparison is exact after lowercasing.
    bool hasPins(const std::string& host) const;

    // True when \p spkiSha256 — one certificate's SPKI SHA-256 digest —
    // equals ANY pin stored for \p host (standard pinning OR-semantics:
    // leaf, intermediate, or root may satisfy it). Strictly false for
    // hosts without pins; callers gate enforcement on hasPins() first.
    bool matchesAny(const std::string& host, const Digest& spkiSha256) const;

    // Number of pinned hosts / total stored pins (for status logging).
    size_t hostCount() const { return pins_.size(); }
    size_t pinCount() const {
        size_t n = 0;
        for (const auto& [host, list] : pins_) {
            (void)host;
            n += list.size();
        }
        return n;
    }

private:
    static std::string normalizeHost(const std::string& host);
    static bool base64Decode(const std::string& in, std::vector<uint8_t>& out);

    std::map<std::string, std::vector<Digest>> pins_;
};

} // namespace lethe

#endif // LETHE_SECURITY_CERT_PINNER_H
