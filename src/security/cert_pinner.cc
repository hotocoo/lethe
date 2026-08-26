#include "security/cert_pinner.h"

namespace lethe {

namespace {

// Standard base64 value table; -1 for non-alphabet bytes.
int b64Value(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

const char kAlphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

} // namespace

bool CertPinner::base64Decode(const std::string& in, std::vector<uint8_t>& out) {
    out.clear();
    // Strip '=' padding, then decode strictly in 4->3 quads ourselves so
    // both padded and unpadded spellings are accepted.
    size_t end = in.size();
    while (end > 0 && in[end - 1] == '=') --end;

    uint32_t acc = 0;
    int bits = 0;
    for (size_t i = 0; i < end; ++i) {
        const int v = b64Value(in[i]);
        if (v < 0) return false; // character outside the standard alphabet
        acc = (acc << 6) | static_cast<uint32_t>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((acc >> bits) & 0xFF));
        }
    }
    // Leftover bits (<8) must be zero padding per canonical encoding.
    if ((acc & ((1u << bits) - 1)) != 0 && bits > 0) return false;
    return true;
}

bool CertPinner::parsePin(const std::string& pin, Digest& out) {
    const std::string prefix = "sha256-";
    if (pin.size() <= prefix.size()) return false;
    // Prefix comparison is case-sensitive per HPKP wire format.
    if (pin.compare(0, prefix.size(), prefix) != 0) return false;

    std::vector<uint8_t> decoded;
    if (!base64Decode(pin.substr(prefix.size()), decoded)) return false;
    if (decoded.size() != kDigestSize) return false;

    std::copy(decoded.begin(), decoded.end(), out.begin());
    return true;
}

std::string CertPinner::formatPin(const Digest& digest) {
    std::string b64;
    b64.reserve(44);
    for (size_t i = 0; i < digest.size(); i += 3) {
        const uint32_t b0 = digest[i];
        const uint32_t b1 = (i + 1 < digest.size()) ? digest[i + 1] : 0;
        const uint32_t b2 = (i + 2 < digest.size()) ? digest[i + 2] : 0;
        const uint32_t triple = (b0 << 16) | (b1 << 8) | b2;
        b64.push_back(kAlphabet[(triple >> 18) & 0x3F]);
        b64.push_back(kAlphabet[(triple >> 12) & 0x3F]);
        b64.push_back(i + 1 < digest.size() ? kAlphabet[(triple >> 6) & 0x3F] : '=');
        b64.push_back(i + 2 < digest.size() ? kAlphabet[triple & 0x3F] : '=');
    }
    return "sha256-" + b64;
}

std::string CertPinner::normalizeHost(const std::string& host) {
    std::string out;
    out.reserve(host.size());
    for (char c : host) {
        out.push_back(
            (c >= 'A' && c <= 'Z') ? static_cast<char>(c - 'A' + 'a') : c);
    }
    return out;
}

bool CertPinner::addPin(const std::string& host, const std::string& pin) {
    // A pin bound to no host can never be enforced; reject it loudly at
    // configuration time instead of storing dead state.
    if (host.empty()) return false;
    Digest digest{};
    if (!parsePin(pin, digest)) return false;
    addPinDigest(host, digest);
    return true;
}

void CertPinner::addPinDigest(const std::string& host, const Digest& digest) {
    pins_[normalizeHost(host)].push_back(digest);
}

bool CertPinner::hasPins(const std::string& host) const {
    return pins_.find(normalizeHost(host)) != pins_.end();
}

bool CertPinner::matchesAny(const std::string& host,
                            const Digest& spkiSha256) const {
    // Strict matching: an unpinned host has NO satisfying pin. Callers
    // gate enforcement on hasPins() first.
    const auto it = pins_.find(normalizeHost(host));
    if (it == pins_.end()) return false;
    for (const Digest& pinned : it->second) {
        if (pinned == spkiSha256) return true;
    }
    return false;
}

} // namespace lethe
