// vpn_relay.cc — One-shot HTTP relay framing over the Lethe tunnel

#include "network/vpn/vpn_relay.h"

#include <cstring>

namespace lethe {
namespace vpn {
namespace relay {

namespace {
void appendU16be(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(v & 0xFF));
}
void appendU32be(std::vector<uint8_t>& out, uint32_t v) {
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(v & 0xFF));
}
uint16_t readU16be(const uint8_t* p) {
    return static_cast<uint16_t>(
        (static_cast<uint16_t>(p[0]) << 8) | static_cast<uint16_t>(p[1]));
}
uint32_t readU32be(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}
bool hasMagic(const uint8_t* data, size_t len) {
    return len >= sizeof(kMagic) &&
           std::memcmp(data, kMagic, sizeof(kMagic)) == 0;
}
} // namespace

std::vector<uint8_t> encodeRequest(const std::string& host, uint16_t port,
                                   uint32_t xid, const uint8_t* payload,
                                   size_t len) {
    std::vector<uint8_t> out;
    out.reserve(sizeof(kMagic) + 1 + host.size() + 2 + 4 + len);
    out.insert(out.end(), kMagic, kMagic + sizeof(kMagic));
    out.push_back(static_cast<uint8_t>(host.size()));
    out.insert(out.end(), host.begin(), host.end());
    appendU16be(out, port);
    appendU32be(out, xid);
    if (len > 0 && payload) {
        out.insert(out.end(), payload, payload + len);
    }
    return out;
}

bool parseRequest(const uint8_t* data, size_t len, Request& out) {
    if (!hasMagic(data, len)) return false;
    size_t off = sizeof(kMagic);
    const uint8_t hostLen = data[off++];
    if (hostLen == 0 || hostLen > kMaxHostLen ||
        off + hostLen + 2 + 4 > len) {
        return false;
    }
    out.host.assign(reinterpret_cast<const char*>(data) + off, hostLen);
    off += hostLen;
    out.port = readU16be(data + off);
    off += 2;
    if (out.port == 0) return false;
    out.xid = readU32be(data + off);
    off += 4;
    out.payload.assign(data + off, data + len);
    return true;
}

bool parseRequest(const std::vector<uint8_t>& data, Request& out) {
    return parseRequest(data.data(), data.size(), out);
}

std::vector<uint8_t> encodeChunk(const uint8_t* chunk, size_t len, bool end,
                                 uint32_t xid) {
    std::vector<uint8_t> out;
    out.reserve(sizeof(kMagic) + 1 + 4 + len);
    out.insert(out.end(), kMagic, kMagic + sizeof(kMagic));
    out.push_back(end ? kFlagEnd : 0);
    appendU32be(out, xid);
    if (len > 0 && chunk) {
        out.insert(out.end(), chunk, chunk + len);
    }
    return out;
}

std::vector<uint8_t> encodeChunk(const std::vector<uint8_t>& chunk, bool end,
                                 uint32_t xid) {
    return encodeChunk(chunk.data(), chunk.size(), end, xid);
}

bool parseChunk(const uint8_t* data, size_t len, uint8_t& flags,
                uint32_t& xid, std::vector<uint8_t>& body) {
    if (!hasMagic(data, len)) return false;
    size_t off = sizeof(kMagic);
    flags = data[off++];
    if ((flags & ~kFlagEnd) != 0) return false; // unknown flags: reject
    if (off + 4 > len) return false;
    xid = readU32be(data + off);
    off += 4;
    body.assign(data + off, data + len);
    return true;
}

bool parseChunk(const std::vector<uint8_t>& data, uint8_t& flags,
                uint32_t& xid, std::vector<uint8_t>& body) {
    return parseChunk(data.data(), data.size(), flags, xid, body);
}

} // namespace relay
} // namespace vpn
} // namespace lethe
