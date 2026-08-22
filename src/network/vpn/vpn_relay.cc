// vpn_relay.cc - Streaming TCP relay framing over the Lethe tunnel

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

std::vector<uint8_t> encodeOpen(uint32_t xid, const std::string& host,
                                uint16_t port) {
    std::vector<uint8_t> out;
    out.reserve(sizeof(kMagic) + 5 + host.size() + 2);
    out.insert(out.end(), kMagic, kMagic + sizeof(kMagic));
    out.push_back(static_cast<uint8_t>(FrameKind::Open));
    appendU32be(out, xid);
    out.push_back(static_cast<uint8_t>(host.size()));
    out.insert(out.end(), host.begin(), host.end());
    appendU16be(out, port);
    return out;
}

std::vector<uint8_t> encodeData(uint32_t xid, const uint8_t* payload,
                                size_t len) {
    std::vector<uint8_t> out;
    out.reserve(sizeof(kMagic) + 5 + len);
    out.insert(out.end(), kMagic, kMagic + sizeof(kMagic));
    out.push_back(static_cast<uint8_t>(FrameKind::Data));
    appendU32be(out, xid);
    if (len > 0 && payload) {
        out.insert(out.end(), payload, payload + len);
    }
    return out;
}

std::vector<uint8_t> encodeData(uint32_t xid, const std::vector<uint8_t>& d) {
    return encodeData(xid, d.data(), d.size());
}

std::vector<uint8_t> encodeEnd(uint32_t xid) {
    std::vector<uint8_t> out;
    out.reserve(sizeof(kMagic) + 5);
    out.insert(out.end(), kMagic, kMagic + sizeof(kMagic));
    out.push_back(static_cast<uint8_t>(FrameKind::End));
    appendU32be(out, xid);
    return out;
}

std::vector<uint8_t> encodeStatus(FrameKind kind, uint32_t xid) {
    std::vector<uint8_t> out;
    out.reserve(sizeof(kMagic) + 5);
    out.insert(out.end(), kMagic, kMagic + sizeof(kMagic));
    out.push_back(static_cast<uint8_t>(kind));
    appendU32be(out, xid);
    return out;
}

bool parseFrame(const uint8_t* data, size_t len, FrameKind& kind,
                OpenFrame& open, DataFrame& dataFrame, IdFrame& id) {
    if (!hasMagic(data, len)) return false;
    size_t off = sizeof(kMagic);
    const auto k = static_cast<FrameKind>(data[off++]);
    if (off + 4 > len) return false;
    const uint32_t xid = readU32be(data + off);
    off += 4;

    id.xid = xid; // every frame carries its exchange id

    switch (k) {
        case FrameKind::Open: {
            if (off >= len) return false;
            const uint8_t hostLen = data[off++];
            if (hostLen == 0 || hostLen > kMaxHostLen ||
                off + hostLen + 2 > len) {
                return false;
            }
            open.xid = xid;
            open.host.assign(reinterpret_cast<const char*>(data) + off,
                             hostLen);
            off += hostLen;
            open.port = readU16be(data + off);
            if (open.port == 0) return false;
            kind = k;
            return true;
        }
        case FrameKind::Data: {
            dataFrame.xid = xid;
            dataFrame.payload.assign(data + off, data + len);
            kind = k;
            return true;
        }
        case FrameKind::End:
        case FrameKind::Ok:
        case FrameKind::Err: {
            id.xid = xid;
            kind = k;
            return true;
        }
        default:
            return false; // unknown frame kind
    }
}

bool parseFrame(const std::vector<uint8_t>& bytes, FrameKind& kind,
                OpenFrame& open, DataFrame& dataFrame, IdFrame& id) {
    return parseFrame(bytes.data(), bytes.size(), kind, open, dataFrame, id);
}

} // namespace relay
} // namespace vpn
} // namespace lethe
