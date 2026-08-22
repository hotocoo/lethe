#ifndef LETHE_NETWORK_VPN_VPN_RELAY_H
#define LETHE_NETWORK_VPN_VPN_RELAY_H

// vpn_relay.h - Streaming TCP relay framing over the Lethe tunnel.
//
// A relay stream carries bidirectional bytes between the client and a TCP
// destination the server connects on its behalf (SOCKS-style), multiplexed
// by exchange id:
//
//   OPEN : MAGIC u8 kind=1 u32be xid u8 hostLen host... u16be port
//          client -> server: connect to host:port for exchange xid
//   DATA : MAGIC u8 kind=2 u32be xid payload...
//          both directions: stream bytes for xid
//   END  : MAGIC u8 kind=3 u32be xid
//          both directions: no more data / close the stream
//   OK   : MAGIC u8 kind=4 u32be xid
//          server -> client: origin connected
//   ERR  : MAGIC u8 kind=5 u32be xid
//          server -> client: could not connect (stream is dead)
//
// The host field normally carries the RESOLVED destination IP (the client
// resolved it via DoH before entering the tunnel), so the server never
// needs DNS and no name ever leaves the machine in plaintext.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace lethe {
namespace vpn {
namespace relay {

inline constexpr uint8_t kMagic[4] = {0x4C, 0x54, 0x48, 0x52}; // "LTHR"

enum class FrameKind : uint8_t {
    Open = 1,
    Data = 2,
    End = 3,
    Ok = 4,
    Err = 5,
};

constexpr size_t kMaxHostLen = 255;
constexpr size_t kMaxPayloadLen = 1200; // stays under the 1420-byte MTU

// --- Encoding ---------------------------------------------------------------

std::vector<uint8_t> encodeOpen(uint32_t xid, const std::string& host,
                                uint16_t port);
std::vector<uint8_t> encodeData(uint32_t xid, const uint8_t* payload,
                                size_t len);
std::vector<uint8_t> encodeData(uint32_t xid, const std::vector<uint8_t>& d);
std::vector<uint8_t> encodeEnd(uint32_t xid);
std::vector<uint8_t> encodeStatus(FrameKind kind, uint32_t xid); // Ok / Err

// --- Parsing ------------------------------------------------------------------

struct OpenFrame {
    uint32_t xid = 0;
    std::string host;
    uint16_t port = 0;
};

struct DataFrame {
    uint32_t xid = 0;
    std::vector<uint8_t> payload;
};

struct IdFrame {
    uint32_t xid = 0;
};

// Parse any frame. On success, `kind` says which out-struct is filled
// (Open / Data / Id for End-Ok-Err). False on malformed input.
bool parseFrame(const uint8_t* bytes, size_t len, FrameKind& kind,
                OpenFrame& open, DataFrame& data, IdFrame& id);
bool parseFrame(const std::vector<uint8_t>& bytes, FrameKind& kind,
                OpenFrame& open, DataFrame& data, IdFrame& id);

} // namespace relay
} // namespace vpn
} // namespace lethe

#endif // LETHE_NETWORK_VPN_VPN_RELAY_H
