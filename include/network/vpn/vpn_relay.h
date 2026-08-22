#ifndef LETHE_NETWORK_VPN_VPN_RELAY_H
#define LETHE_NETWORK_VPN_VPN_RELAY_H

// vpn_relay.h — One-shot HTTP relay framing over the Lethe tunnel.
//
// A relay request is a decrypted tunnel payload that begins with the magic
// bytes and names a TCP destination; the VPN server connects there, forwards
// the payload, and streams the origin's response back as framed chunks.
//
//   Request frame : MAGIC  u8 hostLen  host...  u16be port  u32be xid  payload...
//   Response chunk: MAGIC  u8 flags  u32be xid  chunk...
//
// Every chunk echoes the request's exchange id (xid): a client with queued
// datagrams from a previous exchange can discard them unambiguously.
//
// The host field normally carries the RESOLVED destination IP (the client
// resolved it via DoH before entering the tunnel), so the server never needs
// DNS and no name ever leaves the machine in plaintext.

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace lethe {
namespace vpn {
namespace relay {

inline constexpr uint8_t kMagic[4] = {0x4C, 0x54, 0x48, 0x52}; // "LTHR"
inline constexpr size_t kMaxHostLen = 255;
inline constexpr uint8_t kFlagEnd = 0x01;

struct Request {
    std::string host;
    uint16_t port = 0;
    uint32_t xid = 0;
    std::vector<uint8_t> payload;
};

// Encode a relay request frame.
std::vector<uint8_t> encodeRequest(const std::string& host, uint16_t port,
                                   uint32_t xid, const uint8_t* payload,
                                   size_t len);

// Parse a relay request frame; false on malformed input.
bool parseRequest(const uint8_t* data, size_t len, Request& out);
bool parseRequest(const std::vector<uint8_t>& data, Request& out);

// Encode a response chunk (end marks the final chunk of a response).
std::vector<uint8_t> encodeChunk(const uint8_t* chunk, size_t len, bool end,
                                 uint32_t xid);
std::vector<uint8_t> encodeChunk(const std::vector<uint8_t>& chunk, bool end,
                                 uint32_t xid);

// Parse a response chunk into flags + body; false on malformed input.
bool parseChunk(const uint8_t* data, size_t len, uint8_t& flags,
                uint32_t& xid, std::vector<uint8_t>& body);
bool parseChunk(const std::vector<uint8_t>& data, uint8_t& flags,
                uint32_t& xid, std::vector<uint8_t>& body);

} // namespace relay
} // namespace vpn
} // namespace lethe

#endif // LETHE_NETWORK_VPN_VPN_RELAY_H
