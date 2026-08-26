// private_network_guard.cc — IP scope classification + SSRF decisions
//
// Classification covers the special-use registries an SSRF fetch is
// actually likely to meet: RFC1918 and IPv6 ULA intranets, carrier NAT,
// link-local space (including the 169.254.169.254 metadata endpoints every
// cloud exposes), loopback, multicast, benchmarking/TEST-NET/reserved
// ranges — plus the tunneling forms that embed IPv4 inside IPv6
// (IPv4-mapped ::ffff:/96, NAT64 64:ff9b::/96, 6to4 2002::/16), which
// recurse into the IPv4 classifier so a wrapped private address can never
// pass as public.

#include "security/private_network_guard.h"

#include <algorithm>
#include <arpa/inet.h>
#include <cctype>
#include <cstring>

namespace lethe {

namespace {

std::string toLowerCopy(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string trimCopy(const std::string& s) {
    const size_t start = s.find_first_not_of(" \t\r\n[]");
    if (start == std::string::npos) return "";
    const size_t end = s.find_last_not_of(" \t\r\n[]");
    return s.substr(start, end - start + 1);
}

uint32_t beBytesToHostOrder(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           static_cast<uint32_t>(p[3]);
}

bool allZero(const uint8_t* p, size_t n) {
    for (size_t i = 0; i < n; ++i) {
        if (p[i] != 0) return false;
    }
    return true;
}

} // namespace

AddressScope classifyIpv4(uint32_t a) {
    const uint32_t first = (a >> 24) & 0xff;
    const uint32_t second = (a >> 16) & 0xff;
    const uint32_t third = (a >> 8) & 0xff;

    if (first == 0) return AddressScope::Reserved;      // "this network" 0/8
    if (first == 10) return AddressScope::Private;      // RFC1918
    if (first == 100 && second >= 64 && second <= 127) {
        return AddressScope::Shared;                    // CGNAT 100.64/10
    }
    if (first == 127) return AddressScope::Loopback;    // 127/8
    if (first == 169 && second == 254) {
        return AddressScope::LinkLocal;                 // incl. cloud metadata
    }
    if (first == 172 && second >= 16 && second <= 31) {
        return AddressScope::Private;                   // RFC1918
    }
    if (first == 192 && second == 168) return AddressScope::Private;
    if (first == 192 && second == 0 &&
        (third == 0 || third == 2)) {
        return AddressScope::Reserved;                  // IETF / TEST-NET-1
    }
    if (first == 192 && second == 88 && third == 99) {
        return AddressScope::Reserved;                  // 6to4 relay anycast
    }
    if (first == 198 && (second == 18 || second == 19)) {
        return AddressScope::Reserved;                  // benchmarking
    }
    if (first == 198 && second == 51 && third == 100) {
        return AddressScope::Reserved;                  // TEST-NET-2
    }
    if (first == 203 && second == 0 && third == 113) {
        return AddressScope::Reserved;                  // TEST-NET-3
    }
    if (first >= 224 && first <= 239) return AddressScope::Multicast;
    if (first >= 240) return AddressScope::Reserved;    // 240/4 + broadcast
    return AddressScope::Public;
}

AddressScope classifyIpv6(const uint8_t a[16]) {
    // IPv4-mapped ::ffff:0:0/96 — the classic disguise; recurse.
    if (allZero(a, 10) && a[10] == 0xff && a[11] == 0xff) {
        return classifyIpv4(beBytesToHostOrder(a + 12));
    }
    // Named special forms BEFORE the deprecated IPv4-compatible branch:
    // ::1 and :: also start with zero bytes and would otherwise be
    // swallowed by the embedded-IPv4 recursion below.
    if (allZero(a, 15) && a[15] == 1) return AddressScope::Loopback; // ::1
    if (allZero(a, 16)) return AddressScope::Unspecified;            // ::
    // Deprecated IPv4-compatible ::x.x.x.x (first 12 bytes zero) — recurse
    // so "::10.0.0.5" cannot slip past either.
    if (allZero(a, 12)) {
        return classifyIpv4(beBytesToHostOrder(a + 12));
    }
    // Well-known NAT64 prefix 64:ff9b::/96 embeds raw IPv4.
    if (a[0] == 0x00 && a[1] == 0x64 && a[2] == 0xff && a[3] == 0x9b &&
        allZero(a + 4, 8)) {
        return classifyIpv4(beBytesToHostOrder(a + 12));
    }
    // 6to4 2002::/16 embeds the routed IPv4 endpoint in bits 16..47.
    if (a[0] == 0x20 && a[1] == 0x02) {
        return classifyIpv4(beBytesToHostOrder(a + 2));
    }
    if ((a[0] & 0xfe) == 0xfc) return AddressScope::Private;   // ULA fc00::/7
    if (a[0] == 0xfe && (a[1] & 0xc0) == 0x80) {
        return AddressScope::LinkLocal;                 // fe80::/10
    }
    if (a[0] == 0xff) return AddressScope::Multicast;   // ff00::/8
    return AddressScope::Public;
}

AddressScope classifyAddress(const std::string& ipText) {
    const std::string text = trimCopy(ipText);
    in_addr v4{};
    in6_addr v6{};
    if (::inet_pton(AF_INET, text.c_str(), &v4) == 1) {
        return classifyIpv4(ntohl(v4.s_addr));
    }
    if (::inet_pton(AF_INET6, text.c_str(), &v6) == 1) {
        uint8_t bytes[16];
        std::memcpy(bytes, v6.s6_addr, sizeof(bytes));
        return classifyIpv6(bytes);
    }
    return AddressScope::Invalid;
}

const char* addressScopeName(AddressScope scope) {
    switch (scope) {
    case AddressScope::Public: return "public";
    case AddressScope::Loopback: return "loopback";
    case AddressScope::Private: return "private";
    case AddressScope::LinkLocal: return "link-local";
    case AddressScope::Shared: return "carrier-grade-NAT";
    case AddressScope::Reserved: return "reserved";
    case AddressScope::Multicast: return "multicast";
    case AddressScope::Unspecified: return "unspecified";
    case AddressScope::Invalid: break;
    }
    return "invalid";
}

std::string PrivateNetworkGuard::check(const std::string& host,
                                       const std::string& resolvedIp) const {
    if (!policy_.isolatePrivateNetworks) return "";

    const AddressScope scope = classifyAddress(resolvedIp);
    if (scope == AddressScope::Public) return "";
    if (!resolvedIp.empty() && scope == AddressScope::Invalid) {
        // Not an address at all (e.g. a bare hostname reached the guard):
        // fail closed rather than guess.
        return "Blocked: '" + resolvedIp + "' for " + host +
               " is not a valid IP address - private-network isolation "
               "refuses unclassifiable destinations";
    }

    // Explicit per-host exceptions (exact match, case-insensitive) win:
    // operators re-admit trusted intranet names deliberately.
    if (policy_.allowedHosts.count(toLowerCopy(trimCopy(host))) > 0) {
        return "";
    }

    if (scope == AddressScope::Loopback && policy_.allowLoopback) return "";

    return "Blocked: " + host + " resolves to " + resolvedIp + " (" +
           addressScopeName(scope) +
           ") - private-network isolation refuses internal destinations";
}

} // namespace lethe
