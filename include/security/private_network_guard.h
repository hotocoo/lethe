#ifndef LETHE_SECURITY_PRIVATE_NETWORK_GUARD_H
#define LETHE_SECURITY_PRIVATE_NETWORK_GUARD_H

#include <cstdint>
#include <set>
#include <string>

namespace lethe {

// AddressScope — where one IP address lives on the network. The classifier
// is deliberately conservative: anything that is not demonstrable public
// internet space lands in a private scope, so an SSRF-style fetch cannot
// talk itself into a "probably fine" bucket.
enum class AddressScope {
    Invalid,     // not parsable as an IP address (fail closed)
    Unspecified, // "::" or 0.0.0.0 ("this host" wildcards)
    Loopback,    // 127.0.0.0/8, ::1
    Private,     // RFC1918 (10/8, 172.16/12, 192.168/16) + IPv6 ULA fc00::/7
    LinkLocal,   // 169.254.0.0/16 (incl. 169.254.169.254 cloud metadata),
                 // fe80::/10
    Shared,      // 100.64.0.0/10 carrier-grade NAT space
    Reserved,    // this-network 0/8, IETF 192.0.0/24, TEST-NETs,
                 // benchmarking 198.18/15, 6to4 relay, 240/4 + broadcast
    Multicast,   // 224.0.0.0/4, ff00::/8
    Public,      // globally routable internet space
};

// Classify one IPv4 address given in HOST byte order.
AddressScope classifyIpv4(uint32_t addrHostOrder);

// Classify one 16-byte IPv6 address (network byte order). Embedded IPv4
// forms recurse into the IPv4 classifier so ::ffff:10.0.0.5, NAT64
// 64:ff9b::/96 and 6to4 2002::/16 wrappers can never disguise a private
// destination as public space.
AddressScope classifyIpv6(const uint8_t addr[16]);

// Parse "203.0.113.7", "::1", "[::1]", ... and classify it.
AddressScope classifyAddress(const std::string& ipText);

// Stable human-readable names for logs, error strings, and tests.
const char* addressScopeName(AddressScope scope);

// PrivateNetworkPolicy — configuration of the SSRF guard.
struct PrivateNetworkPolicy {
    // Master switch: false restores unrestricted fetching (legacy mode).
    bool isolatePrivateNetworks = true;
    // Loopback stays reachable by default: local development, tests, and
    // localhost tooling keep working under isolation. Turning this off
    // yields a fully hermetic client.
    bool allowLoopback = true;
    // Explicit per-hostname exceptions (exact match, case-insensitive) for
    // trusted intranet names that must stay fetchable.
    std::set<std::string> allowedHosts;
};

// PrivateNetworkGuard — the decision half of Lethe's SSRF isolation.
//
// Given the hostname a request is headed for and the address it actually
// RESOLVED to (DoH answer, IP literal, or canonicalized numeric spelling),
// check() returns "" when the hop may proceed or a human-readable block
// reason when the destination sits in a non-permitted private scope.
//
// The guard is pure and stateless: HttpClient consults it before opening
// any socket AND before selecting the encrypted-tunnel relay path, so a
// covered destination can neither be dialed directly nor smuggled through
// the VPN exit into the tunnel server's own private network.
class PrivateNetworkGuard {
public:
    PrivateNetworkGuard() = default;
    explicit PrivateNetworkGuard(PrivateNetworkPolicy policy)
        : policy_(std::move(policy)) {}

    void setPolicy(PrivateNetworkPolicy policy) {
        policy_ = std::move(policy);
    }
    const PrivateNetworkPolicy& policy() const { return policy_; }

    // "" => allowed; otherwise the block reason (names host, resolved
    // address, and its scope). An unparseable address fails closed.
    std::string check(const std::string& host,
                      const std::string& resolvedIp) const;

private:
    PrivateNetworkPolicy policy_;
};

} // namespace lethe

#endif // LETHE_SECURITY_PRIVATE_NETWORK_GUARD_H
