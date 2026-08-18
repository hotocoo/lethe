#ifndef LETHE_NETWORK_VPN_VPN_CONFIG_H
#define LETHE_NETWORK_VPN_VPN_CONFIG_H

// vpn_config.h — Built-in VPN configuration for Lethe

#include <string>
#include <vector>
#include "network/vpn/wireguard_cipher.h"

namespace lethe {
namespace vpn {

struct VpnConfig {
    // Server endpoint
    std::string endpointHost;   // e.g. "vpn.aletheia.os"
    int endpointPort = 51820;   // WireGuard standard port

    // Keys
    Key serverPublicKey{};      // peer (server) public key
    Key privateKey{};           // local private key (auto-generated if empty)

    // Traffic policy
    std::vector<std::string> allowedCidrs;  // e.g. {"0.0.0.0/0"} = split/full tunnel
    int mtu = 1420;             // WireGuard standard MTU
    int keepaliveSeconds = 25;  // keepalive interval

    // Privacy
    bool dnsOverVpn = true;     // route DNS through tunnel (DoH inside VPN)
    std::string vpnDnsProvider = "https://dns.aletheia.os/dns-query"; // DoH inside tunnel

    bool isValid() const {
        return !endpointHost.empty() && endpointPort > 0 &&
               serverPublicKey != Key{};
    }

    std::string endpoint() const { return endpointHost + ":" + std::to_string(endpointPort); }
};

} // namespace vpn
} // namespace lethe

#endif // LETHE_NETWORK_VPN_VPN_CONFIG_H

