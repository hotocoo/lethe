#ifndef LETHE_NETWORK_POLICY_PROXY_H
#define LETHE_NETWORK_POLICY_PROXY_H

#include <atomic>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include "network/http_client.h"
#include "network/tls_config.h"

namespace lethe {

// policy_proxy.h — Local policy-enforcing HTTP/CONNECT proxy.
//
// Full-web engines (WebKitGTK on Linux, WebView2 on Windows) hand their
// ENTIRE network stack to this proxy: plain requests are forwarded through
// an HttpClient carrying Lethe's DoH-only resolution, private-network
// isolation, HSTS, certificate pinning and VPN fail-closed routing;
// CONNECT tunnels are granted only AFTER the destination passes the same
// policy, then spliced byte-for-byte (TLS stays end-to-end between the
// engine and the origin - the proxy never terminates it).
//
// Every refusal fails closed with an HTTP 403 whose body names the reason.

class PolicyProxyServer {
public:
    struct Options {
        // Prototype TLS configuration cloned into per-connection clients.
        TLSConfig tls;
        // DoH provider URL applied to forwarding clients ("" inherits
        // none, i.e. resolution stays system-level - avoid in prod).
        std::string dohProvider;
        // Shared DoH answer cache. When null the proxy creates its own so
        // every proxied connection still shares one; pass the browser's
        // cache to share with the navigation gate and reader as well.
        std::shared_ptr<SharedDohCache> dohCache;
        // Private-network policy applied verbatim.
        PrivateNetworkPolicy privateNet;
        // Shared VPN tunnel for routing decisions + covered relaying.
        vpn::VpnTunnel* vpnTunnel = nullptr;  // non-owning; engine owns it
        // VPN relay endpoint (engine UDP transport) for covered streams.
        void* udpTransport = nullptr;   // UdpTransport* (opaque here)
        std::string relayHost;
        int relayPort = 0;
        // Listen address; almost always loopback - this proxy trusts its
        // TCP peers because it enforces policy FOR them.
        std::string bindHost = "127.0.0.1";
        int bindPort = 0;               // 0 = ephemeral
        // Per-launch secret. When set, every request must carry
        // "Proxy-Authorization: Basic base64(lethe:<token>)" or it is
        // refused with 407 before any policy work or upstream I/O. This
        // closes the open-loopback-proxy hole: without it any local process
        // could ride Lethe's VPN tunnel and policy identity. Empty = off
        // (tests / engines that cannot send proxy credentials).
        std::string authToken;
    };

    // 32 random bytes as hex (OpenSSL RAND_bytes); "" if the CSPRNG fails.
    static std::string generateAuthToken();
    // The exact Proxy-Authorization header value the engine must send.
    static std::string basicCredentialFor(const std::string& token);

    PolicyProxyServer() = default;
    ~PolicyProxyServer();

    PolicyProxyServer(const PolicyProxyServer&) = delete;
    PolicyProxyServer& operator=(const PolicyProxyServer&) = delete;

    // Bind + start accepting. Returns false (with reason in lastError()) on
    // socket failure.
    bool start(const Options& options);
    // Stop accepting, close listener; live connection threads detach.
    void stop();

    int port() const { return port_; }
    const std::string& lastError() const { return lastError_; }

private:
    void acceptLoop();
    void serveConnection(int clientFd);
    HttpClient::PolicyDialConfig dialConfig() const;

    // One forwarding HttpClient per proxied request chain (cheap relative
    // to network; keeps single-connection client state thread-confined).
    std::unique_ptr<HttpClient> makeClient();

    Options opts_;
    int listenFd_ = -1;
    std::atomic<int> port_{0};
    std::atomic<bool> running_{false};
    std::thread acceptThread_;
    std::string lastError_;

    // Refuse absurd request sizes before allocating.
    static constexpr size_t kMaxHeaderBytes = 64 * 1024;
};

} // namespace lethe

#endif // LETHE_NETWORK_POLICY_PROXY_H
