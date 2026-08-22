#ifndef LETHE_NETWORK_HTTP_CLIENT_H
#define LETHE_NETWORK_HTTP_CLIENT_H

#include <string>
#include <map>
#include <vector>
#include <chrono>
#include <memory>
#include <cstdint>
#include "network/tls_config.h"
#include "network/vpn/vpn_tunnel.h"

// Declared in network/udp_transport.h (included by the .cc).
namespace lethe {
class UdpTransport;
}

using lethe::UdpTransport;

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#endif

namespace lethe {

enum class HttpMethod { GET, POST, PUT, DELETE, HEAD, PATCH };

struct HttpRequest {
    std::string url;
    HttpMethod method = HttpMethod::GET;
    std::map<std::string, std::string> headers;
    std::string body;
    std::chrono::seconds timeout = std::chrono::seconds(30);
};

struct HttpResponse {
    int statusCode = 0;
    std::map<std::string, std::string> headers;
    std::vector<char> body;
    bool success = false;
    std::string error;
    // Final URL after redirects (may differ from the requested URL).
    std::string finalUrl;
};

class HttpClient {
public:
    HttpClient();
    ~HttpClient();

    bool initialize(const TLSConfig& tlsConfig);

    HttpResponse sendRequest(const HttpRequest& req);

    void shutdown();

    // --- Built-in VPN integration ---
    // Attach a VPN tunnel. When connected and the destination should be
    // routed through the VPN, requests are encrypted via the tunnel.
    void setVpnTunnel(std::shared_ptr<vpn::VpnTunnel> tunnel);
    vpn::VpnTunnel* vpnTunnel() const { return vpnTunnel_.get(); }
    bool isVpnActive() const;

    // --- HTTP-over-tunnel relay (one-shot, plain HTTP only) ---
    // Share the engine's VPN UDP transport and endpoint. When a tunnel is
    // CONNECTED and the resolved destination is covered by its CIDRs,
    // plain-HTTP exchanges are carried THROUGH the encrypted tunnel as
    // framed one-shot requests (the server connects TCP to the target).
    // The client never opens direct TCP to covered destinations while the
    // tunnel is up. TLS destinations are not relayed yet and fail closed
    // rather than bypass the tunnel. Pass nullptr to disable.
    void setVpnRelay(UdpTransport* udpTransport,
                     const std::string& endpointHost, int endpointPort);

    // --- Secure DNS (DNS-over-HTTPS) ---
    // Route all hostname resolution through a DoH JSON provider
    // (e.g. https://cloudflare-dns.com/dns-query). When configured,
    // plaintext system DNS is never consulted for target hosts and a DoH
    // failure blocks the request (fail closed) instead of leaking.
    // Empty string disables. IP-literal URLs skip resolution entirely.
    void setDohProvider(const std::string& url);
    bool isDohEnabled() const { return !dohProvider_.empty(); }

private:
    // --- Relay state (HTTP-over-tunnel) ---
    bool relayConfigured() const { return vpnUdp_ != nullptr && !vpnEndpointHost_.empty() && vpnEndpointPort_ > 0; }
    void resetRelayState();
    bool flushRelayRequest();
    bool fetchRelayChunk(int timeoutMs);

    UdpTransport* vpnUdp_ = nullptr;
    std::string vpnEndpointHost_;
    int vpnEndpointPort_ = 0;
    bool relayMode_ = false;
    std::string relayTargetHost_;
    int relayTargetPort_ = 0;
    std::vector<uint8_t> relayOut_;
    bool relaySent_ = false;
    std::vector<uint8_t> relayIn_;
    size_t relayInPos_ = 0;
    bool relayEof_ = false;
    uint32_t relayXid_ = 0;

    // --- Connection management ---
    bool connectToHost(const std::string& host, int port, const std::string& scheme,
                       const std::chrono::seconds timeout);
    // Raw TCP connect (non-blocking with timeout); sets socketFd_.
    bool openTcp(const std::string& target, int port);
    // TLS handshake on the current socket; SNI/cert name = tlsHostname.
    bool startTls(const std::string& tlsHostname);
    void closeConnection();

    // --- Secure DNS helpers ---
    static bool isIpLiteral(const std::string& host);
    bool refreshDohBootstrap();
    bool dohResolve(const std::string& host, std::string& outIp);
    static std::string urlEncode(const std::string& in);
    static bool looksLikeIpv4(const std::string& s);

    // --- Raw I/O on the current connection ---
    // Returns >0 bytes read, 0 on clean EOF, -1 on error, -2 on timeout.
    int rawRead(uint8_t* buf, size_t len);
    bool writeAll(const char* data, size_t len);
    bool readLine(std::string& out);

    // --- Response parsing ---
    bool readFullResponse(HttpResponse& resp);
    bool readBodyOfLength(HttpResponse& resp, size_t length);
    bool readChunkedBody(HttpResponse& resp);
    bool readBodyUntilClose(HttpResponse& resp);
    void maybeDecompressBody(HttpResponse& resp);

    // --- URL / request building ---
    void parseUrl(const std::string& url, std::string& scheme, std::string& host,
                  std::string& path, int& port);
    std::string buildHttpRequest(const HttpRequest& req, const std::string& host,
                                 const std::string& path, int port);

    TLSConfig tlsConfig_;
    bool initialized_ = false;
    std::shared_ptr<vpn::VpnTunnel> vpnTunnel_;

    // Secure DNS state.
    std::string dohProvider_;                              // empty = disabled
    std::vector<std::string> dohProviderIps_;              // bootstrap cache
    std::chrono::steady_clock::time_point dohBootstrapTime_{};
    bool dohBootstrapValid_ = false;

    // Diagnostic reason for the most recent connect failure.
    std::string lastConnectError_;

    // Current connection state (one connection at a time).
    int socketFd_ = -1;
    bool usingTls_ = false;
    std::chrono::milliseconds ioTimeout_ = std::chrono::seconds(30);
#ifdef HAVE_OPENSSL
    SSL* ssl_ = nullptr;
    SSL_CTX* sslCtx_ = nullptr;
#endif
};

} // namespace lethe

#endif // LETHE_NETWORK_HTTP_CLIENT_H

