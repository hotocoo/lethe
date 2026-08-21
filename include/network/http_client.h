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

private:
    // --- Connection management ---
    bool connectToHost(const std::string& host, int port, const std::string& scheme,
                       const std::chrono::seconds timeout);
    void closeConnection();

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

