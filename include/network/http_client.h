#ifndef LETHE_NETWORK_HTTP_CLIENT_H
#define LETHE_NETWORK_HTTP_CLIENT_H

#include <string>
#include <map>
#include <vector>
#include <chrono>
#include <memory>
#include "network/tls_config.h"
#include "network/vpn/vpn_tunnel.h"

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
    bool performTLSHandshake(const std::string& host, int port);
    std::vector<char> readResponseBody();
    void parseUrl(const std::string& url, std::string& scheme, std::string& host, std::string& path, int& port);
    std::string buildHttpRequest(const HttpRequest& req, const std::string& host, const std::string& path, int port);
    
    TLSConfig tlsConfig_;
    bool initialized_ = false;
    std::shared_ptr<vpn::VpnTunnel> vpnTunnel_;
};

} // namespace lethe

#endif // LETHE_NETWORK_HTTP_CLIENT_H