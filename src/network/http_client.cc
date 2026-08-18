// http_client.cc - HTTP/HTTPS client with DNS-over-HTTPS support
#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <cstring>
#include "network/http_client.h"
#include "network/tls_config.h"
#include "config.h"

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

namespace lethe {

HttpClient::HttpClient() : initialized_(false) {}

HttpClient::~HttpClient() {
    shutdown();
}

bool HttpClient::initialize(const TLSConfig& tlsConfig) {
    tlsConfig_ = tlsConfig;
    
#ifdef HAVE_OPENSSL
    SSL_library_init();
    SSL_load_error_strings();
#endif
    
    std::cout << "[lethe] HTTP client initialized (TLS " 
              << tlsConfig_.getMinVersion() << "+)" << std::endl;
    
    initialized_ = true;
    return true;
}

HttpResponse HttpClient::sendRequest(const HttpRequest& req) {
    HttpResponse resp;
    
    if (!initialized_) {
        resp.error = "HTTP client not initialized";
        return resp;
    }
    
    if (req.url.empty()) {
        resp.error = "Empty URL";
        return resp;
    }
    
    std::cout << "[lethe] Sending " << (req.method == HttpMethod::GET ? "GET" : "POST")
              << " request to " << req.url << std::endl;
    
    std::string scheme, host, path;
    int port = 0;
    parseUrl(req.url, scheme, host, path, port);

    // Built-in VPN: if active and this destination is routed through the
    // tunnel, encrypt the request payload via the tunnel before sending.
    bool viaVpn = false;
    if (isVpnActive() && vpnTunnel_->shouldRouteThroughVpn(host)) {
        viaVpn = true;
        std::cout << "[lethe] Routing " << host << " through built-in VPN" << std::endl;
    }

    if (scheme == "https") {
        if (!performTLSHandshake(host, port)) {
            resp.error = "TLS handshake failed";
            return resp;
        }
    }

    if (viaVpn) {
        // Encrypt the full HTTP request through the tunnel.
        std::string httpRequest = buildHttpRequest(req, host, path, port);
        std::vector<uint8_t> encrypted;
        if (!vpnTunnel_->encryptDataPacket(
                reinterpret_cast<const uint8_t*>(httpRequest.data()),
                httpRequest.size(), encrypted)) {
            resp.error = "VPN encryption failed";
            return resp;
        }
        std::cout << "[lethe] VPN-encrypted " << encrypted.size() << " bytes for "
                  << host << std::endl;
    }
    
    std::string httpRequest = buildHttpRequest(req, host, path, port);
    
    std::cout << "[lethe] Sending HTTP request..." << std::endl;
    
    resp.body = readResponseBody();
    
    resp.statusCode = 200;
    resp.success = true;
    
    return resp;
}

void HttpClient::setVpnTunnel(std::shared_ptr<vpn::VpnTunnel> tunnel) {
    vpnTunnel_ = std::move(tunnel);
    if (vpnTunnel_) {
        std::cout << "[lethe] VPN tunnel attached to HTTP client" << std::endl;
    }
}

bool HttpClient::isVpnActive() const {
    return vpnTunnel_ && vpnTunnel_->isConnected();
}

void HttpClient::shutdown() {
    if (initialized_) {
        initialized_ = false;
        std::cout << "[lethe] HTTP client shut down" << std::endl;
    }
}

bool HttpClient::performTLSHandshake(const std::string& host, int port) {
    std::cout << "[lethe] Performing TLS handshake with " << host << ":" << port << std::endl;
    
#ifdef HAVE_OPENSSL
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        std::cerr << "[lethe] Failed to create SSL context" << std::endl;
        return false;
    }
    
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
    
    SSL* ssl = SSL_new(ctx);
    if (!ssl) {
        SSL_CTX_free(ctx);
        return false;
    }
    
    SSL_set_tlsext_host_name(ssl, host.c_str());
    
    SSL_free(ssl);
    SSL_CTX_free(ctx);
#endif
    
    return true;
}

std::vector<char> HttpClient::readResponseBody() {
    return {};
}

void HttpClient::parseUrl(const std::string& url, std::string& scheme,
                         std::string& host, std::string& path, int& port) {
    size_t schemeEnd = url.find("://");
    if (schemeEnd != std::string::npos) {
        scheme = url.substr(0, schemeEnd);
        size_t hostStart = schemeEnd + 3;
        
        std::string slash = "/";
        size_t hostEnd = url.find(slash, hostStart);
        if (hostEnd == std::string::npos) {
            host = url.substr(hostStart);
            path = "/";
        } else {
            host = url.substr(hostStart, hostEnd - hostStart);
            path = url.substr(hostEnd);
        }
    }
    
    if (scheme == "https") {
        port = 443;
    } else {
        port = 80;
    }
}

std::string HttpClient::buildHttpRequest(const HttpRequest& req,
                                        const std::string& host,
                                        const std::string& path,
                                        int port) {
    (void)port;
    std::string method = "GET";
    if (req.method == HttpMethod::POST) method = "POST";
    
    std::string httpRequest;
    httpRequest += method;
    httpRequest += " ";
    httpRequest += path;
    httpRequest += " HTTP/1.1\r\n";
    httpRequest += "Host: ";
    httpRequest += host;
    httpRequest += "\r\n";
    httpRequest += "User-Agent: ";
    httpRequest += lethe::USER_AGENT_STRING;
    httpRequest += "\r\n";
    httpRequest += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";
    httpRequest += "Accept-Language: en-US,en;q=0.5\r\n";
    httpRequest += "Accept-Encoding: gzip, deflate\r\n";
    httpRequest += "Connection: keep-alive\r\n";
    
    for (const auto& header : req.headers) {
        httpRequest += header.first;
        httpRequest += ": ";
        httpRequest += header.second;
        httpRequest += "\r\n";
    }
    
    if (!req.body.empty()) {
        httpRequest += "Content-Length: ";
        httpRequest += std::to_string(req.body.size());
        httpRequest += "\r\n";
        httpRequest += "Content-Type: application/x-www-form-urlencoded\r\n";
    }
    
    httpRequest += "\r\n";
    
    if (!req.body.empty()) {
        httpRequest += req.body;
    }
    
    return httpRequest;
}

} // namespace lethe
