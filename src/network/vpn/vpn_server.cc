// vpn_server.cc — Reference implementation of a Lethe VPN server

#include "network/vpn/vpn_server.h"

#include <cstring>
#include <iostream>

namespace lethe {
namespace vpn {

VpnServer::VpnServer() = default;

VpnServer::~VpnServer() {
    stop();
}

bool VpnServer::configure(const Key& serverPrivateKey) {
    if (serverPrivateKey == Key{}) return false;
    if (!derivePublicKey(serverPrivateKey, serverPublicKey_)) return false;
    serverPrivateKey_ = serverPrivateKey;
    configured_ = true;
    std::cout << "[lethe-vpn-server] Configured (public key: "
              << toHex(serverPublicKey_) << ")" << std::endl;
    return true;
}

bool VpnServer::start(const std::string& host, int port) {
    if (!configured_) {
        std::cerr << "[lethe-vpn-server] Not configured" << std::endl;
        return false;
    }

    transport_ = std::make_unique<UdpTransport>();
    if (!transport_->bind(host, port)) {
        std::cerr << "[lethe-vpn-server] Bind failed: " << transport_->lastError()
                  << std::endl;
        transport_.reset();
        return false;
    }

    running_ = true;
    std::cout << "[lethe-vpn-server] Listening on " << host << ":" << transport_->localPort()
              << std::endl;
    return true;
}

void VpnServer::stop() {
    running_ = false;
    if (transport_) {
        transport_->close();
        transport_.reset();
    }
    std::lock_guard<std::mutex> lock(mutex_);
    clients_.clear();
}

int VpnServer::process(std::chrono::milliseconds timeout) {
    if (!transport_ || !running_) return 0;

    int processed = 0;
    std::string fromHost;
    int fromPort = 0;
    std::vector<uint8_t> buf;
    int n = transport_->recvFrom(buf, timeout, fromHost, fromPort);
    if (n < 0) {
        return 0; // timeout or error
    }
    handleDatagram(buf.data(), static_cast<size_t>(n), fromHost, fromPort);
    processed++;
    return processed;
}

void VpnServer::run() {
    while (running_) {
        // Process with a short timeout so we can check running_ frequently.
        process(std::chrono::milliseconds(200));
    }
}

bool VpnServer::sendToClient(const std::string& clientKey,
                             const uint8_t* data, size_t len) {
    if (!transport_ || !running_) return false;

    std::vector<uint8_t> ciphertext;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = clients_.find(clientKey);
        if (it == clients_.end()) return false;
        ClientSession& session = it->second;
        if (!session.connected || !session.tunnel) return false;
        if (!session.tunnel->encryptDataPacket(data, len, ciphertext)) {
            return false;
        }
    }

    // Send outside the lock (encryption already done).
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = clients_.find(clientKey);
    if (it == clients_.end()) return false;
    return transport_->sendTo(it->second.host, it->second.port, ciphertext);
}

bool VpnServer::sendToClient(const std::string& clientKey,
                             const std::vector<uint8_t>& data) {
    return sendToClient(clientKey, data.data(), data.size());
}

size_t VpnServer::clientCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    size_t count = 0;
    for (const auto& [key, session] : clients_) {
        if (session.connected) count++;
    }
    return count;
}

std::vector<std::string> VpnServer::connectedClients() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> keys;
    for (const auto& [key, session] : clients_) {
        if (session.connected) keys.push_back(key);
    }
    return keys;
}

void VpnServer::setDataCallback(DataCallback cb) {
    dataCallback_ = std::move(cb);
}

int VpnServer::port() const {
    return transport_ ? transport_->localPort() : 0;
}

std::string VpnServer::host() const {
    return "0.0.0.0"; // bound address host (informational)
}

void VpnServer::handleDatagram(const uint8_t* data, size_t len,
                               const std::string& fromHost, int fromPort) {
    HandshakeMessage msg;
    bool isHandshake = HandshakeMessage::deserialize(data, len, msg);

    if (isHandshake && msg.type == HandshakeType::Init) {
        handleHandshakeInit(msg, fromHost, fromPort);
        return;
    }

    // Data packet: find the session by source address.
    ClientSession* session = findSessionByAddress(fromHost, fromPort);
    if (!session || !session->connected || !session->tunnel) {
        std::cerr << "[lethe-vpn-server] Data packet from unknown client "
                  << fromHost << ":" << fromPort << std::endl;
        return;
    }

    std::vector<uint8_t> plaintext;
    if (!session->tunnel->decryptDataPacket(data, len, plaintext)) {
        std::cerr << "[lethe-vpn-server] Failed to decrypt packet from "
                  << session->keyHex << std::endl;
        return;
    }

    if (dataCallback_) {
        dataCallback_(session->keyHex, plaintext.data(), plaintext.size());
    }
}

void VpnServer::handleHandshakeInit(const HandshakeMessage& msg,
                                    const std::string& fromHost, int fromPort) {
    std::string keyHex = toHex(msg.index);

    // If this address already has a session, it's a re-handshake; replace it.
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ClientSession* existing = findSessionByAddress(fromHost, fromPort);
        if (existing) {
            clients_.erase(existing->keyHex);
        }
    }

    // Create a new server-role tunnel for this client.
    auto tunnel = std::make_unique<VpnTunnel>();
    if (!tunnel->configureServer(serverPrivateKey_)) {
        std::cerr << "[lethe-vpn-server] Failed to configure client tunnel" << std::endl;
        return;
    }

    HandshakeMessage response;
    if (!tunnel->processHandshakeInit(msg, response)) {
        std::cerr << "[lethe-vpn-server] Handshake rejected from " << fromHost
                  << ":" << fromPort << std::endl;
        return;
    }

    // Store the session.
    {
        std::lock_guard<std::mutex> lock(mutex_);
        ClientSession session;
        session.tunnel = std::move(tunnel);
        session.host = fromHost;
        session.port = fromPort;
        session.keyHex = keyHex;
        session.connected = true;
        clients_[keyHex] = std::move(session);
    }

    // Send the response back to the client.
    std::vector<uint8_t> respData = response.serialize();
    if (transport_) {
        transport_->sendTo(fromHost, fromPort, respData);
    }

    std::cout << "[lethe-vpn-server] Client connected: " << keyHex
              << " (" << fromHost << ":" << fromPort << ")" << std::endl;
}

VpnServer::ClientSession* VpnServer::findSessionByAddress(const std::string& host, int port) {
    for (auto& [key, session] : clients_) {
        if (session.host == host && session.port == port) {
            return &session;
        }
    }
    return nullptr;
}

} // namespace vpn
} // namespace lethe

