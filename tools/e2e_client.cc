// e2e_client.cc — End-to-end client test for the standalone VPN server binary
//
// Connects to a running lethe-vpn-server, performs the handshake, and sends a
// data packet. Used to verify the deployment path (real server binary + real
// UDP client).

#include <chrono>
#include <iostream>
#include <string>
#include <vector>

#include "network/vpn/vpn_tunnel.h"
#include "network/vpn/vpn_config.h"
#include "network/udp_transport.h"

using namespace lethe::vpn;
using namespace lethe;

int main(int argc, char** argv) {
    std::string host = "127.0.0.1";
    int port = 15182;
    std::string serverPubHex;
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--host" && i + 1 < argc) host = argv[++i];
        else if (a == "--port" && i + 1 < argc) port = std::atoi(argv[++i]);
        else if (a == "--server-pub" && i + 1 < argc) serverPubHex = argv[++i];
    }

    if (serverPubHex.empty()) {
        std::cerr << "Missing --server-pub" << std::endl;
        return 1;
    }

    Key serverPub{};
    if (!fromHex(serverPubHex, serverPub)) {
        std::cerr << "Invalid server public key hex" << std::endl;
        return 1;
    }

    VpnConfig config;
    config.endpointHost = host;
    config.endpointPort = port;
    config.serverPublicKey = serverPub;
    config.allowedCidrs = {"0.0.0.0/0"};

    VpnTunnel client;
    if (!client.configureClient(config)) {
        std::cerr << "Failed to configure client" << std::endl;
        return 1;
    }

    UdpTransport transport;
    if (!transport.bind("127.0.0.1", 0)) {
        std::cerr << "Failed to bind transport" << std::endl;
        return 1;
    }

    // Handshake.
    HandshakeMessage initMsg;
    if (!client.createHandshakeInit(initMsg)) {
        std::cerr << "Failed to create handshake init" << std::endl;
        return 1;
    }
    std::vector<uint8_t> respData;
    int n = transport.sendAndReceive(host, port, initMsg.serialize(), respData,
                                     std::chrono::milliseconds(3000), true);
    if (n < 0) {
        std::cerr << "Handshake timed out: " << transport.lastError() << std::endl;
        return 1;
    }
    HandshakeMessage respMsg;
    if (!HandshakeMessage::deserialize(respData.data(), respData.size(), respMsg)) {
        std::cerr << "Failed to parse handshake response" << std::endl;
        return 1;
    }
    if (!client.processHandshakeResponse(respMsg)) {
        std::cerr << "Failed to process handshake response" << std::endl;
        return 1;
    }
    std::cout << "[e2e-client] Handshake complete, connected!" << std::endl;

    // Send a data packet.
    std::string message = "Hello from the e2e client!";
    std::vector<uint8_t> ciphertext;
    if (!client.encryptDataPacket(
            reinterpret_cast<const uint8_t*>(message.data()), message.size(), ciphertext)) {
        std::cerr << "Failed to encrypt data packet" << std::endl;
        return 1;
    }
    if (!transport.sendTo(host, port, ciphertext)) {
        std::cerr << "Failed to send data packet" << std::endl;
        return 1;
    }
    std::cout << "[e2e-client] Sent " << ciphertext.size() << " encrypted bytes" << std::endl;

    std::cout << "[e2e-client] SUCCESS" << std::endl;
    return 0;
}

