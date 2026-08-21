// vpn_server_main.cc — Standalone reference Lethe VPN server
//
// A runnable reference implementation of the Lethe VPN server. It binds a UDP
// endpoint, performs WireGuard-style handshakes with clients, and logs
// decrypted traffic. This is the server counterpart that the built-in VPN
// client connects to in a real deployment.
//
// Usage:
//   lethe-vpn-server --host 0.0.0.0 --port 51820 --key <hex-or-file>
//
//   --host        Bind address (default 0.0.0.0)
//   --port        UDP port (default 51820)
//   --key         Server private key: a hex string, or a path to a file
//                 containing a hex string. If omitted, a new key is
//                 generated and printed (save it for clients).

#include <csignal>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <chrono>

#include "network/vpn/vpn_server.h"
#include "network/vpn/wireguard_cipher.h"

using namespace lethe::vpn;

namespace {

std::atomic<bool> g_running{true};

void onSignal(int) {
    g_running = false;
}

// Load a private key from a hex string or a file path containing hex.
bool loadPrivateKey(const std::string& arg, Key& outKey) {
    // If it looks like a hex string (64 hex chars), parse directly.
    if (arg.size() == 64) {
        bool isHex = true;
        for (char c : arg) {
            if (!std::isxdigit(static_cast<unsigned char>(c))) { isHex = false; break; }
        }
        if (isHex) {
            return fromHex(arg, outKey);
        }
    }

    // Otherwise, treat as a file path.
    std::ifstream file(arg);
    if (!file.is_open()) {
        std::cerr << "[lethe-vpn-server] Cannot open key file: " << arg << std::endl;
        return false;
    }
    std::string hex;
    char c;
    while (file.get(c)) {
        if (std::isxdigit(static_cast<unsigned char>(c))) hex += c;
    }
    if (hex.size() != KEY_BYTES * 2) {
        std::cerr << "[lethe-vpn-server] Key file must contain " << (KEY_BYTES * 2)
                  << " hex characters" << std::endl;
        return false;
    }
    return fromHex(hex, outKey);
}

} // namespace

int main(int argc, char** argv) {
    std::string host = "0.0.0.0";
    int port = 51820;
    std::string keyArg;

    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--host" && i + 1 < argc) host = argv[++i];
        else if (arg == "--port" && i + 1 < argc) port = std::atoi(argv[++i]);
        else if (arg == "--key" && i + 1 < argc) keyArg = argv[++i];
        else if (arg == "--help" || arg == "-h") {
            std::cout << "Usage: " << argv[0]
                      << " [--host H] [--port P] [--key HEX|FILE]\n";
            return 0;
        }
    }

    // Load or generate the server key.
    Key serverPriv{};
    if (!keyArg.empty()) {
        if (!loadPrivateKey(keyArg, serverPriv)) return 1;
    } else {
        if (!generatePrivateKey(serverPriv)) {
            std::cerr << "[lethe-vpn-server] Failed to generate key" << std::endl;
            return 1;
        }
        std::cout << "[lethe-vpn-server] Generated new server key (save this!):"
                  << std::endl;
        std::cout << "  private: " << toHex(serverPriv) << std::endl;
    }

    // Configure and start the server.
    VpnServer server;
    if (!server.configure(serverPriv)) {
        std::cerr << "[lethe-vpn-server] Failed to configure server" << std::endl;
        return 1;
    }
    std::cout << "[lethe-vpn-server] Server public key (for clients): "
              << toHex(server.publicKey()) << std::endl;

    if (!server.start(host, port)) {
        std::cerr << "[lethe-vpn-server] Failed to start server" << std::endl;
        return 1;
    }

    // Log decrypted client traffic.
    server.setDataCallback([](const std::string& clientKey,
                              const uint8_t* data, size_t len) {
        std::cout << "[lethe-vpn-server] << " << clientKey.substr(0, 8)
                  << " " << len << " bytes: ";
        // Print a preview (up to 64 bytes) as text if printable.
        size_t preview = std::min<size_t>(len, 64);
        for (size_t i = 0; i < preview; i++) {
            uint8_t c = data[i];
            if (c >= 32 && c < 127) std::cout << static_cast<char>(c);
            else std::cout << ".";
        }
        if (len > preview) std::cout << "...";
        std::cout << std::endl;
    });

    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);

    std::cout << "[lethe-vpn-server] Ready. Press Ctrl+C to stop." << std::endl;

    // Run the event loop until signaled.
    while (g_running.load()) {
        server.process(std::chrono::milliseconds(200));
    }

    server.stop();
    std::cout << "[lethe-vpn-server] Stopped." << std::endl;
    return 0;
}

