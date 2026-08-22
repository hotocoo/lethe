// test_vpn_relay.cc — Relay framing + one-shot HTTP relay over real UDP
//
// Covers:
//   - request/chunk frame encode+parse round trips and malformed rejection
//   - a full relay exchange over REAL loopback UDP: client tunnel ->
//     reference server -> plain TCP origin -> encrypted chunks back

#include "test_framework.h"
#include "network/vpn/vpn_relay.h"
#include "network/vpn/vpn_server.h"
#include "network/vpn/vpn_tunnel.h"
#include "network/vpn/vpn_config.h"
#include "network/udp_transport.h"

#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <cstring>
#include <functional>
#include <netinet/in.h>
#include <string>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

using namespace lethe;
using namespace lethe::vpn;

namespace {

bool waitFor(const std::function<bool()>& pred, int timeoutMs) {
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline) {
        if (pred()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    return pred();
}

// A single-connection TCP origin: answers every connection with the same
// response and closes.
class TinyOrigin {
public:
    bool start(std::string response) {
        response_ = std::move(response);
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ < 0) return false;
        int reuse = 1;
        ::setsockopt(fd_, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = htons(0);
        if (::bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0 ||
            ::listen(fd_, 8) < 0) {
            return false;
        }
        socklen_t len = sizeof(addr);
        ::getsockname(fd_, reinterpret_cast<sockaddr*>(&addr), &len);
        port_ = ntohs(addr.sin_port);
        running_ = true;
        thread_ = std::thread([this]() { loop(); });
        return true;
    }
    int port() const { return port_; }
    int hits() const { return hits_.load(); }
    ~TinyOrigin() {
        running_ = false;
        if (fd_ >= 0) { ::shutdown(fd_, SHUT_RDWR); ::close(fd_); }
        if (thread_.joinable()) thread_.join();
    }

private:
    void loop() {
        while (running_.load()) {
            int c = ::accept(fd_, nullptr, nullptr);
            if (c < 0) continue;
            hits_.fetch_add(1);
            char buf[4096];
            ssize_t n;
            while ((n = ::recv(c, buf, sizeof(buf), 0)) > 0) {
                if (std::strstr(buf, "\r\n\r\n")) break;
            }
            ::send(c, response_.data(), response_.size(), 0);
            ::shutdown(c, SHUT_WR);
            ::close(c);
        }
    }

    int fd_ = -1;
    int port_ = 0;
    std::string response_;
    std::atomic<int> hits_{0};
    std::atomic<bool> running_{false};
    std::thread thread_;
};

} // namespace

LETHE_TEST_CASE(RelayFrame_RequestRoundTrip) {
    const std::string payload = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    auto frame = relay::encodeRequest("10.1.2.3", 8080, 42,
                                      reinterpret_cast<const uint8_t*>(
                                          payload.data()),
                                      payload.size());
    relay::Request parsed;
    CHECK_TRUE(relay::parseRequest(frame, parsed));
    CHECK_EQ(parsed.host, std::string("10.1.2.3"));
    CHECK_EQ(parsed.port, 8080);
    CHECK_EQ(parsed.xid, 42u);
    CHECK_TRUE(std::string(parsed.payload.begin(), parsed.payload.end()) ==
               payload);

    // Empty payload is valid.
    auto empty = relay::encodeRequest("127.0.0.1", 80, 7, nullptr, 0);
    relay::Request p2;
    CHECK_TRUE(relay::parseRequest(empty, p2));
    CHECK_EQ(p2.port, 80);
    CHECK_EQ(p2.xid, 7u);
    CHECK_TRUE(p2.payload.empty());
}

LETHE_TEST_CASE(RelayFrame_ChunkRoundTrip) {
    auto mid = relay::encodeChunk(
        reinterpret_cast<const uint8_t*>("hello"), 5, false, 99);
    uint8_t flags = 0;
    uint32_t xid = 0;
    std::vector<uint8_t> body;
    CHECK_TRUE(relay::parseChunk(mid, flags, xid, body));
    CHECK_EQ(static_cast<int>(flags), 0);
    CHECK_EQ(xid, 99u);
    const std::vector<uint8_t> expected{'h', 'e', 'l', 'l', 'o'};
    CHECK_TRUE(body == expected);

    auto last = relay::encodeChunk(nullptr, 0, true, 99);
    CHECK_TRUE(relay::parseChunk(last, flags, xid, body));
    CHECK_TRUE(flags & relay::kFlagEnd);
    CHECK_TRUE(body.empty());
}

LETHE_TEST_CASE(RelayFrame_MalformedRejected) {
    relay::Request req;
    // Truncated / bad magic / zero port all rejected.
    CHECK_FALSE(relay::parseRequest({}, req));
    CHECK_FALSE(relay::parseRequest({0x00, 0x01, 0x02}, req));

    auto badPort = relay::encodeRequest("h", 0, 1, nullptr, 0);
    CHECK_FALSE(relay::parseRequest(badPort, req));

    uint8_t flags = 0;
    uint32_t xid = 0;
    std::vector<uint8_t> body;
    CHECK_FALSE(relay::parseChunk({'L', 'T', 'H', 'R', 0xFE}, flags, xid,
                                  body));
}

namespace {

// Shared fixture: server + handshaked client transport.
struct RelayFixture {
    VpnServer server;
    VpnTunnel client;
    UdpTransport clientTransport;
    int serverPort = 0;
    std::atomic<bool> running{false};
    std::thread pump;

    bool setup(bool relayEnabled) {
        Key priv{};
        if (!generatePrivateKey(priv)) return false;
        if (!server.configure(priv)) return false;
        server.setRelayEnabled(relayEnabled);
        if (!server.start("127.0.0.1", 0)) return false;
        serverPort = server.port();

        VpnConfig cfg;
        cfg.endpointHost = "127.0.0.1";
        cfg.endpointPort = serverPort;
        cfg.serverPublicKey = server.publicKey();
        cfg.allowedCidrs = {"0.0.0.0/0"};
        if (!client.configureClient(cfg)) return false;
        if (!clientTransport.bind("127.0.0.1", 0)) return false;

        // The event-loop pump MUST run while the handshake happens:
        // otherwise nobody processes the init datagram.
        running = true;
        pump = std::thread([this]() {
            while (running.load()) {
                server.process(std::chrono::milliseconds(20));
            }
        });

        HandshakeMessage init;
        if (!client.createHandshakeInit(init)) return false;
        auto initData = init.serialize();
        std::vector<uint8_t> respData;
        const int n = clientTransport.sendAndReceive(
            "127.0.0.1", serverPort, initData, respData,
            std::chrono::milliseconds(3000), /*onlyFromSender=*/true);
        if (n <= 0) return false;
        HandshakeMessage resp;
        if (!HandshakeMessage::deserialize(respData.data(),
                                           respData.size(), resp)) {
            return false;
        }
        if (!client.processHandshakeResponse(resp)) return false;
        if (!client.isConnected()) return false;

        return waitFor([&]() { return server.clientCount() == 1; }, 2000);
    }

    ~RelayFixture() {
        running = false;
        if (pump.joinable()) pump.join();
    }

    // Send a framed request and collect framed chunks until END.
    std::vector<uint8_t> exchange(const std::string& host, int port,
                                  const std::string& httpRequest,
                                  bool& endSeen) {
        endSeen = false;
        const uint32_t xid = 1234;
        auto frame = relay::encodeRequest(
            host, static_cast<uint16_t>(port), xid,
            reinterpret_cast<const uint8_t*>(httpRequest.data()),
            httpRequest.size());
        std::vector<uint8_t> ct;
        if (!client.encryptDataPacket(frame.data(), frame.size(), ct)) {
            return {};
        }
        if (!clientTransport.sendTo("127.0.0.1", serverPort, ct)) return {};

        std::vector<uint8_t> collected;
        auto deadline = std::chrono::steady_clock::now() +
                        std::chrono::seconds(5);
        while (std::chrono::steady_clock::now() < deadline) {
            std::vector<uint8_t> datagram;
            std::string fh;
            int fp = 0;
            const int n = clientTransport.recvFrom(
                datagram, std::chrono::milliseconds(500), fh, fp);
            if (n <= 0) continue;
            std::vector<uint8_t> pt;
            if (!client.decryptDataPacket(datagram.data(),
                                          datagram.size(), pt)) {
                continue;
            }
            uint8_t flags = 0;
            uint32_t chunkXid = 0;
            std::vector<uint8_t> body;
            if (!relay::parseChunk(pt, flags, chunkXid, body)) continue;
            if (chunkXid != xid) continue; // stale/foreign exchange
            collected.insert(collected.end(), body.begin(), body.end());
            if (flags & relay::kFlagEnd) {
                endSeen = true;
                break;
            }
        }
        return collected;
    }
};

} // namespace

LETHE_TEST_CASE(VpnServer_Relay_HttpExchangeOverRealUdp) {
    TinyOrigin origin;
    const std::string resp =
        "HTTP/1.0 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n"
        "\r\nhello";
    CHECK_TRUE(origin.start(resp));

    RelayFixture fx;
    CHECK_TRUE(fx.setup(/*relayEnabled=*/true));

    const std::string httpReq =
        "GET / HTTP/1.1\r\nHost: origin.test\r\n\r\n";
    bool endSeen = false;
    const std::vector<uint8_t> out =
        fx.exchange("127.0.0.1", origin.port(), httpReq, endSeen);

    CHECK_TRUE(endSeen);
    CHECK_EQ(fx.server.relayedRequests(), 1u);
    CHECK_EQ(origin.hits(), 1);
    const std::string text(out.begin(), out.end());
    CHECK_TRUE(text.find("200 OK") != std::string::npos);
    CHECK_TRUE(text.find("hello") != std::string::npos);
}

LETHE_TEST_CASE(VpnServer_Relay_UnreachableTarget_EndsWithEmptyChunk) {
    RelayFixture fx;
    CHECK_TRUE(fx.setup(/*relayEnabled=*/true));

    const std::string httpReq = "GET / HTTP/1.1\r\nHost: x\r\n\r\n";
    bool endSeen = false;
    // Port 9 on loopback: closed in test environments.
    const std::vector<uint8_t> out = fx.exchange("127.0.0.1", 9, httpReq,
                                                 endSeen);
    CHECK_TRUE(endSeen);   // failure still terminates the exchange
    CHECK_TRUE(out.empty());
    CHECK_EQ(fx.server.relayedRequests(), 1u);
}

LETHE_TEST_CASE(VpnServer_Relay_Disabled_PayloadGoesToCallback) {
    RelayFixture fx;
    CHECK_TRUE(fx.setup(/*relayEnabled=*/false));

    std::atomic<bool> callbackHit{false};
    std::vector<uint8_t> seen;
    fx.server.setDataCallback([&](const std::string&, const uint8_t* data,
                                  size_t len) {
        callbackHit = true;
        seen.assign(data, data + len);
    });

    const std::string magicPayload(reinterpret_cast<const char*>(
                                       relay::kMagic),
                                   sizeof(relay::kMagic));
    auto frame = relay::encodeRequest("127.0.0.1", 9, 555,
                                      reinterpret_cast<const uint8_t*>(
                                          magicPayload.data()),
                                      magicPayload.size());
    std::vector<uint8_t> ct;
    CHECK_TRUE(fx.client.encryptDataPacket(frame.data(), frame.size(), ct));
    CHECK_TRUE(fx.clientTransport.sendTo("127.0.0.1", fx.serverPort, ct));

    CHECK_TRUE(waitFor([&]() { return callbackHit.load(); }, 2000));
    // The payload reached the callback verbatim: no relay interception.
    CHECK_TRUE(seen == frame);
}
