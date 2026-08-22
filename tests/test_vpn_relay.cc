// test_vpn_relay.cc - Streaming relay framing + HTTP streams over real UDP
//
// Covers:
//   - frame encode/parse round trips and malformed rejection
//   - full streaming exchanges over REAL loopback UDP: client tunnel ->
//     reference server -> plain TCP origin -> encrypted frames back,
//     including clean END semantics and per-exchange isolation

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

// A TCP origin that answers every connection with the same response and
// closes; counts connections.
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
LETHE_TEST_CASE(RelayFrame_OpenDataEndRoundTrip) {
    auto open = relay::encodeOpen(42, "10.1.2.3", 8080);
    relay::FrameKind kind;
    relay::OpenFrame o;
    relay::DataFrame d;
    relay::IdFrame id;
    CHECK_TRUE(relay::parseFrame(open, kind, o, d, id));
    CHECK_TRUE(kind == relay::FrameKind::Open);
    CHECK_EQ(o.xid, 42u);
    CHECK_EQ(o.host, std::string("10.1.2.3"));
    CHECK_EQ(o.port, 8080);

    const std::vector<uint8_t> bytes{'h', 'e', 'l', 'l', 'o'};
    auto data = relay::encodeData(7, bytes);
    CHECK_TRUE(relay::parseFrame(data, kind, o, d, id));
    CHECK_TRUE(kind == relay::FrameKind::Data);
    CHECK_EQ(d.xid, 7u);
    CHECK_TRUE(d.payload == bytes);

    auto end = relay::encodeEnd(9);
    CHECK_TRUE(relay::parseFrame(end, kind, o, d, id));
    CHECK_TRUE(kind == relay::FrameKind::End);
    CHECK_EQ(id.xid, 9u);

    auto ok = relay::encodeStatus(relay::FrameKind::Ok, 11);
    CHECK_TRUE(relay::parseFrame(ok, kind, o, d, id));
    CHECK_TRUE(kind == relay::FrameKind::Ok);
    auto err = relay::encodeStatus(relay::FrameKind::Err, 12);
    CHECK_TRUE(relay::parseFrame(err, kind, o, d, id));
    CHECK_TRUE(kind == relay::FrameKind::Err);
}

LETHE_TEST_CASE(RelayFrame_MalformedRejected) {
    relay::FrameKind kind;
    relay::OpenFrame o;
    relay::DataFrame d;
    relay::IdFrame id;

    CHECK_FALSE(relay::parseFrame({}, kind, o, d, id));
    CHECK_FALSE(relay::parseFrame({'X', 'Y'}, kind, o, d, id));
    CHECK_FALSE(relay::parseFrame({'L', 'T', 'H', 'R', 99}, kind, o, d, id));

    // Open with zero port or empty host rejected.
    auto badPort = relay::encodeOpen(1, "h", 0);
    CHECK_FALSE(relay::parseFrame(badPort, kind, o, d, id));
    // Unknown kind byte.
    auto badKind = std::vector<uint8_t>({'L', 'T', 'H', 'R', 77, 0, 0, 0, 1});
    CHECK_FALSE(relay::parseFrame(badKind, kind, o, d, id));
}
namespace {

// Shared fixture: server + handshaked client transport + helpers to drive
// v3 stream frames.
struct RelayFixture {
    VpnServer server;
    VpnTunnel client;
    UdpTransport clientTransport;
    int serverPort = 0;
    uint32_t nextXid = 100;
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

        // The event-loop pump MUST run while the handshake happens.
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
        return client.isConnected() &&
               waitFor([&]() { return server.clientCount() == 1; }, 2000);
    }

    ~RelayFixture() {
        running = false;
        if (pump.joinable()) pump.join();
    }

    bool sendEncrypted(const std::vector<uint8_t>& frame) {
        std::vector<uint8_t> ct;
        if (!client.encryptDataPacket(frame.data(), frame.size(), ct)) {
            return false;
        }
        return clientTransport.sendTo("127.0.0.1", serverPort, ct);
    }

    // Drive one full HTTP exchange: OPEN -> OK -> DATA(request) ->
    // END(request) -> collect DATA until END. Returns collected bytes.
    std::vector<uint8_t> httpExchange(const std::string& host, int port,
                                      const std::string& httpRequest,
                                      bool& okSeen, bool& endSeen) {
        okSeen = false;
        endSeen = false;
        const uint32_t xid = ++nextXid;
        if (!sendEncrypted(relay::encodeOpen(xid, host,
                                             static_cast<uint16_t>(port)))) {
            return {};
        }
        if (!sendEncrypted(relay::encodeData(
                xid, reinterpret_cast<const uint8_t*>(httpRequest.data()),
                httpRequest.size()))) {
            return {};
        }
        if (!sendEncrypted(relay::encodeEnd(xid))) return {};

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
            if (!client.decryptDataPacket(datagram.data(), datagram.size(),
                                          pt)) {
                continue;
            }
            relay::FrameKind kind;
            relay::OpenFrame o;
            relay::DataFrame d;
            relay::IdFrame id;
            if (!relay::parseFrame(pt, kind, o, d, id)) continue;
            if (id.xid != xid) continue; // stale exchange
            if (kind == relay::FrameKind::Ok) {
                okSeen = true;
                continue;
            }
            if (kind == relay::FrameKind::Err) break; // refused
            if (kind == relay::FrameKind::Data) {
                collected.insert(collected.end(), d.payload.begin(),
                                 d.payload.end());
                continue;
            }
            if (kind == relay::FrameKind::End) {
                endSeen = true;
                break;
            }
        }
        return collected;
    }
};

} // namespace

LETHE_TEST_CASE(VpnServer_Relay_HttpStreamOverRealUdp) {
    TinyOrigin origin;
    const std::string resp =
        "HTTP/1.0 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n"
        "\r\nhello";
    CHECK_TRUE(origin.start(resp));

    RelayFixture fx;
    CHECK_TRUE(fx.setup(/*relayEnabled=*/true));

    const std::string httpReq =
        "GET / HTTP/1.1\r\nHost: origin.test\r\n\r\n";
    bool okSeen = false;
    bool endSeen = false;
    const std::vector<uint8_t> out =
        fx.httpExchange("127.0.0.1", origin.port(), httpReq, okSeen, endSeen);

    CHECK_TRUE(okSeen);
    CHECK_TRUE(endSeen);
    CHECK_EQ(fx.server.relayedRequests(), 1u);
    CHECK_EQ(origin.hits(), 1);
    const std::string text(out.begin(), out.end());
    CHECK_TRUE(text.find("200 OK") != std::string::npos);
    CHECK_TRUE(text.find("hello") != std::string::npos);

    // A second full exchange works on the same session.
    bool ok2 = false;
    bool end2 = false;
    const std::vector<uint8_t> out2 =
        fx.httpExchange("127.0.0.1", origin.port(), httpReq, ok2, end2);
    CHECK_TRUE(ok2 && end2);
    CHECK_EQ(out2.size(), out.size());
    CHECK_EQ(fx.server.relayedRequests(), 2u);
}

LETHE_TEST_CASE(VpnServer_Relay_UnreachableTarget_ErrFrame) {
    RelayFixture fx;
    CHECK_TRUE(fx.setup(/*relayEnabled=*/true));

    const uint32_t xid = ++fx.nextXid;
    CHECK_TRUE(fx.sendEncrypted(relay::encodeOpen(xid, "127.0.0.1", 9)));

    // Expect the verdict frame for our xid: ERR (never OK).
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::seconds(5);
    bool errSeen = false;
    while (std::chrono::steady_clock::now() < deadline && !errSeen) {
        std::vector<uint8_t> datagram;
        std::string fh;
        int fp = 0;
        const int n = fx.clientTransport.recvFrom(
            datagram, std::chrono::milliseconds(500), fh, fp);
        if (n <= 0) continue;
        std::vector<uint8_t> pt;
        if (!fx.client.decryptDataPacket(datagram.data(), datagram.size(),
                                         pt)) {
            continue;
        }
        relay::FrameKind kind;
        relay::OpenFrame o;
        relay::DataFrame d;
        relay::IdFrame id;
        if (!relay::parseFrame(pt, kind, o, d, id)) continue;
        if (id.xid != xid) continue;
        CHECK_FALSE(kind == relay::FrameKind::Ok); // never OK for a dead target
        if (kind == relay::FrameKind::Err) errSeen = true;
    }
    CHECK_TRUE(errSeen);
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

    const std::string magicPayload(reinterpret_cast<const char*>(relay::kMagic),
                                   sizeof(relay::kMagic));
    auto frame = relay::encodeData(777,
                                   reinterpret_cast<const uint8_t*>(
                                       magicPayload.data()),
                                   magicPayload.size());
    CHECK_TRUE(fx.sendEncrypted(frame));

    CHECK_TRUE(waitFor([&]() { return callbackHit.load(); }, 2000));
    // The payload reached the callback verbatim: no relay interception.
    CHECK_TRUE(seen == frame);
}