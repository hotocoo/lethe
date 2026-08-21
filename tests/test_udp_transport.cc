// test_udp_transport.cc — Tests for the UDP network transport (loopback)

#include "test_framework.h"
#include "network/udp_transport.h"

#include <chrono>
#include <thread>

using namespace lethe;

LETHE_TEST_CASE(UdpTransport_BindAndLocalPort) {
    UdpTransport t;
    CHECK_TRUE(t.bind("127.0.0.1", 0)); // ephemeral port
    CHECK_TRUE(t.isOpen());
    CHECK_TRUE(t.localPort() > 0);
    CHECK_EQ(t.localHost(), "127.0.0.1");
    t.close();
    CHECK_FALSE(t.isOpen());
}

LETHE_TEST_CASE(UdpTransport_SendRecv_Loopback) {
    UdpTransport a, b;
    CHECK_TRUE(a.bind("127.0.0.1", 0));
    CHECK_TRUE(b.bind("127.0.0.1", 0));

    // A sends to B.
    std::string payload = "hello over udp";
    CHECK_TRUE(a.sendTo("127.0.0.1", b.localPort(),
                        reinterpret_cast<const uint8_t*>(payload.data()),
                        payload.size()));

    // B receives.
    std::vector<uint8_t> buf;
    std::string fromHost;
    int fromPort = 0;
    int n = b.recvFrom(buf, std::chrono::milliseconds(2000), fromHost, fromPort);
    CHECK_TRUE(n > 0);
    CHECK_EQ(n, static_cast<int>(payload.size()));
    CHECK_EQ(fromHost, "127.0.0.1");
    CHECK_EQ(fromPort, a.localPort());
    std::string received(buf.begin(), buf.begin() + n);
    CHECK_EQ(received, payload);
}

LETHE_TEST_CASE(UdpTransport_SendAndReceive_Echo) {
    UdpTransport client, server;
    CHECK_TRUE(client.bind("127.0.0.1", 0));
    CHECK_TRUE(server.bind("127.0.0.1", 0));

    // Server echoes in a background thread.
    std::thread echoThread([&server]() {
        std::vector<uint8_t> buf;
        std::string fromHost;
        int fromPort = 0;
        int n = server.recvFrom(buf, std::chrono::milliseconds(3000), fromHost, fromPort);
        if (n > 0) {
            server.sendTo(fromHost, fromPort, buf);
        }
    });

    // Client sends and waits for the echo.
    std::vector<uint8_t> sendBuf = {'e', 'c', 'h', 'o'};
    std::vector<uint8_t> outBuf;
    int n = client.sendAndReceive("127.0.0.1", server.localPort(), sendBuf,
                                  outBuf, std::chrono::milliseconds(3000),
                                  /*onlyFromSender=*/true);
    CHECK_TRUE(n > 0);
    CHECK_EQ(n, 4);
    CHECK_EQ(std::string(outBuf.begin(), outBuf.end()), "echo");

    echoThread.join();
}

LETHE_TEST_CASE(UdpTransport_RecvTimeout_ReturnsMinusOne) {
    UdpTransport t;
    CHECK_TRUE(t.bind("127.0.0.1", 0));

    std::vector<uint8_t> buf;
    std::string fromHost;
    int fromPort = 0;
    int n = t.recvFrom(buf, std::chrono::milliseconds(150), fromHost, fromPort);
    CHECK_EQ(n, -1);
    CHECK_TRUE(!t.lastError().empty());
}

LETHE_TEST_CASE(UdpTransport_MultipleDatagrams) {
    UdpTransport a, b;
    CHECK_TRUE(a.bind("127.0.0.1", 0));
    CHECK_TRUE(b.bind("127.0.0.1", 0));

    // Send 5 datagrams.
    for (int i = 0; i < 5; i++) {
        std::string msg = "msg" + std::to_string(i);
        CHECK_TRUE(a.sendTo("127.0.0.1", b.localPort(),
                            reinterpret_cast<const uint8_t*>(msg.data()),
                            msg.size()));
    }

    // Receive all 5.
    int total = 0;
    for (int i = 0; i < 5; i++) {
        std::vector<uint8_t> buf;
        std::string fromHost;
        int fromPort = 0;
        int n = b.recvFrom(buf, std::chrono::milliseconds(2000), fromHost, fromPort);
        CHECK_TRUE(n > 0);
        total += n;
    }
    // "msg0".."msg4" = 4+4+4+4+4 = 20 bytes.
    CHECK_EQ(total, 20);
}

