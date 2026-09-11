#ifndef LETHE_NETWORK_POLICY_PROXY_H
#define LETHE_NETWORK_POLICY_PROXY_H

#include <atomic>
#include <condition_variable>
#include <deque>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>
#include "network/doh_resolver.h"
#include "network/http_client.h"
#include "network/tls_config.h"

namespace lethe {

// policy_proxy.h — Local policy-enforcing HTTP/CONNECT proxy.
//
// Full-web engines (WebKitGTK on Linux, WebView2 on Windows) hand their
// ENTIRE network stack to this proxy: plain requests are forwarded through
// an HttpClient carrying Lethe's DoH-only resolution, private-network
// isolation, HSTS, certificate pinning and VPN fail-closed routing;
// CONNECT tunnels are granted only AFTER the destination passes the same
// policy, then spliced byte-for-byte (TLS stays end-to-end between the
// engine and the origin - the proxy never terminates it).
//
// Every refusal fails closed with an HTTP 403 whose body names the reason.

class PolicyProxyServer {
public:
    struct Options {
        // Prototype TLS configuration cloned into per-connection clients.
        TLSConfig tls;
        // DoH provider URL applied to forwarding clients (\"\" inherits
        // none, i.e. resolution stays system-level - avoid in prod).
        std::string dohProvider;
        // Shared DoH answer cache. When null the proxy creates its own so
        // every proxied connection still shares one; pass the browser's
        // cache to share with the navigation gate and reader as well.
        std::shared_ptr<SharedDohCache> dohCache;
        // Shared keep-alive DoH resolver pool; created here when null and a
        // provider is set, so proxied connections never pay TCP + TLS to the
        // provider per query.
        std::shared_ptr<SharedDohResolver> dohResolver;
        // Measurement switch: do not auto-create the pool (per-query
        // provider handshakes, the 0.1.0 behaviour).
        bool disableDohResolverPool = false;
        // Private-network policy applied verbatim.
        PrivateNetworkPolicy privateNet;
        // Shared VPN tunnel for routing decisions + covered relaying.
        vpn::VpnTunnel* vpnTunnel = nullptr;  // non-owning; engine owns it
        // VPN relay endpoint (engine UDP transport) for covered streams.
        void* udpTransport = nullptr;   // UdpTransport* (opaque here)
        std::string relayHost;
        int relayPort = 0;
        // Listen address; almost always loopback - this proxy trusts its
        // TCP peers because it enforces policy FOR them.
        std::string bindHost = "127.0.0.1";
        int bindPort = 0;               // 0 = ephemeral
        // Per-launch secret. When set, every request must carry
        // "Proxy-Authorization: Basic base64(lethe:<token>)" or it is
        // refused with 407 before any policy work or upstream I/O. This
        // closes the open-loopback-proxy hole: without it any local process
        // could ride Lethe's VPN tunnel and policy identity. Empty = off
        // (tests / engines that cannot send proxy credentials).
        std::string authToken;
        // Worker threads in the connection-handling pool. 0 = auto (roughly
        // 3x reported hardware concurrency, bounded to 16-32 workers).
        // CONNECT tunnels are handed to a separate bounded tunnel set, so oversizing this pool only adds
        // scheduler/cache contention under high fan-out.
        size_t workerThreads = 0;
        // Event-driven HTTP/1.x forwarding. Workers perform authentication
        // and policy-gated upstream establishment, then hand the live
        // sockets to one shared kqueue reactor. CONNECT remains on the
        // existing tunnel path. Default stays off until benchmark
        // verification proves parity and a material fan-out win.
        bool enableHttpReactor = false;
        // Optional secure frontend for Chromium: TLS-protected HTTPS proxy
        // with HTTP/2 multiplexing. The existing authenticated HTTP proxy
        // remains the policy backend; this frontend is opt-in until it has
        // passed the full CEF security/performance benchmark.
        bool enableHttpsProxy = false;
        // Number of kqueue reactor shards. Each shard owns its event loop
        // and socket set; the proxy load-balances connections across them.
        // A small shard count avoids turning one reactor CPU into the new
        // fan-out ceiling.
        size_t httpReactorShards = 4;
    };

    // 32 random bytes as hex (OpenSSL RAND_bytes); "" if the CSPRNG fails.
    static std::string generateAuthToken();
    // The exact Proxy-Authorization header value the engine must send.
    static std::string basicCredentialFor(const std::string& token);

    PolicyProxyServer();
    ~PolicyProxyServer();

    PolicyProxyServer(const PolicyProxyServer&) = delete;
    PolicyProxyServer& operator=(const PolicyProxyServer&) = delete;

    // Bind + start accepting. Returns false (with reason in lastError()) on
    // socket failure.
    bool start(const Options& options);
    // Stop accepting, wake live handlers, and join the worker pool.
    void stop();

    int port() const { return port_; }
    int httpsProxyPort() const { return httpsProxyPort_.load(std::memory_order_relaxed); }
    const std::string& httpsProxySpkiSha256() const { return httpsProxySpkiSha256_; }
    const std::string& lastError() const { return lastError_; }

private:
    class HttpForwardReactor;
    class TunnelReactor;
    struct ConnectTask {
        int clientFd = -1;
        std::string host;
        int port = 0;
    };
    void acceptLoop();
    void serveConnection(int clientFd);
    void workerLoop();
    void connectWorkerLoop();
    void serveConnect(int clientFd, std::string host, int port);
    HttpClient::PolicyDialConfig dialConfig() const;

    // One forwarding HttpClient per proxied request chain (cheap relative
    // to network; keeps single-connection client state thread-confined).
    std::unique_ptr<HttpClient> makeClient();

    Options opts_;
    int listenFd_ = -1;
    std::atomic<int> port_{0};
    std::atomic<int> httpsProxyPort_{0};
    std::atomic<bool> running_{false};
    // Set on stop() so in-flight connection handlers (CONNECT splice loops,
    // long reads) can notice shutdown and bail instead of holding a worker
    // thread hostage - which is what made quit() hang on active tunnels.
    std::atomic<bool> stopping_{false};
    std::thread acceptThread_;

    // Every live client fd, so stop() can close them and unblock workers
    // stuck in recv()/read(). Guarded by its own mutex (never held while
    // doing socket I/O).
    std::set<int> activeFds_;
    std::mutex activeFds_mtx_;
    void trackFd(int fd);
    void untrackFd(int fd);
    // True once stop() has begun; connection handlers poll this to exit.
    bool isStopping() const { return stopping_.load(std::memory_order_relaxed); }

    // Fixed-size worker pool: accept() pushes a fresh client fd, workers
    // pop and serve. CONNECT tunnels use the separate bounded tunnel set;
    // auto sizing is modestly over-subscribed for I/O-heavy browser fan-out.
    std::vector<std::thread> workers_;
    // CONNECT admission is deliberately separate from the request pool.
    // dialPolicyChecked() performs DoH/policy/TCP setup synchronously; doing
    // that work on the ordinary request workers makes HTTPS fan-out serialize
    // behind the small request pool before the tunnel reactor ever sees it.
    // These workers are bounded and still execute the identical policy gate.
    std::vector<std::thread> connectWorkers_;
    std::deque<ConnectTask> connectQueue_;
    std::mutex connectQueue_mtx_;
    std::condition_variable connectQueue_cv_;
    size_t connectWorkerCount_ = 0;
    // CONNECT tunnels are long-lived (video/audio/WebSocket/etc.). Keep them
    // out of the request worker pool so a media-heavy page cannot consume
    // every policy worker and create a p99.9 queueing tail for new requests.
    struct TunnelWorker {
        std::thread thread;
        std::shared_ptr<std::atomic<bool>> done;
    };
    std::vector<TunnelWorker> tunnelWorkers_;
    std::mutex tunnelWorkers_mtx_;
    void reapTunnelWorkers();
    static constexpr size_t kMaxTunnelWorkers = 128;
    std::vector<std::unique_ptr<HttpForwardReactor>> httpReactors_;
    std::atomic<size_t> httpReactorRoundRobin_{0};
    std::vector<std::unique_ptr<TunnelReactor>> tunnelReactors_;
    std::atomic<size_t> tunnelReactorRoundRobin_{0};
    std::deque<int> queue_;
    std::mutex queue_mtx_;
    std::condition_variable queue_cv_;
    size_t workerCount_ = 0;

    std::string lastError_;
    std::string httpsProxySpkiSha256_;
    int httpsProxyPid_ = -1;
    std::string httpsProxyKeyPath_;
    std::string httpsProxyCertPath_;
    std::string httpsProxyConfigPath_;
    std::string httpsProxyMrubyPath_;
    bool startHttpsProxyFrontend();
    void stopHttpsProxyFrontend();
    // Precomputed once at start: proxy authentication is on the hot path
    // for every engine connection, so do not rebuild the Base64 credential
    // (and allocate) for every request.
    std::string expectedAuthCredential_;

    // Refuse absurd request sizes before allocating.
    static constexpr size_t kMaxHeaderBytes = 64 * 1024;
};

} // namespace lethe

#endif // LETHE_NETWORK_POLICY_PROXY_H
