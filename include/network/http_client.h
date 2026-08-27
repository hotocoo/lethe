#ifndef LETHE_NETWORK_HTTP_CLIENT_H
#define LETHE_NETWORK_HTTP_CLIENT_H

#include <string>
#include <map>
#include <vector>
#include <chrono>
#include <memory>
#include <cstdint>
#include "network/doh_cache.h"
#include "network/tls_config.h"
#include "network/vpn/vpn_tunnel.h"
#include "security/cert_pinner.h"
#include "security/cookie_jar.h"
#include "security/hsts_cache.h"
#include "security/private_network_guard.h"

// Declared in network/udp_transport.h (included by the .cc).
namespace lethe {
class UdpTransport;
}

using lethe::UdpTransport;

#ifdef HAVE_OPENSSL
#include <openssl/ssl.h>
#endif

namespace lethe {

// PolicyStream - a live, policy-checked byte pipe to one origin.
// Returned by HttpClient::dialPolicyChecked() for CONNECT splices in the
// local policy proxy. The stream OWNS its HttpClient (socket, TLS session
// or tunnel-relay state); destroying it closes everything. read() returns
// >0 bytes, 0 on clean EOF (origin END / half-close), -1 on error/timeout.
struct PolicyStream {
    virtual ~PolicyStream() = default;
    virtual ssize_t read(uint8_t* buf, size_t len, int timeoutMs) = 0;
    virtual bool write(const uint8_t* buf, size_t len) = 0;
    // Half-close our side: END frame on a relay, shutdown(SHUT_WR) direct.
    virtual void shutdownWrite() = 0;
};
using PolicyStreamPtr = std::unique_ptr<PolicyStream>;

enum class HttpMethod { GET, POST, PUT, DELETE, HEAD, PATCH };

// How the client may derive the Referer header from a triggering URL.
// Unset defers to the client default (strict-origin-when-cross-origin).
enum class ReferrerPolicy {
    Unset,
    NoReferrer,                   // never send Referer
    Origin,                       // origin-only, always
    StrictOriginWhenCrossOrigin,  // full same-origin; origin-only
                                  // cross-origin; nothing on downgrade
    UnsafeUrl,                    // full URL always (explicit opt-in)
};

struct HttpRequest {
    std::string url;
    HttpMethod method = HttpMethod::GET;
    std::map<std::string, std::string> headers;
    std::string body;
    std::chrono::seconds timeout = std::chrono::seconds(30);
    // Top-level site ("https://example.com") used to partition cookies.
    // Empty derives the partition from the request URL itself, which is
    // correct for top-level document navigations.
    std::string topLevelSite;
    // URL of the document that triggered this request ("" = none). When
    // set, the Referer sent on every hop is COMPUTED from this URL under
    // the active policy - it is never pasted verbatim. A caller-supplied
    // Referer header still wins outright.
    std::string referrer;
    // Policy override for this request chain; Unset uses the client
    // default. Any response's Referrer-Policy header narrows the policy
    // for later hops of the same chain.
    ReferrerPolicy referrerPolicy = ReferrerPolicy::Unset;
    // Marks a top-level user navigation (address bar, link or history
    // traversal). Navigation requests send Sec-Fetch-Site/Mode/Dest/User
    // metadata and Upgrade-Insecure-Requests: 1; API-style fetches (LLM
    // agent traffic) leave this false and their wire format stays
    // exactly as before.
    bool navigationRequest = false;
};

struct HttpResponse {
    int statusCode = 0;
    std::map<std::string, std::string> headers;
    std::vector<char> body;
    bool success = false;
    std::string error;
    // Final URL after redirects (may differ from the requested URL).
    std::string finalUrl;
    // Every Set-Cookie value seen on THIS response hop, in wire order
    // (headers map collapses repeats; cookies must not be collapsed).
    std::vector<std::string> setCookieHeaders;
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

    // --- HTTP(S)-over-tunnel relay (streaming) ---
    // Share the engine's VPN UDP transport and endpoint. When a tunnel is
    // CONNECTED and the resolved destination is covered by its CIDRs, the
    // exchange (plain HTTP or TLS) is carried THROUGH the encrypted tunnel
    // as a streaming relay: the server connects the TCP origin, and bytes
    // flow both directions as framed DATA. The client never opens direct
    // TCP to covered destinations while the tunnel is up. Pass nullptr to
    // disable.
    void setVpnRelay(UdpTransport* udpTransport,
                     const std::string& endpointHost, int endpointPort);

    // --- Secure DNS (DNS-over-HTTPS) ---
    // Route all hostname resolution through a DoH JSON provider
    // (e.g. https://cloudflare-dns.com/dns-query). When configured,
    // plaintext system DNS is never consulted for target hosts and a DoH
    // failure blocks the request (fail closed) instead of leaking.
    // Empty string disables. IP-literal URLs skip resolution entirely.
    void setDohProvider(const std::string& url);
    bool isDohEnabled() const { return !dohProvider_.empty(); }
    // TTL for cached DoH answers (default 300s; 0 disables the cache).
    // Only successful resolutions are ever cached - failures always retry
    // the provider, so fail-closed semantics are unchanged.
    void setDohCacheTtl(std::chrono::seconds ttl) { dohCacheTtl_ = ttl; }
    // Share one answer cache across many clients (proxy connections, the
    // navigation gate, reader fetches): a hostname is then resolved once
    // per TTL process-wide instead of once per connection. nullptr reverts
    // to the private per-client cache.
    void setSharedDohCache(std::shared_ptr<SharedDohCache> cache) { sharedDoh_ = std::move(cache); }
    const std::shared_ptr<SharedDohCache>& sharedDohCache() const { return sharedDoh_; }

    // --- Cookies (partitioned jar owned by Engine) ---
    // When enabled and the request carries a top-level site (or the URL
    // implies one), matching cookies ride as a Cookie header and every
    // Set-Cookie of every response hop lands in the jar under that
    // partition. An explicit Cookie header from the caller always wins.
    void enableCookies(CookieJar* jar) { cookieJar_ = jar; }
    void disableCookies() { cookieJar_ = nullptr; }
    bool cookiesEnabled() const { return cookieJar_ != nullptr; }

    // --- HSTS (RFC 6797, cache owned by Engine) ---
    // When enabled: Strict-Transport-Security headers on VERIFIED https://
    // hops are recorded into the cache, and every later http:// request to
    // a covered host is rewritten to https:// BEFORE any network I/O - the
    // plaintext request is never attempted, and no insecure fallback
    // exists (a failed TLS handshake fails the whole request).
    void enableHsts(HstsCache* cache) { hstsCache_ = cache; }
    void disableHsts() { hstsCache_ = nullptr; }
    bool hstsEnabled() const { return hstsCache_ != nullptr; }

    // --- Certificate pinning (SPKI SHA-256, store owned by Engine) ---
    // Hosts carrying pins accept only TLS chains in which at least one
    // certificate's SubjectPublicKeyInfo hashes to a configured pin.
    // Enforcement runs on EVERY handshake - direct TCP and TLS-over-tunnel
    // alike, redirect hops included - right after (and in addition to)
    // ordinary certificate verification. A mismatch fails closed: the
    // connection is torn down and the request never goes out.
    void enableCertPinning(CertPinner* pinner) { certPinner_ = pinner; }
    void disableCertPinning() { certPinner_ = nullptr; }
    bool certPinningEnabled() const { return certPinner_ != nullptr; }

    // Default User-Agent used when the request does not carry one.
    // Empty restores the built-in standard string.
    void setUserAgent(std::string ua) { defaultUserAgent_ = std::move(ua); }
    const std::string& userAgent() const { return defaultUserAgent_; }

    // --- Navigation request hygiene ---
    // Default referrer policy for requests that do not override it.
    // StrictOriginWhenCrossOrigin is the browser-standard default: a
    // triggering URL is only ever revealed in full to its own origin,
    // reduced to its origin elsewhere, and withheld entirely on any
    // https -> http downgrade.
    void setDefaultReferrerPolicy(ReferrerPolicy policy) {
        defaultReferrerPolicy_ = policy;
    }
    ReferrerPolicy defaultReferrerPolicy() const {
        return defaultReferrerPolicy_;
    }

    // --- Private-network (SSRF) isolation ---
    // Every hop's RESOLVED destination address - the DoH answer for a
    // hostname, an IP literal, or a canonicalized numeric spelling-out -
    // is scope-classified BEFORE any socket is opened and BEFORE the
    // encrypted-tunnel relay path is chosen. Destinations in non-permitted
    // private scopes (RFC1918, CGNAT, link-local/cloud-metadata, IPv6 ULA,
    // embedded-IPv4 wrappers, reserved ranges) fail closed with a named
    // reason; loopback stays reachable while allowLoopback is set, and
    // explicit hostnames can be re-admitted via PrivateNetworkPolicy.
    void setPrivateNetworkPolicy(PrivateNetworkPolicy policy) {
        privateNetGuard_.setPolicy(std::move(policy));
    }
    const PrivateNetworkPolicy& privateNetworkPolicy() const {
        return privateNetGuard_.policy();
    }

    // Canonicalize every numeric IPv4/IPv6 spelling the platform's
    // resolvers accept - dotted quads plus the inet_aton family (decimal
    // "2130706433", octal "0177.0.0.1", mixed-radix and short forms) that
    // inet_pton refuses - into standard text form. Returns "" for anything
    // that would need name resolution. Purely local: no DNS, no network.
    static std::string canonicalNumericAddress(const std::string& host);

    // Parse a Referrer-Policy header value ("no-referrer, unsafe-url").
    // Per spec, the LAST recognized token wins and unknown tokens are
    // skipped; returns false when no recognized token remains (such a
    // header leaves the active policy untouched).
    static bool parseReferrerPolicy(const std::string& headerValue,
                                    ReferrerPolicy& out);

    // Derive Sec-Fetch-Site for a hop from the triggering URL ("none"
    // when there is none; same-origin / same-site / cross-site).
    // Same-site is best-effort "last two host labels" without a Public
    // Suffix List; IP-literal hosts are same-site only when identical.
    static std::string deriveFetchSite(const std::string& referrerUrl,
                                       const std::string& targetUrl);

    // --- Embedded full-web engine support (local policy proxy) ---
    // Configuration for dialPolicyChecked(); mirrors what a configured
    // client carries, so the proxy can mint per-connection clients with
    // identical policy without sharing mutable state across threads.
    struct PolicyDialConfig {
        TLSConfig tls;
        std::string dohProvider;          // empty = system DNS (tests)
        std::shared_ptr<SharedDohCache> dohCache; // shared answers (may be null)
        PrivateNetworkPolicy privateNet;
        UdpTransport* vpnUdp = nullptr;   // enables covered-relay dials
        vpn::VpnTunnel* vpnTunnel = nullptr; // non-owning; engine owns it
        std::string relayEndpointHost;
        int relayEndpointPort = 0;
        std::chrono::seconds timeout{30};
        // Raw-tunnel mode (CONNECT splices): policy checks still run in
        // full, but the proxy NEVER terminates TLS - the caller's bytes
        // pass through untouched, so the engine keeps end-to-end TLS with
        // the origin. Certificate pinning cannot apply here (the chain is
        // invisible); documented honestly rather than faked.
        bool rawTunnel = false;
    };

    // Open a live stream to scheme://host:port after running the FULL
    // request-path policy: DoH-only resolution (or canonicalization of IP
    // literals), private-network scope check on the RESOLVED address, VPN
    // fail-closed routing - covered destinations ride the encrypted relay
    // when the tunnel is up and are REFUSED when it is down. https dials
    // complete a verified handshake (certificate verification and pins)
    // before the stream is handed over; CONNECT splices raw bytes through.
    // On refusal returns nullptr with a named reason in \p error.
    static PolicyStreamPtr dialPolicyChecked(const PolicyDialConfig& cfg,
                                             const std::string& scheme,
                                             const std::string& host,
                                             int port, std::string& error);

    // Navigation gate for embedded engines: "" = allowed, otherwise the
    // named refusal. Resolves the URL's host exactly like the request
    // path would (DoH / literal canonicalization), runs the private-net
    // guard and the VPN fail-closed decision WITHOUT opening any socket
    // to the destination.
    std::string policyCheckUrl(const std::string& url);

    class DialStreamImpl;

private:
    // --- Relay state (streaming HTTP(S)-over-tunnel) ---
    bool relayConfigured() const {
        return vpnUdp_ != nullptr && !vpnEndpointHost_.empty() &&
               vpnEndpointPort_ > 0;
    }
    void resetRelayState();
    bool relayEnsureOpen();                       // OPEN + wait OK/ERR
    bool relaySendData(const uint8_t* p, size_t n);
    bool relaySendEnd();
    // Pull one xid-filtered frame: 1 = DATA appended to relayIn_,
    // 2 = irrelevant frame skipped, 0 = stream ended (END), -1 = error.
    int pullRelayFrame(int timeoutMs);
    int pullUntilUseful(int timeoutMs);
    // TLS-over-pipe helpers (memory BIOs).
    bool tlsPumpOut();                            // wbio pending -> DATA
    bool tlsFillRead(int timeoutMs);              // tunnel frames -> rbio

    UdpTransport* vpnUdp_ = nullptr;
    std::string vpnEndpointHost_;
    int vpnEndpointPort_ = 0;
    bool relayMode_ = false;
    std::string relayTargetHost_;
    int relayTargetPort_ = 0;
    uint32_t relayXid_ = 0;
    bool relayOpenSent_ = false;
    bool relayEstablished_ = false;
    bool relayFailed_ = false;
    std::vector<uint8_t> relayIn_;
    size_t relayInPos_ = 0;
    bool relayEof_ = false;
    void* relayRbio_ = nullptr; // BIO* (opaque here; OpenSSL owns via SSL)
    void* relayWbio_ = nullptr;

    // --- Connection management ---
    bool connectToHost(const std::string& host, int port, const std::string& scheme,
                       const std::chrono::seconds timeout);
    // Raw TCP connect (non-blocking with timeout); sets socketFd_.
    bool openTcp(const std::string& target, int port);
    // TLS handshake on the current socket; SNI/cert name = tlsHostname.
    bool startTls(const std::string& tlsHostname);
    // Post-handshake pin enforcement for tlsHostname. No-op unless the
    // host carries pins; walks the peer chain (leaf first) computing SPKI
    // SHA-256 digests and requires one match. Sets lastConnectError_ on
    // mismatch ("Blocked: certificate pin mismatch for <host>").
    bool verifyCertificatePins(const std::string& tlsHostname);
    void closeConnection();

    // --- Secure DNS helpers ---
    static bool isIpLiteral(const std::string& host);
    bool refreshDohBootstrap();
    bool dohResolve(const std::string& host, std::string& outIp);
    static std::string urlEncode(const std::string& in);
    static bool looksLikeIpv4(const std::string& s);

    // Private-network isolation decision maker (stateless policy holder).
    PrivateNetworkGuard privateNetGuard_;

    // --- DoH answer cache (host -> resolved IP with expiry) ---
    void dohCacheStore(const std::string& host, const std::string& ip);
    bool dohCacheLookup(const std::string& host, std::string& outIp);
    struct DohEntry {
        std::string ip;
        std::chrono::steady_clock::time_point expires{};
    };

    // --- Buffered connection reads ---
    // All response parsing pulls through one buffer so header lines and
    // chunked framing stop costing a syscall per byte, and so bytes read
    // past a response boundary survive for keep-alive reuse.
    int fillIoBuf(); // >0 bytes buffered, 0 clean EOF, <0 error/timeout
    int bufferedReadByte(uint8_t& out);
    bool bufferedReadExact(uint8_t* dst, size_t n);

    // --- Keep-alive connection reuse ---
    bool tryReuseConnection(const std::string& scheme, const std::string& host,
                            int port);
    // Decide from the just-parsed response whether the connection may serve
    // another request; closes it when it may not.
    void finishResponse(HttpResponse& resp);

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
    static void parseUrl(const std::string& url, std::string& scheme, std::string& host,
                         std::string& path, int& port);
    std::string buildHttpRequest(const HttpRequest& req, const std::string& host,
                                 const std::string& path, int port,
                                 const std::string& cookieHeader,
                                 const std::string& computedReferer,
                                 const std::string& secFetchSite);

    // --- Navigation request hygiene helpers ---
    // Referer header value for one hop: computed from the triggering URL
    // under p policy ("" when the policy withholds it entirely).
    static std::string refererForHop(const std::string& referrer,
                                     const std::string& targetUrl,
                                     ReferrerPolicy policy);
    // Effective origin "scheme://host[:port]" (default ports omitted).
    struct HopParts {
        std::string scheme, host, path;
        int port = 0;
    };
    static HopParts splitHop(const std::string& url);
    static bool hopSameOrigin(const HopParts& a, const HopParts& b);
    static std::string hopOrigin(const HopParts& p);
    // Default referrer policy applied when requests don't override it.
    ReferrerPolicy defaultReferrerPolicy_ = ReferrerPolicy::StrictOriginWhenCrossOrigin;
    // Cookie header for one request hop under its partition ("" when none).
    // \p hopInitiator is the URL that triggered THIS hop (the caller's
    // referrer on the first hop, the previous hop while redirecting); it
    // drives the RFC6265bis SameSite delivery decision in the jar.
    std::string cookieHeaderForHop(const HttpRequest& req,
                                   const std::string& currentUrl,
                                   const std::string& hopInitiator) const;

    TLSConfig tlsConfig_;
    bool initialized_ = false;
    std::shared_ptr<vpn::VpnTunnel> vpnTunnel_;

    // Secure DNS state.
    std::string dohProvider_;                              // empty = disabled
    std::vector<std::string> dohProviderIps_;              // bootstrap cache
    std::chrono::steady_clock::time_point dohBootstrapTime_{};
    bool dohBootstrapValid_ = false;

    // DoH answer cache: bounded, success-only, TTL-expired.
    std::map<std::string, DohEntry> dohCache_;
    std::shared_ptr<SharedDohCache> sharedDoh_;            // optional, process-wide
    static constexpr size_t kMaxDohCacheEntries = 256;
    std::chrono::seconds dohCacheTtl_{300};

    // Diagnostic reason for the most recent connect failure.
    std::string lastConnectError_;

    // Partitioned cookie storage (not owned) and configurable UA default.
    CookieJar* cookieJar_ = nullptr;
    std::string defaultUserAgent_;

    // HSTS policy store (not owned); nullptr disables enforcement.
    HstsCache* hstsCache_ = nullptr;

    // Certificate pin store (not owned); nullptr disables enforcement.
    CertPinner* certPinner_ = nullptr;

    // Current connection state (one connection at a time).
    int socketFd_ = -1;
    bool usingTls_ = false;
    std::chrono::milliseconds ioTimeout_ = std::chrono::seconds(30);

    // Buffered-read state (persists across keep-alive responses).
    std::vector<uint8_t> ioBuf_;
    size_t ioBufPos_ = 0;

    // Keep-alive state.
    std::string kaScheme_;
    std::string kaHost_;
    std::string kaResolvedTarget_;   // address the conn was established to
    bool kaTargetIsIp_ = false;      // target was classifiable at connect
    int kaPort_ = 0;
    bool connectionReusable_ = false;  // established conn may serve another req
    bool connectionReused_ = false;    // last request rode a reused conn
    bool peerAllowsKeepAlive_ = true;  // no "Connection: close" in response
    bool http10Peer_ = false;          // HTTP/1.0 responses default to close
    bool bodyUntilEof_ = false;        // EOF-delimited body burns the conn
#ifdef HAVE_OPENSSL
    SSL* ssl_ = nullptr;
    SSL_CTX* sslCtx_ = nullptr;
#endif
};

} // namespace lethe

#endif // LETHE_NETWORK_HTTP_CLIENT_H

