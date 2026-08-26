// http_client.cc - HTTP/HTTPS client with live socket I/O
//
// Implements real network fetching:
//   - TCP connect with timeout (IPv4/IPv6 via getaddrinfo)
//   - TLS handshake via OpenSSL (SNI, version policy, certificate verification)
//   - HTTP/1.1 request writing and response parsing
//   - Content-Length, chunked transfer-encoding, and read-until-close bodies
//   - gzip/deflate response decompression (zlib)
//   - Redirect following (3xx + Location, up to 5 hops)

#include "network/http_client.h"
#include "network/udp_transport.h"
#include "network/vpn/vpn_relay.h"

#include <algorithm>

#include <arpa/inet.h>
#include <cerrno>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <netdb.h>
#include <sstream>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#include <zlib.h>

#ifdef HAVE_OPENSSL
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#endif

#include "config.h"

namespace lethe {

namespace {

constexpr size_t kReadChunkSize = 16384;
constexpr size_t kMaxResponseSize = 32 * 1024 * 1024; // 32 MiB safety cap
constexpr int kMaxRedirects = 5;

std::string toLowerCopy(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string trimCopy(const std::string& s) {
    size_t start = s.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(start, end - start + 1);
}

std::string getHeader(const std::map<std::string, std::string>& headers,
                      const std::string& name) {
    auto it = headers.find(toLowerCopy(name));
    if (it == headers.end()) return "";
    return it->second;
}

// Best-effort registrable-domain stand-in for the Public Suffix List:
// the last two labels of an already-lowercased host. Deliberately not
// PSL-exact (co.uk style multi-label suffixes would misgroup); IP
// literals never take part in same-site matching at the call sites.
std::string lastTwoLabels(const std::string& hostLower) {
    const size_t last = hostLower.find_last_of('.');
    if (last == std::string::npos || last == 0) return hostLower;
    const size_t prev = hostLower.find_last_of('.', last - 1);
    if (prev == std::string::npos) return hostLower;
    return hostLower.substr(prev + 1);
}

// Resolve an absolute or relative Location header against a base URL.
std::string resolveUrl(const std::string& base, const std::string& location) {
    if (location.empty()) return base;
    // Already an absolute URL of ANY scheme (http(s), ftp://, ws://, ...).
    // Whether that scheme may actually be followed is decided later by
    // the fail-closed scheme allowlist - never here.
    const size_t schemeSep = location.find("://");
    if (schemeSep != std::string::npos &&
        location.find('/') > schemeSep) {
        return location;
    }

    // Extract "scheme://host[:port]" (the origin) from the base URL.
    size_t schemeEnd = base.find("://");
    if (schemeEnd == std::string::npos) return location;
    std::string scheme = base.substr(0, schemeEnd + 3); // e.g. "http://"
    size_t hostStart = schemeEnd + 3;
    size_t hostEnd = base.find('/', hostStart);
    std::string authority = (hostEnd == std::string::npos)
                                ? base.substr(hostStart)
                                : base.substr(hostStart, hostEnd - hostStart);
    std::string origin = scheme + authority; // e.g. "http://127.0.0.1:8080"

    if (location.rfind("//", 0) == 0) {
        // Protocol-relative: //host/path
        return scheme + location;
    }
    if (location.rfind("/", 0) == 0) {
        // Absolute path: /path
        return origin + location;
    }
    // Relative path: append under the origin root.
    return origin + "/" + location;
}

} // namespace

HttpClient::HttpClient() : initialized_(false) {}

HttpClient::~HttpClient() {
    shutdown();
}

bool HttpClient::initialize(const TLSConfig& tlsConfig) {
    tlsConfig_ = tlsConfig;

#ifdef HAVE_OPENSSL
    OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, nullptr);
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

    std::string currentUrl = req.url;
    HttpRequest currentReq = req;

    // Referrer state across this request chain: starts from the
    // triggering document (when the caller supplied one), then every
    // followed redirect makes the previous hop the next hop's referrer.
    // The policy starts from the request override or the client default,
    // and any response's Referrer-Policy header narrows it for later
    // hops of the same chain.
    std::string hopReferrer = currentReq.referrer;
    ReferrerPolicy chainPolicy =
        currentReq.referrerPolicy != ReferrerPolicy::Unset
            ? currentReq.referrerPolicy
            : defaultReferrerPolicy_;

    for (int redirect = 0; redirect <= kMaxRedirects; redirect++) {
        std::string scheme, host, path;
        int port = 0;
        parseUrl(currentUrl, scheme, host, path, port);

        // Fail-closed scheme allowlist, enforced on EVERY hop BEFORE any
        // network I/O - including redirect targets, so a Location that
        // points at ftp:// or javascript: can never drag a navigation
        // off the secure stack. Only real http(s) is fetchable here.
        if (scheme != "http" && scheme != "https") {
            resp.error = "Blocked non-http(s) URL scheme '" + scheme +
                         "': " + currentUrl;
            std::cerr << "[lethe-http] " << resp.error << std::endl;
            closeConnection();
            return resp;
        }

        if (host.empty()) {
            resp.error = "Invalid URL: " + currentUrl;
            return resp;
        }

        // RFC 6797 enforcement BEFORE any network I/O: an http:// request
        // to a host with a recorded Strict-Transport-Security policy is
        // rewritten to https:// here - plaintext is never put on the wire
        // and there is no insecure fallback if TLS then fails.
        if (scheme == "http" && hstsEnabled() &&
            hstsCache_->shouldUpgrade(host)) {
            constexpr const char* kHttpPrefix = "http://";
            currentUrl = "https://" + currentUrl.substr(strlen(kHttpPrefix));
            std::cout << "[lethe-http] HSTS upgrade: " << currentUrl
                      << " enforced before connect" << std::endl;
            parseUrl(currentUrl, scheme, host, path, port);
        }

        // VPN fail-closed policy is enforced inside connectToHost on the
        // RESOLVED destination address (after DoH), so hostname destinations
        // are protected exactly like IP literals.
        const bool viaVpn = isVpnActive() && vpnTunnel_ &&
            vpnTunnel_->shouldRouteThroughVpn(host);

        std::cout << "[lethe-http] "
                  << (currentReq.method == HttpMethod::GET ? "GET" : "REQ")
                  << " " << currentUrl << (viaVpn ? " (via VPN)" : "") << std::endl;

        // A reused keep-alive connection can go stale while idle (the peer
        // closed it). That failure mode is indistinguishable from a flaky
        // network until the write/read fails - so retry ONCE on a fresh
        // connection before giving up. Never retried for fresh connections.
        bool gotResponse = false;
        for (int attempt = 0; attempt < 2 && !gotResponse; ++attempt) {
            if (!connectToHost(host, port, scheme, currentReq.timeout)) {
                resp.error = !lastConnectError_.empty()
                    ? lastConnectError_
                    : "Connection failed to " + host + ":" + std::to_string(port);
                lastConnectError_.clear();
                return resp;
            }

            const bool reused = connectionReused_;
            resp = HttpResponse{}; // no state may leak between attempts/hops

            // Navigation hygiene is computed per hop, AFTER the HSTS
            // rewrite above, so downgrade decisions always see the scheme
            // that will actually hit the wire.
            const std::string computedReferer =
                refererForHop(hopReferrer, currentUrl, chainPolicy);
            const std::string secFetchSite =
                deriveFetchSite(hopReferrer, currentUrl);

            std::string httpRequest = buildHttpRequest(
                currentReq, host, path, port,
                cookieHeaderForHop(currentReq, currentUrl, hopReferrer),
                computedReferer, secFetchSite);
            if (!writeAll(httpRequest.data(), httpRequest.size())) {
                const bool stale = reused && attempt == 0;
                closeConnection();
                if (stale) continue;
                resp.error = "Failed to write request to " + host;
                return resp;
            }

            if (!readFullResponse(resp)) {
                const bool stale = reused && attempt == 0;
                closeConnection();
                if (stale) continue;
                if (resp.error.empty()) {
                    resp.error = "Failed to read response from " + host;
                }
                return resp;
            }
            gotResponse = true;
        }

        // Keep the connection open only when both sides agree it can serve
        // another request; otherwise tear it down now.
        finishResponse(resp);

        // Every hop's Set-Cookie lands in the partitioned jar under the
        // top-level site of THIS navigation (redirect hops included).
        if (cookieJar_ && !resp.setCookieHeaders.empty()) {
            const std::string hopSite = CookieJar::topLevelSiteFor(currentUrl);
            const std::string& part =
                currentReq.topLevelSite.empty() ? hopSite : currentReq.topLevelSite;
            for (const auto& sc : resp.setCookieHeaders) {
                cookieJar_->store(part, currentUrl, sc);
            }
        }

        // Strict-Transport-Security is honored only on verified https://
        // hops (RFC 6797 forbids learning policy over plain HTTP) and on
        // redirect hops too - a 3xx can carry the header just as well.
        if (hstsEnabled() && scheme == "https") {
            const std::string sts = getHeader(
                resp.headers, "strict-transport-security");
            if (!sts.empty()) {
                std::chrono::seconds maxAge{0};
                bool includeSubDomains = false;
                if (HstsCache::parseStsHeader(sts, maxAge,
                                              includeSubDomains)) {
                    hstsCache_->record(host, maxAge, includeSubDomains);
                    std::cout << "[lethe-http] HSTS policy recorded for "
                              << host << " (max-age="
                              << maxAge.count()
                              << (includeSubDomains ? ", includeSubDomains"
                                                    : "")
                              << ")" << std::endl;
                } else {
                    std::cout << "[lethe-http] Ignoring malformed "
                                 "Strict-Transport-Security header"
                              << std::endl;
                }
            }
        }

        // Referrer-Policy is honored on ANY response of the chain
        // (redirect hops included): once a recognized policy arrives it
        // governs every later hop - mirroring how a document's policy
        // governs its subresource requests. A header with no recognized
        // token leaves the active policy untouched.
        const std::string rpHeader =
            getHeader(resp.headers, "referrer-policy");
        if (!rpHeader.empty()) {
            ReferrerPolicy learned;
            if (parseReferrerPolicy(rpHeader, learned)) {
                chainPolicy = learned;
            } else {
                std::cout << "[lethe-http] Ignoring Referrer-Policy "
                             "header with no known token" << std::endl;
            }
        }

        // Follow redirects.
        if (resp.statusCode >= 300 && resp.statusCode < 400) {
            std::string location = getHeader(resp.headers, "location");
            if (location.empty()) {
                resp.error = "Redirect without Location header";
                return resp;
            }
            if (redirect == kMaxRedirects) {
                resp.error = "Too many redirects";
                return resp;
            }
            const std::string previousHop = currentUrl;
            currentUrl = resolveUrl(currentUrl, location);
            hopReferrer = previousHop;
            // Redirects to a different host with POST become GET.
            if (currentReq.method == HttpMethod::POST) {
                currentReq.method = HttpMethod::GET;
                currentReq.body.clear();
            }
            continue;
        }

        resp.finalUrl = currentUrl;
        return resp;
    }

    resp.error = "Too many redirects";
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

// --- Secure DNS (DNS-over-HTTPS) ---------------------------------------------

std::string HttpClient::cookieHeaderForHop(
    const HttpRequest& req, const std::string& currentUrl,
    const std::string& hopInitiator) const {
    if (!cookieJar_) return "";
    const std::string hopSite = CookieJar::topLevelSiteFor(currentUrl);
    const std::string& part =
        req.topLevelSite.empty() ? hopSite : req.topLevelSite;

    // SameSite context of THIS hop: the initiator is the triggering
    // document (first hop) or the previous redirect hop; navigation kind
    // and method safety decide whether Lax cookies may ride cross-site.
    CookieRequestContext ctx;
    ctx.initiatorUrl = hopInitiator;
    ctx.topNavigation = req.navigationRequest;
    switch (req.method) {
    case HttpMethod::GET:
    case HttpMethod::HEAD:
        ctx.safeMethod = true;
        break;
    default:
        ctx.safeMethod = false; // POST/PUT/PATCH/DELETE never count as safe
        break;
    }
    return cookieJar_->headerFor(part, currentUrl, ctx);
}

void HttpClient::setDohProvider(const std::string& url) {
    dohProvider_ = url;
    dohProviderIps_.clear();
    dohBootstrapValid_ = false;
    dohCache_.clear(); // answers pinned to the old provider must not survive
    if (!url.empty()) {
        std::cout << "[lethe-http][doh] provider configured: " << url << std::endl;
    }
}

bool HttpClient::isIpLiteral(const std::string& host) {
    in_addr v4{};
    in6_addr v6{};
    return ::inet_pton(AF_INET, host.c_str(), &v4) == 1 ||
           ::inet_pton(AF_INET6, host.c_str(), &v6) == 1;
}

std::string HttpClient::canonicalNumericAddress(const std::string& host) {
    // The platform resolver is the single source of truth: openTcp() dials
    // through getaddrinfo, so AI_NUMERICHOST (purely local - no DNS, no
    // network) sees exactly what a connection WOULD dial. This also keeps
    // documented platform divergences honest: glibc reads leading-zero
    // octets as octal ("0177.0.0.1" -> 127.0.0.1) while Apple resolvers
    // read them as decimal ("0177.0.0.1" -> 177.0.0.1); either way the
    // guard classifies the address that would actually be dialed.
    if (host.empty()) return ""; // some platforms accept "" as a wildcard
    addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_NUMERICHOST | AI_NUMERICSERV;
    addrinfo* res = nullptr;
    if (::getaddrinfo(host.c_str(), "0", &hints, &res) != 0 || !res) {
        return "";
    }
    char buf[INET6_ADDRSTRLEN] = {0};
    std::string out;
    const void* src = res->ai_family == AF_INET
        ? static_cast<const void*>(
              &reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr)
        : static_cast<const void*>(
              &reinterpret_cast<sockaddr_in6*>(res->ai_addr)->sin6_addr);
    if (::inet_ntop(res->ai_family, src, buf, sizeof(buf))) {
        out = buf;
    }
    ::freeaddrinfo(res);
    return out;
}

std::string HttpClient::urlEncode(const std::string& in) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    out.reserve(in.size() * 3);
    for (unsigned char c : in) {
        const bool unreserved = std::isalnum(c) || c == '-' || c == '.' ||
                                c == '_' || c == '~';
        if (unreserved) {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(hex[c >> 4]);
            out.push_back(hex[c & 0xF]);
        }
    }
    return out;
}

bool HttpClient::looksLikeIpv4(const std::string& s) {
    int octets = 0;
    size_t i = 0;
    while (i < s.size()) {
        // One octet: 1-3 digits, value <= 255.
        int digits = 0, value = 0;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
            value = value * 10 + (s[i] - '0');
            digits++;
            i++;
            if (digits > 3) return false;
        }
        if (digits == 0 || value > 255) return false;
        octets++;
        if (i < s.size() && s[i] == '.') {
            i++;
            if (i >= s.size()) return false; // trailing dot
        } else {
            break;
        }
    }
    return octets == 4 && i == s.size();
}

bool HttpClient::refreshDohBootstrap() {
    const auto now = std::chrono::steady_clock::now();
    if (dohBootstrapValid_ &&
        now - dohBootstrapTime_ < std::chrono::seconds(300)) {
        return !dohProviderIps_.empty();
    }

    std::string scheme, phost, path;
    int port = 0;
    parseUrl(dohProvider_, scheme, phost, path, port);
    if (phost.empty()) return false;

    addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo* res = nullptr;
    const std::string portStr = std::to_string(port);
    if (::getaddrinfo(phost.c_str(), portStr.c_str(), &hints, &res) != 0 || !res) {
        dohProviderIps_.clear();
        dohBootstrapValid_ = true;
        dohBootstrapTime_ = now;
        return false;
    }

    dohProviderIps_.clear();
    char ipbuf[INET6_ADDRSTRLEN] = {0};
    for (addrinfo* rp = res; rp; rp = rp->ai_next) {
        void* src = rp->ai_family == AF_INET
            ? static_cast<void*>(&reinterpret_cast<sockaddr_in*>(rp->ai_addr)->sin_addr)
            : static_cast<void*>(&reinterpret_cast<sockaddr_in6*>(rp->ai_addr)->sin6_addr);
        if (::inet_ntop(rp->ai_family, src, ipbuf, sizeof(ipbuf))) {
            dohProviderIps_.emplace_back(ipbuf);
        }
    }
    ::freeaddrinfo(res);

    dohBootstrapValid_ = true;
    dohBootstrapTime_ = now;
    return !dohProviderIps_.empty();
}

// --- DoH answer cache -------------------------------------------------------

void HttpClient::dohCacheStore(const std::string& host, const std::string& ip) {
    if (dohCacheTtl_.count() <= 0) return;
    // Bound the cache: drop expired entries first; if a pathological burst
    // still exceeds the cap, start over rather than grow without limit.
    if (dohCache_.size() >= kMaxDohCacheEntries) {
        const auto now = std::chrono::steady_clock::now();
        for (auto it = dohCache_.begin(); it != dohCache_.end();) {
            if (now >= it->second.expires) it = dohCache_.erase(it);
            else ++it;
        }
        if (dohCache_.size() >= kMaxDohCacheEntries) dohCache_.clear();
    }
    dohCache_[host] = DohEntry{ip, std::chrono::steady_clock::now() + dohCacheTtl_};
}

bool HttpClient::dohCacheLookup(const std::string& host, std::string& outIp) {
    const auto now = std::chrono::steady_clock::now();
    auto it = dohCache_.find(host);
    if (it == dohCache_.end()) return false;
    if (now >= it->second.expires) {
        dohCache_.erase(it);
        return false;
    }
    outIp = it->second.ip;
    return true;
}

bool HttpClient::dohResolve(const std::string& host, std::string& outIp) {
    // Repeat visits to a host are the common case for both browsing and LLM
    // page reads: serve them from the TTL cache instead of paying a fresh
    // DoH round trip (which itself opens TCP+TLS to the provider).
    if (!dohCache_.empty() || dohCacheTtl_.count() > 0) {
        std::string cached;
        if (dohCacheLookup(host, cached)) {
            outIp = cached;
            std::cout << "[lethe-http][doh] " << host << " -> " << cached
                      << " (cached)" << std::endl;
            return true;
        }
    }

    std::string pscheme, phost, ppath;
    int pport = 0;
    parseUrl(dohProvider_, pscheme, phost, ppath, pport);
    if (phost.empty()) return false;

    // Bootstrap: resolve the PROVIDER once via the system resolver. Only the
    // trusted provider's address ever comes from plaintext DNS.
    if (!refreshDohBootstrap()) {
        std::cerr << "[lethe-http][doh] cannot resolve provider " << phost
                  << std::endl;
        return false;
    }

    std::string query = ppath;
    if (query.find('?') == std::string::npos) query += '?';
    else query += '&';
    query += "name=" + urlEncode(host) + "&type=1"; // A record

    for (const auto& pip : dohProviderIps_) {
        closeConnection();
        if (!openTcp(pip, pport)) continue;
        if (pscheme == "https" && !startTls(phost)) { // SNI/cert = provider name
            continue;
        }

        const std::string reqStr =
            "GET " + query + " HTTP/1.1\r\n"
            "Host: " + phost + "\r\n"
            "Accept: application/dns-json\r\n"
            "User-Agent: lethe-doh\r\n"
            "Connection: close\r\n\r\n";

        HttpResponse resp;
        if (writeAll(reqStr.data(), reqStr.size()) && readFullResponse(resp) &&
            resp.statusCode == 200) {
            closeConnection();
            // Extract the first IPv4 A record from the JSON Answer list.
            const std::string body(resp.body.data(), resp.body.size());
            size_t pos = 0;
            while ((pos = body.find("\"data\"", pos)) != std::string::npos) {
                const size_t colon = body.find(':', pos + 6);
                const size_t q1 = body.find('"', colon + 1);
                const size_t q2 = body.find('"', q1 + 1);
                if (colon == std::string::npos || q1 == std::string::npos ||
                    q2 == std::string::npos) break;
                const std::string candidate = body.substr(q1 + 1, q2 - q1 - 1);
                pos = q2;
                if (looksLikeIpv4(candidate)) {
                    outIp = candidate;
                    dohCacheStore(host, candidate);
                    std::cout << "[lethe-http][doh] " << host << " -> "
                              << candidate << std::endl;
                    return true;
                }
            }
            continue; // valid response but no A record: try next provider IP
        }
        closeConnection();
    }
    return false;
}

void HttpClient::shutdown() {
    closeConnection();
    if (initialized_) {
        initialized_ = false;
        std::cout << "[lethe] HTTP client shut down" << std::endl;
    }
}

// --- Connection management ---

bool HttpClient::connectToHost(const std::string& host, int port,
                               const std::string& scheme,
                               const std::chrono::seconds timeout) {
    ioTimeout_ = std::chrono::duration_cast<std::chrono::milliseconds>(timeout);
    lastConnectError_.clear();

    // Fast path: an established keep-alive connection to the same
    // scheme://host:port serves the next request with no TCP or TLS setup,
    // and skips DNS entirely - the origin was already validated for it.
    if (tryReuseConnection(scheme, host, port)) {
        std::cout << "[lethe-http] Reusing keep-alive connection to "
                  << host << ":" << port << std::endl;
        return true;
    }

    closeConnection();
    connectionReused_ = false;

    // Secure DNS: when a DoH provider is configured, target hostnames are
    // resolved through it and the plaintext system resolver is never used.
    // Failure is fatal for the request (fail closed), never a silent leak.
    std::string connectTarget = host;
    bool targetIsIp = false;
    std::string guardAddress; // destination address the isolation guard sees
    if (!dohProvider_.empty() && !isIpLiteral(host)) {
        std::string ip;
        if (!dohResolve(host, ip)) {
            lastConnectError_ = "Blocked: secure DNS (DoH) lookup failed for " + host;
            std::cerr << "[lethe-http][doh] " << lastConnectError_ << std::endl;
            return false;
        }
        connectTarget = ip;
        guardAddress = ip;
        targetIsIp = true;
    } else {
        // No DoH for this hop (IP literal, or legacy plaintext-DNS mode):
        // still canonicalize numeric spell-outs ("2130706433", "0177.0.0.1",
        // "0x7f000001") that getaddrinfo happily dials although they look
        // nothing like an address, so isolation sees exactly what would be
        // dialed. AI_NUMERICHOST keeps that purely local.
        const std::string canon = canonicalNumericAddress(host);
        if (!canon.empty()) {
            guardAddress = canon;
            targetIsIp = true;
        }
        // A non-numeric hostname without DoH resolves inside openTcp(); the
        // engine enables DoH by default precisely so every destination is
        // resolved - and therefore guarded - before any connection attempt.
    }

    // Private-network (SSRF) isolation on the RESOLVED destination, before
    // any socket or tunnel exchange. Applies to direct dials and to relayed
    // exchanges alike: a covered destination must not be smuggled through
    // the tunnel into the VPN exit's own private network either.
    if (targetIsIp) {
        const std::string deny =
            privateNetGuard_.check(host, guardAddress);
        if (!deny.empty()) {
            lastConnectError_ = deny;
            std::cerr << "[lethe-http] " << deny << std::endl;
            return false;
        }
    }

    // Built-in VPN routing policy — fail closed on the RESOLVED destination.
    // Evaluating after resolution means hostname destinations get the same
    // protection as IP literals: with a full-tunnel config, nothing leaves
    // the machine while the tunnel is down.
    const bool covered = vpnTunnel_ &&
        vpnTunnel_->shouldRouteThroughVpn(connectTarget);
    kaResolvedTarget_ = connectTarget; // reused conns re-check this
    kaTargetIsIp_ = targetIsIp;
    if (covered && !isVpnActive()) {
        lastConnectError_ = "Blocked: " + host + " (" + connectTarget +
                            ") requires the VPN tunnel (allowed CIDR match) "
                            "but the tunnel is down";
        std::cerr << "[lethe-http] " << lastConnectError_ << std::endl;
        return false;
    }

    // Tunnel UP and destination covered: carry the exchange (plain HTTP
    // or TLS) through the encrypted streaming relay. The resolved IP
    // travels INSIDE the tunnel; no direct TCP connection to the
    // destination is ever opened.
    if (covered && isVpnActive() && relayConfigured()) {
        resetRelayState();
        relayMode_ = true;
        relayTargetHost_ = connectTarget;
        relayTargetPort_ = port;
        std::cout << "[lethe-http] Routing " << host << ":" << port
                  << " through the encrypted tunnel" << std::endl;
        // TLS runs over the pipe too: startTls branches on relayMode_ and
        // uses memory BIOs fed by the relay stream.
        if (scheme == "https") {
            const bool ok = startTls(host);
            if (!ok) {
                lastConnectError_ = !lastConnectError_.empty()
                    ? lastConnectError_
                    : "TLS-over-tunnel handshake failed for " + host;
            }
            return ok;
        }
        return true; // plain HTTP: stream established lazily on first write
    }

    if (!openTcp(connectTarget, port)) {
        if (lastConnectError_.empty()) {
            std::cerr << "[lethe-http] Connect failed to " << host << ":"
                      << port << std::endl;
        }
        return false;
    }

    // Fresh connection: it becomes reusable only after a clean response
    // confirms both sides want keep-alive (finishResponse).
    kaScheme_ = scheme;
    kaHost_ = host;
    kaPort_ = port;
    connectionReusable_ = false;
    connectionReused_ = false;

    if (scheme == "https") {
        return startTls(host); // SNI + certificate name stay the real hostname.
    }
    return true;
}

bool HttpClient::openTcp(const std::string& target, int port) {
    addrinfo hints;
    std::memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* res = nullptr;
    std::string portStr = std::to_string(port);
    int rc = ::getaddrinfo(target.c_str(), portStr.c_str(), &hints, &res);
    if (rc != 0 || !res) {
        std::cerr << "[lethe-http] Address resolution failed for " << target
                  << ": " << gai_strerror(rc) << std::endl;
        return false;
    }

    int connectedFd = -1;
    for (addrinfo* rp = res; rp && connectedFd < 0; rp = rp->ai_next) {
        int fd = ::socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (fd < 0) continue;

        // Non-blocking connect + select to enforce the timeout.
        int flags = fcntl(fd, F_GETFL, 0);
        fcntl(fd, F_SETFL, flags | O_NONBLOCK);

        int crc = ::connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (crc == 0) {
            fcntl(fd, F_SETFL, flags);
            connectedFd = fd;
        } else if (errno == EINPROGRESS) {
            fd_set wfds;
            FD_ZERO(&wfds);
            FD_SET(fd, &wfds);
            timeval tv;
            tv.tv_sec = static_cast<time_t>(ioTimeout_.count() / 1000);
            tv.tv_usec = static_cast<suseconds_t>(ioTimeout_.count() % 1000 * 1000);
            int sel = ::select(fd + 1, nullptr, &wfds, nullptr, &tv);
            if (sel > 0) {
                int soError = 0;
                socklen_t soLen = sizeof(soError);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &soLen) == 0 &&
                    soError == 0) {
                    fcntl(fd, F_SETFL, flags);
                    connectedFd = fd;
                }
            }
        }
        if (connectedFd < 0) {
            ::close(fd);
        }
    }
    ::freeaddrinfo(res);

    if (connectedFd < 0) return false;
    socketFd_ = connectedFd;
    return true;
}

bool HttpClient::startTls(const std::string& tlsHostname) {
#ifdef HAVE_OPENSSL
    usingTls_ = true;

        sslCtx_ = SSL_CTX_new(TLS_client_method());
        if (!sslCtx_) {
            std::cerr << "[lethe-http] Failed to create SSL context" << std::endl;
            closeConnection();
            return false;
        }

        // Version policy: map config codes onto OpenSSL constants.
        // Config uses 0x0303=TLS1.2, 0x0304=TLS1.3 (0x0305 treated as 1.3).
        int minVer = tlsConfig_.getMinVersion();
        SSL_CTX_set_min_proto_version(
            sslCtx_, minVer >= 0x0304 ? TLS1_3_VERSION : TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(sslCtx_, TLS1_3_VERSION);

        // Certificate verification.
        if (tlsConfig_.isVerifyCertificates()) {
            SSL_CTX_set_verify(sslCtx_, SSL_VERIFY_PEER, nullptr);
            const std::string& caPath = tlsConfig_.getCaBundlePath();
            if (!caPath.empty()) {
                if (!SSL_CTX_load_verify_locations(sslCtx_, caPath.c_str(), nullptr)) {
                    std::cerr << "[lethe-http] Failed to load CA bundle: " << caPath
                              << std::endl;
                    SSL_CTX_free(sslCtx_);
                    sslCtx_ = nullptr;
                    closeConnection();
                    return false;
                }
            }
            // Empty caPath => OpenSSL uses the system default store.
        } else {
            SSL_CTX_set_verify(sslCtx_, SSL_VERIFY_NONE, nullptr);
        }

    ssl_ = SSL_new(sslCtx_);
    if (!ssl_) {
        SSL_CTX_free(sslCtx_);
        sslCtx_ = nullptr;
        closeConnection();
        return false;
    }
#ifdef HAVE_OPENSSL
    if (relayMode_) {
        // TLS over the tunnel pipe: memory BIOs instead of a socket fd.
        // SSL_connect/SSL_read/SSL_write move bytes between the pipe and
        // the TLS state machine; certificate verification is unchanged.
        BIO* rbio = BIO_new(BIO_s_mem());
        BIO* wbio = BIO_new(BIO_s_mem());
        if (!rbio || !wbio) {
            if (rbio) BIO_free(rbio);
            if (wbio) BIO_free(wbio);
            closeConnection();
            return false;
        }
        SSL_set_bio(ssl_, rbio, wbio); // ssl_ owns both from here on
        relayRbio_ = rbio;
        relayWbio_ = wbio;

        auto deadline = std::chrono::steady_clock::now() + ioTimeout_;
        while (true) {
            const int rc = SSL_connect(ssl_);
            if (rc == 1) break; // handshake complete
            const int err = SSL_get_error(ssl_, rc);
            if (err == SSL_ERROR_WANT_READ) {
                if (!tlsPumpOut() || !tlsFillRead(3000)) {
                    std::cerr << "[lethe-http] Relay TLS handshake stalled"
                              << std::endl;
                    closeConnection();
                    return false;
                }
            } else if (err == SSL_ERROR_WANT_WRITE) {
                if (!tlsPumpOut()) {
                    closeConnection();
                    return false;
                }
            } else {
                std::cerr << "[lethe-http] Relay TLS handshake failed with "
                          << tlsHostname << " (SSL error " << err << ")"
                          << std::endl;
                closeConnection();
                return false;
            }
            if (std::chrono::steady_clock::now() > deadline) {
                std::cerr << "[lethe-http] Relay TLS handshake timed out"
                          << std::endl;
                closeConnection();
                return false;
            }
        }

        // Pin enforcement applies on the tunnel path exactly as on a
        // direct socket - same chain, same host, same fail-closed rule.
        if (!verifyCertificatePins(tlsHostname)) {
            closeConnection();
            return false;
        }

        const SSL* sslConst = ssl_;
        std::cout << "[lethe-http] TLS established over tunnel with "
                  << tlsHostname << " ("
                  << SSL_get_version(sslConst) << ")" << std::endl;
        return true;
    }
#endif

    SSL_set_fd(ssl_, socketFd_);
    SSL_set_tlsext_host_name(ssl_, tlsHostname.c_str());

        // Enforce the timeout on the underlying socket for the handshake.
        timeval tv;
        tv.tv_sec = static_cast<time_t>(ioTimeout_.count() / 1000);
        tv.tv_usec = static_cast<suseconds_t>((ioTimeout_.count() % 1000) * 1000);
        setsockopt(socketFd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(socketFd_, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    int ok = SSL_connect(ssl_);
    if (ok != 1) {
        int err = SSL_get_error(ssl_, ok);
        std::cerr << "[lethe-http] TLS handshake failed with " << tlsHostname
                  << " (SSL error " << err << ")" << std::endl;
        closeConnection();
        return false;
    }

    if (!verifyCertificatePins(tlsHostname)) {
        closeConnection();
        return false;
    }

    const SSL* sslConst = ssl_;
    std::cout << "[lethe-http] TLS established with " << tlsHostname << " ("
              << SSL_get_version(sslConst) << ")" << std::endl;
    return true;
#else
    std::cerr << "[lethe-http] HTTPS requested but OpenSSL is unavailable"
              << std::endl;
    closeConnection();
    return false;
#endif
}

bool HttpClient::verifyCertificatePins(const std::string& tlsHostname) {
#ifdef HAVE_OPENSSL
    if (!certPinner_ || !certPinner_->hasPins(tlsHostname)) {
        return true; // host carries no pins: nothing to enforce
    }

    // Inspect the full peer chain, leaf first. Standard pinning semantics:
    // a pin may be satisfied by the leaf, an intermediate, or the root.
    // SSL_get_peer_cert_chain includes the leaf on the client side; the
    // explicit leaf fetch covers exotic servers that omit it.
    std::vector<X509*> inspect;
    X509* leaf =
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
        SSL_get1_peer_certificate(ssl_);
#else
        SSL_get_peer_certificate(ssl_);
#endif
    if (leaf) inspect.push_back(leaf);
    if (STACK_OF(X509)* chain = SSL_get_peer_cert_chain(ssl_)) {
        for (int i = 0; i < sk_X509_num(chain); ++i) {
            inspect.push_back(sk_X509_value(chain, i));
        }
    }

    bool matched = false;
    for (X509* cert : inspect) {
        X509_PUBKEY* pk = X509_get_X509_PUBKEY(cert);
        if (!pk) continue;
        unsigned char* der = nullptr;
        const int derLen = i2d_X509_PUBKEY(pk, &der);
        if (derLen <= 0 || !der) continue;
        unsigned char md[EVP_MAX_MD_SIZE];
        unsigned int mdLen = 0;
        const bool hashed =
            EVP_Digest(der, static_cast<size_t>(derLen), md, &mdLen,
                       EVP_sha256(), nullptr) == 1;
        OPENSSL_free(der);
        if (!hashed || mdLen != CertPinner::kDigestSize) continue;

        CertPinner::Digest digest{};
        std::copy(md, md + CertPinner::kDigestSize, digest.begin());
        if (certPinner_->matchesAny(tlsHostname, digest)) {
            matched = true;
            break;
        }
    }
    if (leaf) X509_free(leaf);

    if (!matched) {
        lastConnectError_ = "Blocked: certificate pin mismatch for " +
                            tlsHostname +
                            " (no pinned SPKI found in the peer chain)";
        std::cerr << "[lethe-http] " << lastConnectError_ << std::endl;
        return false;
    }
    std::cout << "[lethe-http] Certificate pin verified for "
              << tlsHostname << std::endl;
    return true;
#else
    (void)tlsHostname;
    return true;
#endif
}

void HttpClient::setVpnRelay(UdpTransport* udpTransport,
                             const std::string& endpointHost,
                             int endpointPort) {
    vpnUdp_ = udpTransport;
    vpnEndpointHost_ = endpointHost;
    vpnEndpointPort_ = endpointPort;
    resetRelayState();
}

void HttpClient::resetRelayState() {
    // Best-effort stream close: the server also reaps streams whose client
    // went silent, so a lost END is not fatal.
    if (relayMode_ && relayEstablished_ && relayConfigured() && vpnTunnel_) {
        std::vector<uint8_t> endFrame =
            vpn::relay::encodeEnd(relayXid_);
        std::vector<uint8_t> ct;
        if (vpnTunnel_->encryptDataPacket(endFrame.data(), endFrame.size(),
                                          ct)) {
            (void)vpnUdp_->sendTo(vpnEndpointHost_, vpnEndpointPort_, ct);
        }
    }
    relayMode_ = false;
    relayTargetHost_.clear();
    relayTargetPort_ = 0;
    relayOpenSent_ = false;
    relayEstablished_ = false;
    relayFailed_ = false;
    relayIn_.clear();
    relayInPos_ = 0;
    relayEof_ = false;
    relayXid_ = 0;
    relayRbio_ = nullptr; // owned by ssl_ once set; freed with it
    relayWbio_ = nullptr;
}

// Send OPEN for this exchange and wait (bounded) for OK / ERR.
bool HttpClient::relayEnsureOpen() {
    if (relayEstablished_) return true;
    if (relayFailed_) return false;
    if (!relayOpenSent_) {
        if (!relayConfigured() || !vpnTunnel_) return false;
        relayXid_ = static_cast<uint32_t>(
            std::chrono::steady_clock::now().time_since_epoch().count());
        std::vector<uint8_t> frame = vpn::relay::encodeOpen(
            relayXid_, relayTargetHost_,
            static_cast<uint16_t>(relayTargetPort_));
        std::vector<uint8_t> ct;
        if (!vpnTunnel_->encryptDataPacket(frame.data(), frame.size(), ct)) {
            return false;
        }
        if (!vpnUdp_->sendTo(vpnEndpointHost_, vpnEndpointPort_, ct)) {
            return false;
        }
        relayOpenSent_ = true;
    }

    // Wait for the connect verdict before any DATA leaves.
    auto deadline = std::chrono::steady_clock::now() +
                    std::chrono::milliseconds(3000);
    while (!relayEstablished_ && !relayFailed_ &&
           std::chrono::steady_clock::now() < deadline) {
        const int waitMs = 250;
        if (!relayConfigured() || !vpnTunnel_) return false;
        std::vector<uint8_t> datagram;
        std::string fh;
        int fp = 0;
        const int n = vpnUdp_->recvFrom(datagram,
                                        std::chrono::milliseconds(waitMs),
                                        fh, fp);
        if (n <= 0) continue;
        std::vector<uint8_t> pt;
        if (!vpnTunnel_->decryptDataPacket(datagram.data(),
                                           static_cast<size_t>(n), pt)) {
            continue;
        }
        vpn::relay::FrameKind kind;
        vpn::relay::OpenFrame openIgnored;
        vpn::relay::DataFrame dataIgnored;
        vpn::relay::IdFrame id;
        if (!vpn::relay::parseFrame(pt, kind, openIgnored, dataIgnored,
                                    id)) {
            continue;
        }
        if (id.xid != relayXid_) continue; // stale exchange
        if (kind == vpn::relay::FrameKind::Ok) {
            relayEstablished_ = true;
        } else if (kind == vpn::relay::FrameKind::Err) {
            relayFailed_ = true;
            std::cerr << "[lethe-http] Relay stream refused by server"
                      << std::endl;
        }
    }
    return relayEstablished_;
}

bool HttpClient::relaySendData(const uint8_t* p, size_t n) {
    if (!relayEnsureOpen()) return false;
    size_t sent = 0;
    while (sent < n) {
        const size_t take =
            std::min<size_t>(n - sent, vpn::relay::kMaxPayloadLen);
        std::vector<uint8_t> frame =
            vpn::relay::encodeData(relayXid_, p + sent, take);
        std::vector<uint8_t> ct;
        if (!vpnTunnel_->encryptDataPacket(frame.data(), frame.size(), ct)) {
            return false;
        }
        if (!vpnUdp_->sendTo(vpnEndpointHost_, vpnEndpointPort_, ct)) {
            return false;
        }
        sent += take;
    }
    return true;
}

bool HttpClient::relaySendEnd() {
    if (!relayConfigured() || !vpnTunnel_) return false;
    std::vector<uint8_t> frame = vpn::relay::encodeEnd(relayXid_);
    std::vector<uint8_t> ct;
    if (!vpnTunnel_->encryptDataPacket(frame.data(), frame.size(), ct)) {
        return false;
    }
    return vpnUdp_->sendTo(vpnEndpointHost_, vpnEndpointPort_, ct);
}

// Pull one frame for the current exchange.
// Returns 1 = DATA appended to relayIn_; 0 = stream ended; -1 = error.
int HttpClient::pullRelayFrame(int timeoutMs) {
    if (!relayConfigured() || !vpnTunnel_ || relayFailed_) return -1;
    std::vector<uint8_t> datagram;
    std::string fh;
    int fp = 0;
    const int n = vpnUdp_->recvFrom(datagram,
                                    std::chrono::milliseconds(timeoutMs),
                                    fh, fp);
    if (n <= 0) return -1; // timeout or socket error
    std::vector<uint8_t> pt;
    if (!vpnTunnel_->decryptDataPacket(datagram.data(),
                                       static_cast<size_t>(n), pt)) {
        return -1;
    }
    vpn::relay::FrameKind kind;
    vpn::relay::OpenFrame openIgnored;
    vpn::relay::DataFrame data;
    vpn::relay::IdFrame id;
    if (!vpn::relay::parseFrame(pt, kind, openIgnored, data, id)) {
        return -1;
    }
    if (id.xid != relayXid_) {
        // Stale datagram from an earlier exchange: skip and keep pulling.
        return pullRelayFrame(timeoutMs);
    }
    if (kind == vpn::relay::FrameKind::Data) {
        relayIn_.insert(relayIn_.end(), data.payload.begin(),
                        data.payload.end());
        return 1;
    }
    if (kind == vpn::relay::FrameKind::End) {
        relayEof_ = true;
        return 0;
    }
    if (kind == vpn::relay::FrameKind::Err) {
        relayFailed_ = true;
        return -1;
    }
    return 2; // unexpected frame kind: tell caller to keep pulling
}

int HttpClient::pullUntilUseful(int timeoutMs) {
    for (int guard = 0; guard < 64; guard++) {
        const int r = pullRelayFrame(timeoutMs);
        if (r != 2) return r;
    }
    return -1;
}

#ifdef HAVE_OPENSSL
// Push whatever TLS queued in the write BIO out as DATA frames.
bool HttpClient::tlsPumpOut() {
    BIO* wbio = static_cast<BIO*>(relayWbio_);
    if (!wbio) return false;
    char buf[vpn::relay::kMaxPayloadLen];
    while (BIO_pending(wbio) > 0) {
        const int n = BIO_read(wbio, buf, sizeof(buf));
        if (n <= 0) return false;
        if (!relaySendData(reinterpret_cast<uint8_t*>(buf),
                           static_cast<size_t>(n))) {
            return false;
        }
    }
    return true;
}

// Pull tunnel frames for this exchange into the read BIO so SSL can retry.
bool HttpClient::tlsFillRead(int timeoutMs) {
    BIO* rbio = static_cast<BIO*>(relayRbio_);
    if (!rbio) return false;
    const int r = pullUntilUseful(timeoutMs);
    if (r < 0) return false;                       // error or hard EOF
    if (!relayIn_.empty()) {
        const size_t avail = relayIn_.size() - relayInPos_;
        BIO_write(rbio, relayIn_.data() + relayInPos_,
                  static_cast<int>(avail));
        relayInPos_ = relayIn_.size();
        relayIn_.clear();
        relayInPos_ = 0;
        return true;
    }
    // END arrived with no pending bytes: nothing more will ever come.
    return relayEof_ ? false : true;
}
#endif

void HttpClient::closeConnection() {
    resetRelayState();
#ifdef HAVE_OPENSSL
    if (ssl_) {
        SSL_shutdown(ssl_);
        SSL_free(ssl_);
        ssl_ = nullptr;
    }
    if (sslCtx_) {
        SSL_CTX_free(sslCtx_);
        sslCtx_ = nullptr;
    }
#endif
    if (socketFd_ >= 0) {
        ::close(socketFd_);
        socketFd_ = -1;
    }
    usingTls_ = false;
    // Nothing buffered belongs to a dead connection; keep-alive identity is
    // meaningless without a live one too.
    ioBuf_.clear();
    ioBufPos_ = 0;
    connectionReusable_ = false;
    kaScheme_.clear();
    kaHost_.clear();
    kaPort_ = 0;
}

// --- Keep-alive connection reuse -------------------------------------------

bool HttpClient::tryReuseConnection(const std::string& scheme,
                                    const std::string& host, int port) {
    if (!connectionReusable_ || socketFd_ < 0) return false;
    // Relay exchanges are single-use by protocol design (OPEN/DATA/END);
    // they never leave a reusable socket behind anyway.
    if (relayMode_) return false;
    if (kaScheme_ != scheme || kaHost_ != host || kaPort_ != port) return false;

    // Policy re-check on EVERY reuse. The connection may predate a VPN
    // state change: a kept-alive socket must never become a plaintext
    // path around the tunnel policy, so a covered destination with the
    // tunnel down fails closed - exactly like a fresh connect would.
    const bool covered = vpnTunnel_ &&
        vpnTunnel_->shouldRouteThroughVpn(kaResolvedTarget_);
    if (covered && !isVpnActive()) {
        lastConnectError_ = "Blocked: " + host + " (" + kaResolvedTarget_ +
                            ") requires the VPN tunnel (allowed CIDR match) "
                            "but the tunnel is down";
        std::cerr << "[lethe-http] " << lastConnectError_ << std::endl;
        closeConnection(); // the stale socket predates the policy change
        return false;
    }

    // Isolation re-check mirrors the VPN one so every entry point into the
    // network path consults the same policy; it is a cheap classification
    // of the address this connection was established to.
    if (kaTargetIsIp_) {
        const std::string deny =
            privateNetGuard_.check(host, kaResolvedTarget_);
        if (!deny.empty()) {
            lastConnectError_ = deny;
            std::cerr << "[lethe-http] " << deny << std::endl;
            closeConnection();
            return false;
        }
    }

    connectionReused_ = true;
    return true;
}

void HttpClient::finishResponse(HttpResponse& resp) {
    // Framing decides - not the status code: a fully-framed redirect or
    // error response leaves the connection exactly as reusable as a 200,
    // while an EOF-delimited body or peer "close" burns it either way.
    const bool fullyFramed =
        !bodyUntilEof_ &&
        peerAllowsKeepAlive_ &&
        !http10Peer_;
    if (fullyFramed && socketFd_ >= 0 && !relayMode_ &&
        relayInPos_ == 0) {
        connectionReusable_ = true;
        return; // socket stays open for the next same-origin request
    }
    closeConnection();
}

// --- Buffered reads ---------------------------------------------------------
//
// One refill per ~16 KiB instead of a select()+recv() pair per byte: header
// lines, chunked framing, and chunk terminators stop dominating response
// time on plain TCP, and bytes that land past a response boundary stay here
// for keep-alive reuse instead of being lost.

int HttpClient::fillIoBuf() {
    ioBuf_.resize(kReadChunkSize);
    const int n = rawRead(ioBuf_.data(), kReadChunkSize);
    if (n <= 0) {
        ioBuf_.clear();
        ioBufPos_ = 0;
        return n;
    }
    ioBuf_.resize(static_cast<size_t>(n));
    ioBufPos_ = 0;
    return n;
}

int HttpClient::bufferedReadByte(uint8_t& out) {
    if (ioBufPos_ >= ioBuf_.size()) {
        const int r = fillIoBuf();
        if (r <= 0) return r;
    }
    out = ioBuf_[ioBufPos_++];
    return 1;
}

bool HttpClient::bufferedReadExact(uint8_t* dst, size_t n) {
    size_t got = 0;
    while (got < n) {
        if (ioBufPos_ >= ioBuf_.size()) {
            const int r = fillIoBuf();
            if (r <= 0) return false; // error, timeout, or premature EOF
        }
        const size_t avail = ioBuf_.size() - ioBufPos_;
        const size_t take = std::min(avail, n - got);
        std::memcpy(dst + got, ioBuf_.data() + ioBufPos_, take);
        ioBufPos_ += take;
        got += take;
    }
    return true;
}

// --- Raw I/O ---

int HttpClient::rawRead(uint8_t* buf, size_t len) {
#ifdef HAVE_OPENSSL
    if (relayMode_ && usingTls_ && ssl_) {
        // TLS over the tunnel pipe: feed peer bytes into the read BIO,
        // then let SSL_read consume them. Pump writes on renegotiations.
        while (true) {
            const int n = SSL_read(ssl_, buf, static_cast<int>(len));
            if (n > 0) return n;
            const int err = SSL_get_error(ssl_, n);
            if (err == SSL_ERROR_ZERO_RETURN) return 0; // clean close
            if (err == SSL_ERROR_WANT_READ) {
                if (!tlsPumpOut()) return -1;
                if (!tlsFillRead(3000)) return -1;
                continue;
            }
            if (err == SSL_ERROR_WANT_WRITE) {
                if (!tlsPumpOut()) return -1;
                continue;
            }
            return -1;
        }
    }
#endif
    if (relayMode_) {
        // Plain HTTP over the pipe: reassemble DATA frames.
        while (relayInPos_ >= relayIn_.size() && !relayEof_) {
            if (!relayEnsureOpen()) return -1;
            if (pullUntilUseful(3000) < 1 && !relayEof_) return -1;
            if (relayEof_) break;
        }
        if (relayInPos_ >= relayIn_.size()) return 0; // stream ended
        const size_t avail = relayIn_.size() - relayInPos_;
        const size_t take = len < avail ? len : avail;
        std::memcpy(buf, relayIn_.data() + relayInPos_, take);
        relayInPos_ += take;
        if (relayInPos_ == relayIn_.size()) {
            relayIn_.clear();
            relayInPos_ = 0;
        }
        return static_cast<int>(take);
    }
    if (socketFd_ < 0) return -1;

#ifdef HAVE_OPENSSL
    if (usingTls_ && ssl_) {
        int n = SSL_read(ssl_, buf, static_cast<int>(len));
        if (n > 0) return n;
        int err = SSL_get_error(ssl_, n);
        if (err == SSL_ERROR_ZERO_RETURN) return 0; // clean close
        if (err == SSL_ERROR_SYSCALL) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return -2;
            if (errno == 0) return 0; // peer closed
            return -1;
        }
        if (err == SSL_ERROR_WANT_READ) return -2; // timeout
        return -1;
    }
#endif

    // Plain TCP with select-based timeout.
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(socketFd_, &rfds);
    timeval tv;
    tv.tv_sec = static_cast<time_t>(ioTimeout_.count() / 1000);
    tv.tv_usec = static_cast<suseconds_t>((ioTimeout_.count() % 1000) * 1000);

    int sel = ::select(socketFd_ + 1, &rfds, nullptr, nullptr, &tv);
    if (sel < 0) {
        if (errno == EINTR) return -2;
        return -1;
    }
    if (sel == 0) return -2; // timeout

    ssize_t n = ::recv(socketFd_, buf, len, 0);
    if (n < 0) {
        if (errno == EINTR) return -2;
        return -1;
    }
    return static_cast<int>(n);
}

bool HttpClient::writeAll(const char* data, size_t len) {
#ifdef HAVE_OPENSSL
    if (relayMode_ && usingTls_ && ssl_) {
        // TLS over the tunnel pipe: encrypt into the write BIO, then push
        // its bytes out as DATA frames.
        size_t total = 0;
        while (total < len) {
            const int n = SSL_write(ssl_, data + total,
                                    static_cast<int>(len - total));
            if (n > 0) {
                if (!tlsPumpOut()) return false;
                total += static_cast<size_t>(n);
                continue;
            }
            const int err = SSL_get_error(ssl_, n);
            if (err == SSL_ERROR_WANT_READ) {
                if (!tlsFillRead(3000)) return false;
                continue;
            }
            std::cerr << "[lethe-http] Relay SSL_write failed (error "
                      << err << ")" << std::endl;
            return false;
        }
        return true;
    }
#endif
    if (relayMode_) {
        // Plain HTTP over the pipe: chunk straight into DATA frames.
        return relaySendData(reinterpret_cast<const uint8_t*>(data), len);
    }
    if (socketFd_ < 0) return false;
    size_t total = 0;
    while (total < len) {
        ssize_t n;
#ifdef HAVE_OPENSSL
        if (usingTls_ && ssl_) {
            n = SSL_write(ssl_, data + total, static_cast<int>(len - total));
            if (n <= 0) {
                std::cerr << "[lethe-http] SSL_write failed (error "
                          << SSL_get_error(ssl_, n) << ")" << std::endl;
                return false;
            }
        } else
#endif
        {
            n = ::send(socketFd_, data + total, len - total, 0);
            if (n < 0) {
                if (errno == EINTR) continue;
                std::cerr << "[lethe-http] send failed: " << strerror(errno)
                          << std::endl;
                return false;
            }
        }
        total += static_cast<size_t>(n);
    }
    return true;
}

bool HttpClient::readLine(std::string& out) {
    out.clear();
    while (true) {
        uint8_t c = 0;
        const int n = bufferedReadByte(c);
        if (n < 0) return false; // error or timeout
        if (n == 0) {
            // EOF: return whatever we have (final line without newline).
            return !out.empty();
        }
        if (c == '\n') {
            if (!out.empty() && out.back() == '\r') out.pop_back();
            return true;
        }
        out += static_cast<char>(c);
        if (out.size() > 65536) return false; // pathological header guard
    }
}

// --- Response parsing ---

bool HttpClient::readFullResponse(HttpResponse& resp) {
    // Framing facts that decide keep-alive eligibility in finishResponse.
    peerAllowsKeepAlive_ = true;
    http10Peer_ = false;
    bodyUntilEof_ = false;

    // Status line: "HTTP/1.1 200 OK"
    std::string statusLine;
    if (!readLine(statusLine)) {
        resp.error = "Failed to read status line";
        return false;
    }
    std::istringstream iss(statusLine);
    std::string httpVersion, reason;
    if (!(iss >> httpVersion >> resp.statusCode >> reason)) {
        resp.error = "Malformed status line: " + statusLine;
        return false;
    }
    http10Peer_ = (httpVersion.rfind("HTTP/1.0", 0) == 0);

    // Headers until the blank line.
    std::string line;
    while (readLine(line) && !line.empty()) {
        size_t colon = line.find(':');
        if (colon != std::string::npos) {
            std::string key = toLowerCopy(trimCopy(line.substr(0, colon)));
            std::string value = trimCopy(line.substr(colon + 1));
            if (key == "set-cookie") {
                // The headers map collapses repeated names; cookies are
                // per-name state and must survive individually.
                resp.setCookieHeaders.push_back(value);
            }
            resp.headers[key] = value;
        }
    }

    const std::string connHeader =
        toLowerCopy(getHeader(resp.headers, "connection"));
    if (connHeader.find("close") != std::string::npos) {
        peerAllowsKeepAlive_ = false; // explicit teardown wins over defaults
    }

    // Body.
    std::string transferEncoding = toLowerCopy(getHeader(resp.headers, "transfer-encoding"));
    std::string contentLengthStr = getHeader(resp.headers, "content-length");

    if (transferEncoding.find("chunked") != std::string::npos) {
        if (!readChunkedBody(resp)) {
            resp.error = "Failed to read chunked body";
            return false;
        }
    } else if (!contentLengthStr.empty()) {
        size_t contentLength = 0;
        try {
            contentLength = std::stoul(contentLengthStr);
        } catch (...) {
            resp.error = "Invalid Content-Length: " + contentLengthStr;
            return false;
        }
        if (!readBodyOfLength(resp, contentLength)) {
            resp.error = "Failed to read body";
            return false;
        }
    } else {
        // No length and no chunking: only EOF delimits the body - the
        // server must close, so this connection is single-use.
        bodyUntilEof_ = true;
        if (!readBodyUntilClose(resp)) {
            resp.error = "Failed to read body";
            return false;
        }
    }

    maybeDecompressBody(resp);

    resp.success = (resp.statusCode >= 200 && resp.statusCode < 300);
    return true;
}

bool HttpClient::readBodyOfLength(HttpResponse& resp, size_t length) {
    resp.body.reserve(std::min(length, kMaxResponseSize));
    size_t remaining = length;
    std::vector<uint8_t> chunk(kReadChunkSize);
    while (remaining > 0) {
        size_t want = std::min(remaining, chunk.size());
        if (!bufferedReadExact(chunk.data(), want)) return false;
        resp.body.insert(resp.body.end(),
                         reinterpret_cast<char*>(chunk.data()),
                         reinterpret_cast<char*>(chunk.data() + want));
        remaining -= want;
        if (resp.body.size() > kMaxResponseSize) {
            std::cerr << "[lethe-http] Response too large, aborting" << std::endl;
            return false;
        }
    }
    return true;
}

bool HttpClient::readChunkedBody(HttpResponse& resp) {
    while (true) {
        // Read the chunk-size line.
        std::string sizeLine;
        if (!readLine(sizeLine)) return false;
        if (sizeLine.empty()) return true; // no more chunks (malformed but done)

        // Strip chunk extensions after ';'.
        size_t semicolon = sizeLine.find(';');
        if (semicolon != std::string::npos) sizeLine = sizeLine.substr(0, semicolon);
        sizeLine = trimCopy(sizeLine);

        size_t chunkSize = 0;
        try {
            chunkSize = std::stoul(sizeLine, nullptr, 16);
        } catch (...) {
            std::cerr << "[lethe-http] Invalid chunk size: " << sizeLine << std::endl;
            return false;
        }

        if (chunkSize == 0) {
            // Trailer section: read until blank line.
            std::string trailer;
            while (readLine(trailer) && !trailer.empty()) {
                // ignore trailers
            }
            return true;
        }

        if (!readBodyOfLength(resp, chunkSize)) return false;

        // Consume the CRLF after each chunk (buffered: two bytes, no
        // per-byte syscalls).
        uint8_t crlf[2] = {0, 0};
        if (!bufferedReadExact(crlf, 2)) return false;
    }
}

bool HttpClient::readBodyUntilClose(HttpResponse& resp) {
    // Drain anything already buffered first so no byte is skipped, then
    // pull straight from the connection until EOF.
    while (ioBufPos_ < ioBuf_.size()) {
        resp.body.push_back(static_cast<char>(ioBuf_[ioBufPos_++]));
        if (resp.body.size() > kMaxResponseSize) {
            std::cerr << "[lethe-http] Response too large, aborting" << std::endl;
            return false;
        }
    }
    std::vector<uint8_t> chunk(kReadChunkSize);
    while (true) {
        const int n = rawRead(chunk.data(), chunk.size());
        if (n < 0) return false; // timeout or error
        if (n == 0) return true; // clean EOF
        resp.body.insert(resp.body.end(),
                         reinterpret_cast<char*>(chunk.data()),
                         reinterpret_cast<char*>(chunk.data() + n));
        if (resp.body.size() > kMaxResponseSize) {
            std::cerr << "[lethe-http] Response too large, aborting" << std::endl;
            return false;
        }
    }
}

void HttpClient::maybeDecompressBody(HttpResponse& resp) {
    std::string encoding = toLowerCopy(getHeader(resp.headers, "content-encoding"));
    if (encoding.empty() || resp.body.empty()) return;

    std::vector<char> out;
    out.reserve(resp.body.size());

    if (encoding.find("gzip") != std::string::npos) {
        z_stream zs;
        std::memset(&zs, 0, sizeof(zs));
        // 15 + 16: window bits + gzip format.
        if (inflateInit2(&zs, 15 + 16) != Z_OK) return;

        zs.next_in = reinterpret_cast<Bytef*>(resp.body.data());
        zs.avail_in = static_cast<uInt>(resp.body.size());

        std::vector<Bytef> buf(kReadChunkSize);
        int ret;
        do {
            zs.next_out = buf.data();
            zs.avail_out = static_cast<uInt>(buf.size());
            ret = inflate(&zs, Z_NO_FLUSH);
            if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR) {
                inflateEnd(&zs);
                return; // not actually gzip; keep original body
            }
            size_t have = buf.size() - zs.avail_out;
            out.insert(out.end(), buf.begin(), buf.begin() + have);
        } while (ret != Z_STREAM_END && zs.avail_in > 0);

        inflateEnd(&zs);
        resp.body = std::move(out);
    } else if (encoding.find("deflate") != std::string::npos) {
        z_stream zs;
        std::memset(&zs, 0, sizeof(zs));
        if (inflateInit2(&zs, 15) != Z_OK) return;

        zs.next_in = reinterpret_cast<Bytef*>(resp.body.data());
        zs.avail_in = static_cast<uInt>(resp.body.size());

        std::vector<Bytef> buf(kReadChunkSize);
        int ret;
        do {
            zs.next_out = buf.data();
            zs.avail_out = static_cast<uInt>(buf.size());
            ret = inflate(&zs, Z_NO_FLUSH);
            if (ret != Z_OK && ret != Z_STREAM_END && ret != Z_BUF_ERROR) {
                inflateEnd(&zs);
                return;
            }
            size_t have = buf.size() - zs.avail_out;
            out.insert(out.end(), buf.begin(), buf.begin() + have);
        } while (ret != Z_STREAM_END && zs.avail_in > 0);

        inflateEnd(&zs);
        resp.body = std::move(out);
    }
}

// --- Navigation request hygiene ---------------------------------------------

HttpClient::HopParts HttpClient::splitHop(const std::string& url) {
    HopParts p;
    parseUrl(url, p.scheme, p.host, p.path, p.port);
    p.host = toLowerCopy(p.host);
    return p;
}

bool HttpClient::hopSameOrigin(const HopParts& a, const HopParts& b) {
    return a.scheme == b.scheme && a.host == b.host && a.port == b.port;
}

std::string HttpClient::hopOrigin(const HopParts& p) {
    std::string origin = p.scheme + "://" + p.host;
    const bool defaultPort =
        (p.scheme == "https" && p.port == 443) ||
        (p.scheme == "http" && p.port == 80);
    if (!defaultPort) origin += ":" + std::to_string(p.port);
    return origin;
}

bool HttpClient::parseReferrerPolicy(const std::string& headerValue,
                                     ReferrerPolicy& out) {
    bool found = false;
    size_t pos = 0;
    while (pos <= headerValue.size()) {
        size_t comma = headerValue.find(',', pos);
        std::string token = trimCopy(toLowerCopy(
            comma == std::string::npos ? headerValue.substr(pos)
                                       : headerValue.substr(pos, comma - pos)));
        // The LAST recognized token wins; unrecognized tokens are skipped
        // so future policy names degrade gracefully instead of erroring.
        if (token == "no-referrer") { out = ReferrerPolicy::NoReferrer; found = true; }
        else if (token == "origin") { out = ReferrerPolicy::Origin; found = true; }
        else if (token == "strict-origin-when-cross-origin") {
            out = ReferrerPolicy::StrictOriginWhenCrossOrigin; found = true;
        }
        else if (token == "unsafe-url") { out = ReferrerPolicy::UnsafeUrl; found = true; }
        if (comma == std::string::npos) break;
        pos = comma + 1;
    }
    return found;
}

std::string HttpClient::deriveFetchSite(const std::string& referrerUrl,
                                        const std::string& targetUrl) {
    if (referrerUrl.empty()) return "none";
    const HopParts r = splitHop(referrerUrl);
    const HopParts t = splitHop(targetUrl);
    if (hopSameOrigin(r, t)) return "same-origin";
    if (r.host == t.host) return "same-site"; // same host, different port
    if (isIpLiteral(r.host) || isIpLiteral(t.host)) {
        return "cross-site"; // no same-site guessing for address literals
    }
    if (!r.host.empty() && lastTwoLabels(r.host) == lastTwoLabels(t.host)) {
        return "same-site";
    }
    return "cross-site";
}

std::string HttpClient::refererForHop(const std::string& referrer,
                                      const std::string& targetUrl,
                                      ReferrerPolicy policy) {
    if (referrer.empty() || policy == ReferrerPolicy::NoReferrer) return "";
    if (policy == ReferrerPolicy::UnsafeUrl) return referrer;

    const HopParts r = splitHop(referrer);
    const HopParts t = splitHop(targetUrl);
    // Every implemented policy withholds a secure page's address from
    // plaintext peers: an https -> http downgrade strips it entirely.
    if (r.scheme == "https" && t.scheme != "https") return "";
    // Origin-only policies (and cross-origin targets under the default
    // policy) reveal only the triggering origin.
    if (policy == ReferrerPolicy::Origin || !hopSameOrigin(r, t)) {
        return hopOrigin(r);
    }
    // Same-origin under strict-origin-when-cross-origin: full URL.
    return referrer;
}

// --- URL / request building ---

void HttpClient::parseUrl(const std::string& url, std::string& scheme,
                          std::string& host, std::string& path, int& port) {
    scheme.clear();
    host.clear();
    path = "/";
    port = 0;

    size_t schemeEnd = url.find("://");
    std::string rest = url;
    if (schemeEnd != std::string::npos) {
        scheme = toLowerCopy(url.substr(0, schemeEnd));
        rest = url.substr(schemeEnd + 3);
    }

    // Split host[:port] from path.
    size_t hostEnd = rest.find('/');
    std::string hostPort = (hostEnd == std::string::npos)
                               ? rest
                               : rest.substr(0, hostEnd);
    if (hostEnd != std::string::npos) {
        path = rest.substr(hostEnd);
    }

    // Split host and explicit port.
    size_t colon = hostPort.find(':');
    if (colon != std::string::npos) {
        host = hostPort.substr(0, colon);
        try {
            port = std::stoi(hostPort.substr(colon + 1));
        } catch (...) {
            port = 0;
        }
    } else {
        host = hostPort;
    }

    // Strip userinfo if present.
    size_t at = host.find('@');
    if (at != std::string::npos) host = host.substr(at + 1);

    // Default ports.
    if (port == 0) {
        if (scheme == "https") port = 443;
        else port = 80;
    }
}

std::string HttpClient::buildHttpRequest(const HttpRequest& req,
                                         const std::string& host,
                                         const std::string& path,
                                         int port,
                                         const std::string& cookieHeader,
                                         const std::string& computedReferer,
                                         const std::string& secFetchSite) {
    (void)port;
    std::string method = "GET";
    switch (req.method) {
        case HttpMethod::GET: method = "GET"; break;
        case HttpMethod::POST: method = "POST"; break;
        case HttpMethod::PUT: method = "PUT"; break;
        case HttpMethod::DELETE: method = "DELETE"; break;
        case HttpMethod::HEAD: method = "HEAD"; break;
        case HttpMethod::PATCH: method = "PATCH"; break;
    }

    // Caller-supplied headers always win: a default is emitted only when
    // the request does not already carry that header (case-insensitive),
    // so custom User-Agent / Accept values actually reach the server.
    auto hasHeader = [&req](const char* name) {
        const std::string lower = toLowerCopy(name);
        for (const auto& h : req.headers) {
            if (toLowerCopy(h.first) == lower) return true;
        }
        return false;
    };

    std::string httpRequest;
    httpRequest += method;
    httpRequest += " ";
    httpRequest += path;
    httpRequest += " HTTP/1.1\r\n";
    httpRequest += "Host: ";
    httpRequest += host;
    httpRequest += "\r\n";
    if (!hasHeader("User-Agent")) {
        httpRequest += "User-Agent: ";
        httpRequest += defaultUserAgent_.empty() ? lethe::USER_AGENT_STRING
                                                : defaultUserAgent_.c_str();
        httpRequest += "\r\n";
    }
    if (!hasHeader("Accept")) {
        httpRequest += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";
    }
    if (!hasHeader("Accept-Language")) {
        httpRequest += "Accept-Language: en-US,en;q=0.5\r\n";
    }
    if (!hasHeader("Accept-Encoding")) {
        httpRequest += "Accept-Encoding: gzip, deflate\r\n";
    }
    // --- Navigation request hygiene ---
    // Computed Referer under the active policy; a caller-supplied
    // Referer header wins outright (same precedence as every default).
    if (!computedReferer.empty() && !hasHeader("Referer")) {
        httpRequest += "Referer: ";
        httpRequest += computedReferer;
        httpRequest += "\r\n";
    }
    // Sec-Fetch-* metadata and Upgrade-Insecure-Requests ride only on
    // top-level user navigations; API-style fetches stay wire-compatible.
    if (req.navigationRequest) {
        if (!hasHeader("Upgrade-Insecure-Requests")) {
            httpRequest += "Upgrade-Insecure-Requests: 1\r\n";
        }
        if (!hasHeader("Sec-Fetch-Site")) {
            httpRequest += "Sec-Fetch-Site: ";
            httpRequest += secFetchSite;
            httpRequest += "\r\n";
        }
        if (!hasHeader("Sec-Fetch-Mode")) {
            httpRequest += "Sec-Fetch-Mode: navigate\r\n";
        }
        if (!hasHeader("Sec-Fetch-Dest")) {
            httpRequest += "Sec-Fetch-Dest: document\r\n";
        }
        if (!hasHeader("Sec-Fetch-User")) {
            httpRequest += "Sec-Fetch-User: ?1\r\n";
        }
    }
    // HTTP/1.1 connections persist by default; say so explicitly unless
    // the caller overrides Connection itself.
    if (!hasHeader("Connection")) {
        httpRequest += "Connection: keep-alive\r\n";
    }

    for (const auto& header : req.headers) {
        httpRequest += header.first;
        httpRequest += ": ";
        httpRequest += header.second;
        httpRequest += "\r\n";
    }
    if (!cookieHeader.empty() && !hasHeader("Cookie")) {
        httpRequest += "Cookie: ";
        httpRequest += cookieHeader;
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

