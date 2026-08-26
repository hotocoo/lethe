# Lethe — Custom Browser for Aletheia Platform

[![CI](https://github.com/hotocoo/lethe/actions/workflows/ci.yml/badge.svg)](https://github.com/hotocoo/lethe/actions/workflows/ci.yml)

Minimalist, high-performance browser with maximum security and a built-in VPN, built as the native browser for the Aletheia OS. Lethe's secure network stack is also used by the OS's LLM agent for private, encrypted web searching.

## Features

### Performance
- **Single-process architecture**: Combined browser/renderer for reduced overhead
- **Renderer abstraction**: software pipeline today with a hardware-accelerated
  backend hook and automatic fallback
- **Optimized memory management**: Custom allocator with strict limits
- **Fast startup**: Precompiled components, minimal warm-up time
- **Efficient network stack**: HTTP/1.1 keep-alive connection reuse with
  transparent stale-connection retry, buffered response parsing, and a TTL
  cache for DNS-over-HTTPS answers

### Security
- **Strict Content Security Policy (CSP)**: No eval(), no inline scripts by default
- **HSTS enforcement (RFC 6797)**: Strict-Transport-Security policy learned
  only over verified HTTPS hops; later plain-http:// requests to covered
  hosts are rewritten to https:// BEFORE any connection attempt - plaintext
  is never put on the wire and there is no insecure fallback
- **Enforced sandboxing**: macOS Seatbelt profile denies file writes outside
  temp locations; Linux seccomp-bpf default-deny allowlist (~90 syscalls)
  with PR_SET_NO_NEW_PRIVS — the whole suite runs under the active sandbox
- **Network isolation**: Per-tab network namespaces for multi-instance sessions
- **Memory protection**: ASLR, DEP, stack canaries, heap metadata separation
- **Secure TLS configuration**: TLS 1.3+, modern cipher suites only,
  certificate verification on by default
- **DNS over HTTPS (DoH)**: hostname resolution through a DoH JSON provider
  (Cloudflare by default); plaintext system DNS is never used for targets,
  and DoH failures block requests instead of leaking (fail closed)
- **SameSite cookie enforcement (RFC6265bis)**: Lax-by-default delivery -
  cookies are withheld from every cross-site request except safe-method
  top-level navigations; Strict cookies never cross sites; SameSite=None
  is accepted only together with Secure. The __Secure- and __Host- name
  prefixes are enforced at storage time (__Host- additionally demands an
  https origin, no Domain attribute, and an explicit Path=/), and a
  rejected Set-Cookie can neither plant nor delete stored state
- **Navigation request hygiene**: the Referer of every hop is computed
  under the active Referrer-Policy (browser-standard
  strict-origin-when-cross-origin by default) - full URL same-origin,
  origin-only cross-origin, stripped entirely on https->http downgrades;
  Sec-Fetch-Site/Mode/Dest/User metadata and Upgrade-Insecure-Requests
  ride on top-level navigations; a fail-closed allowlist refuses every
  non-http(s) URL scheme before any network I/O, redirect targets included
- **Private-network isolation (SSRF guard)**: every hop's RESOLVED
  destination address - DoH answer, IP literal, or numeric spelling-out -
  is scope-classified BEFORE any socket is opened and before the tunnel
  relay path is chosen; non-loopback private scopes (RFC1918, CGNAT,
  link-local incl. cloud-metadata endpoints, IPv6 ULA, NAT64/6to4/
  IPv4-mapped wrappers embedding private space, TEST-NET/benchmarking/
  multicast/reserved ranges) fail closed with named reasons; numeric
  spell-outs like http://2130706433/ are canonicalized through the dialing
  resolver so they cannot dodge the check; loopback stays reachable for
  local development and trusted intranet names can be re-admitted via
  LETHE_PRIVATE_NET_ALLOW
- **Built-in VPN**: WireGuard-style encrypted tunnel for all traffic

### Built-in VPN
Lethe ships with a fully integrated VPN client, so privacy is always available without third-party apps.

- **WireGuard-style cryptography**:
  - X25519 ECDH for key exchange
  - ChaCha20-Poly1305 AEAD for packet encryption
  - HMAC-SHA256 / HKDF-SHA256 for indexing and key derivation
- **Forward secrecy**: Ephemeral keys per handshake, cleared after use
- **Tamper detection**: Every packet authenticated; tampered packets rejected
- **Anti-replay**: Explicit 64-bit wire counter with a 2048-packet sliding
  window (WireGuard-standard) — duplicates, retransmissions, and too-old
  packets are rejected before decryption; failed authentication never
  moves the window
- **Session lifetime limits**: WireGuard REJECT_AFTER_TIME semantics —
  sessions expire after 180s and refuse data until rekeyed; message-count
  exhaustion (REJECT_AFTER_MESSAGES) is also enforced
- **Flexible routing with fail-closed policy**: CIDR-based allowed IPs
  (split or full tunnel). Destinations covered by the tunnel's CIDRs are
  **blocked, never leaked in plaintext**, while the tunnel is down — the
  HTTP client refuses them until the VPN reconnects
- **Real handshakes + self-maintenance**: the engine performs genuine UDP
  handshakes against the VPN server and transparently rekeys at 2/3 of the
  session lifetime (WireGuard REKEY_AFTER_TIME), retries unreachable
  endpoints with backoff, and sends 25s keepalives to hold NAT mappings
- **MTU enforcement**: Standard 1420-byte WireGuard MTU
- **DNS over VPN**: Route DNS through the tunnel for leak-free resolution
- **HTTP/HTTPS over the tunnel**: destinations covered by an UP tunnel
  are carried as encrypted streaming relay exchanges — the engine never
  opens direct TCP to covered hosts while the session is live. TLS runs
  over the pipe too (memory-BIO handshake inside the stream), with normal
  certificate verification against the system store or a configured CA
  bundle

```cpp
// Enable the built-in VPN
lethe::vpn::VpnConfig vpnCfg;
vpnCfg.endpointHost = "vpn.aletheia.os";
vpnCfg.endpointPort = 51820;
vpnCfg.serverPublicKey = serverPubKey;
vpnCfg.allowedCidrs = {"0.0.0.0/0"};  // Full tunnel
engine.enableVpn(vpnCfg);
```

#### Reference VPN Server & Network Transport
The built-in VPN ships with a real UDP network transport layer and a runnable
reference server, so the tunnel works end-to-end (not just in-process).

- **UDP transport** (`UdpTransport`): portable POSIX UDP sockets (IPv4/IPv6) with
  timeouts and a `sendAndReceive()` helper for handshake-style exchanges.
- **Reference server** (`lethe-vpn-server`): a standalone UDP server that performs
  WireGuard-style handshakes with any number of clients and maintains per-client
  tunnels with independent data keys.
- **Server DoS hardening**: per-source-host handshake rate limiting
  (16 per 10s by default), a concurrent-client cap (1024), and idle-client
  eviction (180s) — rejected handshakes are dropped silently so they cannot
  be amplified, and the rate-tracking map is memory-bounded.

```bash
# Start the reference VPN server (generates and prints a key if none given)
./build/lethe-vpn-server --host 0.0.0.0 --port 51820

# Verify with the end-to-end client (uses the server's printed public key)
./build/lethe-vpn-e2e-client --host 127.0.0.1 --port 51820 --server-pub <hex>
```

#### Live HTTP/HTTPS Fetching
The `HttpClient` performs genuine network I/O — no stubs:

- **TCP** connect with timeouts (IPv4/IPv6 via `getaddrinfo`)
- **TLS** handshake via OpenSSL (SNI, version policy, certificate verification)
- **HTTP/1.1** request writing and full response parsing
- **Content-Length**, **chunked transfer-encoding**, and read-until-close bodies
- **gzip/deflate** response decompression (zlib)
- **Redirect following** (3xx + `Location`, up to 5 hops)

```cpp
lethe::TLSConfig tls;                 // TLS 1.3+, verifies certs by default
lethe::HttpClient client;
client.initialize(tls);
lethe::HttpRequest req;
req.url = "https://example.com";
auto resp = client.sendRequest(req);  // real socket I/O
```

### LLM Search Integration
The Aletheia OS LLM uses Lethe's network stack for web access, ensuring all AI-driven searches are private and encrypted.

- **Structured search results**: Title, URL, snippet, relevance score —
  titles arrive entity-decoded, snippets are extracted from the result
  block, and navigation noise (empty/same-engine anchors) is filtered
- **Readable page extraction**: HTML stripped to clean text for the LLM
- **Agent-grade caching**: successful page reads and identical search
  queries are memoized briefly (TTL + LRU bound) so agent re-reads never
  touch the network; browser navigation always fetches fresh documents
- **VPN-routed by default**: LLM searches go through the built-in VPN
- **No telemetry**: Zero tracking of LLM queries

```cpp
// The OS LLM calls this to search the web
auto results = bridge.llmWebSearch("quantum computing breakthroughs");

// Or read a specific page
auto page = bridge.llmReadPage("https://example.com/article");
```

### Aletheia OS Integration
Lethe is the native browser of the Aletheia OS, exposed through a unified bridge API.

- **Native browser control**: `openUrl`/`navigate` are real page loads —
  each document is fetched through Lethe's secure stack (DoH resolution +
  VPN fail-closed policy), the fetched title lands in tab state, the
  readable text is cached per tab for the OS, and history records only
  successful visits outside incognito
- **Session back/forward**: `goBack`/`goForward` traverse PER-TAB history
  through the same secure-stack pipeline — tabs never share paths — the
  cursor moves only when the target actually loads, traversal is never
  re-recorded, a new navigation from the past truncates the forward
  branch, and a traversal blocked by the VPN policy fails closed without
  moving anything
- **VPN control**: Enable/disable the built-in VPN from the OS
- **LLM search**: The OS LLM accesses the web through Lethe
- **Status reporting**: Real-time browser and VPN status

```cpp
// The Aletheia OS uses this bridge
lethe::aletheia::AletheiaBridge bridge(&engine);
bridge.openUrl("https://aletheia.os");
bridge.enableVpn(vpnCfg);
auto results = bridge.llmWebSearch("aletheia os features");
```

### Privacy
- **No telemetry or tracking**: Zero external analytics
- **Cookie partitioning**: Isolated cookie storage per top-level origin
  (memory-only jar; cookies never touch disk and are purged on exit)
- **Incognito by default**: Temporary browsing session with auto-purge on exit
- **Stealth user agent**: optional fixed low-entropy UA profile that reveals
  neither the platform nor any browser identity (`LETHE_USER_AGENT_MODE=stealth`)
- **DNS over HTTPS (DoH)**: Encrypted DNS queries via Cloudflare/DNS-over-HTTPS providers
- **VPN encryption**: All traffic can be encrypted through the built-in tunnel

### Minimal UI
- Clean, distraction-free interface with focus mode (**Ctrl+Shift+F**
  hides the address entry and menu button until toggled again)
- Tab bar only when needed (the strip hides entirely while a single tab is open)
- No extensions or plugins — pure web rendering

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Aletheia OS                          │
│  ┌─────────────┐  ┌─────────────┐  ┌───────────────┐   │
│  │  LLM Agent  │  │  OS Shell   │  │  System Apps  │   │
│  └──────┬──────┘  └──────┬──────┘  └───────┬───────┘   │
│         │                 │                  │           │
│         └─────────────────┼──────────────────┘           │
│                           ▼                              │
│              ┌─────────────────────────┐                 │
│              │    AletheiaBridge       │                 │
│              │  (native browser API)   │                 │
│              └────────────┬────────────┘                 │
│                           ▼                              │
│  ┌─────────────────────────────────────────────────┐    │
│  │                   Lethe Engine                  │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────────┐  │    │
│  │  │  Browser │  │ Renderer │  │   Network    │  │    │
│  │  │  State   │  │  (Skia)  │  │   Stack      │  │    │
│  │  └──────────┘  └──────────┘  └──────┬───────┘  │    │
│  │                                      │          │    │
│  │  ┌──────────────┐  ┌──────────────┐  │          │    │
│  │  │  Built-in    │  │  LLM Search  │◄─┘          │    │
│  │  │  VPN Tunnel  │  │   Service    │              │    │
│  │  └──────────────┘  └──────────────┘              │    │
│  └─────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────┘
```

## Build Requirements

- Platforms: **Linux and macOS** (portable POSIX sockets; sandboxing uses
  Seatbelt on macOS and seccomp-bpf on Linux — Windows is not supported)
- Linux only: `libseccomp` development files (`libseccomp-dev` on
  Debian/Ubuntu, `libseccomp-devel` on Fedora) — required by the enforced
  sandbox; the build fails loudly without them
- C++20 compiler (Clang 13+ or GCC 11+)
- CMake >= 3.18
- OpenSSL >= 3.0 (for VPN cryptography and TLS)
- Zlib
- Ninja build system (recommended)
- Optional: Qt6 or GTK3 (for GUI)

## Building

```bash
# Using the build script (recommended)
./build.sh

# Or manually with ninja
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -G Ninja
ninja lethe_core lethe_tests
```

## Running Tests

```bash
# Run the full test suite (191 tests)
./build/lethe_tests

# Or with ctest
cd build && ctest
```

### End-to-End Verification

Two layers of e2e run for every change — locally and in CI:

1. **Full-stack suite** (inside `lethe_tests`): browser-grade navigation e2e
   against real local origins — mock DoH, real TCP/HTTP servers, real TLS 1.3
   servers whose certificates chain to an engine-provided CA bundle, and page
   loads pushed THROUGH the encrypted tunnel with exact fetch accounting.
2. **Deployment-path sim**: `scripts/e2e_vpn_loopback.sh` starts the standalone
   `lethe-vpn-server` binary, points the standalone `lethe-vpn-e2e-client`
   binary at it over real loopback UDP, and asserts that a genuine handshake
   completes and the server decrypts the client's encrypted payload:

   ```bash
   ./scripts/e2e_vpn_loopback.sh [host] [port]   # defaults: 127.0.0.1 15182
   ```

CI (`.github/workflows/ci.yml`) builds and runs both layers on Linux
(gcc + clang; one job also compiles the GTK3 GUI target) and macOS, plus an
ASan+UBSan build of the entire suite.

The test suite covers:
- VPN cryptography (X25519, ChaCha20-Poly1305, HMAC, HKDF)
- VPN tunnel handshake (loopback client-server)
- VPN data path (bidirectional encryption/decryption)
- Tamper detection and MTU enforcement
- **Anti-replay window** (duplicates, reordering, window expiry, auth-failure neutrality)
- **Session lifetime expiry** (REJECT_AFTER_TIME)
- **Server DoS hardening** (idle eviction, client cap, handshake rate limiting)
- **Engine VPN networking** (real UDP handshake, transparent rekey, unreachable-endpoint endurance)
- **HTTP fail-closed policy** (VPN-routed destinations blocked while the tunnel is down)
- CIDR routing
- **UDP transport** (real loopback sockets: bind, send/recv, timeouts)
- **Reference VPN server over real UDP** (handshake, data path, multi-client, tamper rejection)
- **Live HTTP fetching** (real TCP: GET, POST, headers, gzip, redirects, errors)
- **Live HTTPS fetching** (real TLS 1.3 handshake with a self-signed cert server)
- **Live LLM search** (SearchService web search + page read over real HTTP)
- **Full-stack e2e** (Bridge -> LLM search -> DoH resolution -> VPN policy -> origin, with tunnel up and down)
- **Browser-grade navigation e2e** (bridge openUrl/navigate really fetch:
  title extraction into tab state, cached reader text with zero refetch,
  tunnel-down navigation blocked with zero origin hits then recovery when
  the same tunnel comes up, incognito vs persistent history)
- **Redirect-aware navigation e2e** (relative 301 Location resolved by the
  client; tab URL, title, cache key, and history all land on the final URL)
- **Multi-tab isolation e2e** (per-tab reader cache: switching tabs serves
  each document from its own cache with zero extra fetches, no cross-talk)
- **HTTPS navigation e2e** (real TLS 1.3 origin whose certificate chains to
  an engine-provided CA bundle - Config.caBundlePath - with verification
  kept fully on)
- **Back/forward navigation e2e** (traversals refetch through DoH with
  exact fetch accounting; forward-branch truncation on fresh navigation;
  a traversal blocked by a downed tunnel fails closed with zero origin
  hits, cursor and tab restored, then succeeds once the tunnel returns)
- **Navigation history unit semantics** (cursor model: edges, peeks,
  forward-branch truncation, 1000-entry cap keeping the most recent)
- **Cross-tab history isolation e2e** (back in one tab never lands on
  another tab's page; sibling tabs' state untouched by traversals)
- **CSP decision semantics** ('self' matches only with a document origin
  and only up to a path boundary - example.org.evil.io fails; originless
  'self' fails closed; script-scheme URIs denied; host names containing
  "eval" no longer falsely blocked; policy string built from directives)
- **HSTS (RFC 6797)** (policy cache semantics: exact + includeSubDomains
  matching with label-boundary checks, max-age=0 revocation, expiry,
  IP-literal refusal, capacity bound; STS header parsing incl. malformed
  rejection; e2e: learned policy upgrades plain-http:// before connect with
  the request landing on the TLS origin only, control run without policy
  fails closed against a TLS-only origin, STS received over plain HTTP is
  ignored)
- **SameSite + cookie name prefixes (RFC6265bis)** (None-without-Secure
  rejected at store time AND on the wire; Lax/Strict/unspecified matrix -
  top-level safe-method GET rides cross-site while POST and subresource
  fetches stay home and an initiator-less navigation delivers everything;
  case-insensitive attribute values and prefix matching; __Secure- needs
  Secure plus https, __Host- needs host-only plus explicit Path=/; a
  rejected Set-Cookie cannot delete a conforming cookie it collides with)
- **Navigation request hygiene** (Referer computed per hop under
  Referrer-Policy: full URL same-origin, origin-only cross-origin,
  stripped on https->http downgrades; response Referrer-Policy headers
  governing later redirect hops with last-known-token-wins parsing;
  Sec-Fetch-Site derivation incl. same-site port rule and IP-literal
  handling; navigation-only Sec-Fetch/UIR emission with caller-header
  precedence; fail-closed scheme allowlist blocking ftp/file/javascript/
  data/scheme-less URLs before any I/O and refusing foreign-scheme
  redirect targets)
- **Private-network isolation** (IPv4/IPv6 scope classifier matrix incl.
  IPv4-mapped/NAT64/6to4/compat embedded addresses; guard decisions with
  per-host allowlist, loopback toggle, master switch and fail-closed on
  unclassifiable destinations; resolver-authoritative canonicalization of
  numeric spell-outs across glibc vs Apple leading-zero semantics; e2e:
  named-private, redirect-to-private, and metadata-endpoint hops blocked
  after resolution with zero origin hits while ordinary loopback
  navigation through mock DoH keeps working)
- **Tunnel relay framing** (request/chunk encode+parse round trips,
  malformed rejection, exchange-id staleness filtering)
- **Streaming HTTP relay over real UDP** (OPEN/DATA/END frames with
  exchange ids: client tunnel -> reference server -> TCP origin ->
  encrypted frames back; multi-exchange sessions; unreachable targets
  answer ERR; client END half-closes so origins can still respond;
  disabled relay passes payloads to the data callback verbatim)
- **HTTPS tunneled navigation e2e** (certificate-verified TLS 1.3 running
  INSIDE the encrypted relay stream: DoH resolution + memory-BIO
  handshake + CA-bundle trust + exactly one relayed request and zero
  direct origin connections)
- **Tunneled navigation e2e** (bridge fetches a page THROUGH the encrypted
  tunnel: exactly one relayed request, zero direct client connections to
  the origin, DoH-only mock untouched; disabling the relay on the server
  makes further covered navigations fail closed - no plaintext fallback)
- **Authenticate-first server dispatch** (known-session datagrams decrypt
  before any handshake parsing, so ciphertext can never masquerade as an
  Init and swallow traffic; genuine rekeys from known addresses fall back
  to handshake handling)
- **LLM text extraction entities** (&amp;, &quot;, &nbsp; decoded in pages)
- **Reader-mode rendering** (HTML block extraction: titles, headings, lists, entities)
- **DNS over HTTPS** (mock-provider end-to-end, dead-provider fail-closed, IP-literal bypass)
- **Sandbox enforcement** (workspace write denied, temp write allowed under the live profile)
- **HTTP keep-alive** (one connection for repeat fetches, Connection: close
  honored, stale idle connections retried transparently once, redirect hops
  staying on one connection)
- **Keep-alive vs. VPN policy** (a reused connection fails closed when the
  tunnel drops - kept-alive sockets can never bypass the tunnel policy)
- **DoH answer cache** (repeat hostnames resolve once; TTL expiry and
  provider-change invalidation)
- **LLM page/query caches** (repeat reads without network; readPageFresh
  always fetches; LRU eviction; clearCaches)
- **Result parsing quality** (entity-decoded titles, extracted snippets,
  navigation noise and duplicate URLs filtered)
- **Partitioned cookie jar** (per-top-level-site isolation, host-only vs
  Domain scoping, path rules, Secure/HttpOnly, Max-Age and Expires handling,
  capacity bound, full wire round trip through HttpClient including a
  foreign-partition non-leak check and explicit-Cookie-header precedence)
- **Environment configuration** (LETHE_SANDBOX / LETHE_DNS_PROVIDER /
  LETHE_USER_AGENT_MODE accepted values, unknown-value fallbacks, untouched
  defaults when unset; standard vs stealth UA resolution)
- Engine VPN integration
- LLM search service
- Aletheia OS bridge

## Structure

- `src/core/` — Core engine initialization, process management, VPN control
- `src/browser/` — Browser state management (tabs, windows)
- `src/security/` — Content policies, sandboxing, TLS config
- `src/network/` — Network stack (HTTP/HTTPS, DoH)
- `src/network/vpn/` — Built-in VPN (WireGuard-style crypto, tunnel)
- `src/llm/` — LLM search service (web search, page reading)
- `src/aletheia/` — Aletheia OS integration bridge
- `src/renderer/` — Renderer process bindings (Skia + GPU)
- `src/ui/` — User interface (Qt6/GTK3)
- `browser/app/` — Main application entry point
- `tools/` — Standalone reference VPN server and e2e verification client
- `scripts/` — End-to-end verification scripts (used locally and by CI)
- `include/` — Public headers by domain
- `tests/` — Test suite (lightweight framework, no external deps)

## Configuration

Environment variables:

```bash
export LETHE_SANDBOX=1          # 0/false/off/no disables sandboxing
export LETHE_DNS_PROVIDER="https://cloudflare-dns.com"   # none/off = disable DoH
export LETHE_USER_AGENT_MODE="standard|stealth"
export LETHE_PRIVATE_NET_MODE="isolate"   # open = disable SSRF isolation
export LETHE_PRIVATE_NET_ALLOW="intranet.corp,print.server"  # guard exceptions
```

Environment is applied first; explicit command-line flags always win over it.

Command line:

```bash
lethe [url]                     # Open URL (or new window if omitted)
lethe --incognito                # Force incognito mode
lethe --disable-sandbox          # Disable sandboxing (dangerous!)
lethe --dns-provider URL         # DNS-over-HTTPS provider URL
```

## License

Apache-2.0

