# Lethe — Custom Browser for Aletheia Platform

[![CI](https://github.com/hotocoo/lethe/actions/workflows/ci.yml/badge.svg)](https://github.com/hotocoo/lethe/actions/workflows/ci.yml)

Minimalist, high-performance browser with maximum security and a built-in VPN, built as the native browser for the Aletheia OS. Lethe's secure network stack is also used by the OS's LLM agent for private, encrypted web searching.

## Status: v0.2.0 (usable, measured, not finished)

Lethe is a working browser you can use day to day, and since 0.2.0 every
performance claim about it is backed by `tools/bench` runs against Google
Chrome on the same machine (see `docs/BENCHMARKS.md`). What exists and works
end to end:

- **Oblivion windows** (⌘⇧N / Ctrl+Shift+N): Lethe's private mode, named for
  the river of forgetting. Own in-memory site-data store wiped when the
  last tab closes, https-only (plaintext refused outright), tracker
  protection forced on, fixed low-entropy user agent, tabs never merge with
  normal windows, dark chrome. A strict superset of the default ephemeral
  session.
- **Built-in tracker protection**: 227 curated advertising / analytics /
  identity hosts blocked as third-party requests inside the engine
  (WebKit content-blocker rules on macOS/Linux, `WebResourceRequested` on
  Windows). First-party never touched. `--no-tracker-block` to compare.
- **HTTPS-first**: top-level `http://` is tried as `https://` first; a
  failed upgrade shows one explicit, labelled plaintext link.
- **Authenticated policy proxy**: the local proxy that carries all engine
  traffic demands a per-launch token, so no other local process can ride
  Lethe's VPN tunnel or policy identity. The browser refuses to start if the
  proxy cannot bind (`--no-proxy` is the explicit opt-out).

- **Native shells**: AppKit + WKWebView on macOS, GTK3 + WebKitGTK on Linux,
  a WebView2 host on Windows. Tabs, address bar with search fallback,
  back/forward/reload/stop, progress, lock indicator, find in page, zoom,
  print, downloads, JavaScript dialogs, file-upload panel, HTTP auth,
  `window.open`/`target=_blank` into new tabs, reader view, block/error
  pages with the refusal reason, security status panel.
- **Policy on every navigation**: DoH-only resolution, private-network
  (SSRF) guard on the RESOLVED address, VPN fail-closed routing - checked off
  the main thread before the engine is allowed to load. On macOS 14+ and on
  Linux, ALL engine traffic additionally rides Lethe's local
  PolicyProxyServer, so subresources are enforced at the transport layer.
- **Ephemeral by default** (`--persistent` to keep site data), no history
  written to disk, macOS Seatbelt profile limiting writes to temp,
  `~/Downloads` and Lethe's own caches.
- Scripted end-to-end checklist (`--e2e-script`, see `docs/E2E.md`) that
  loads real sites, follows links, uses history, opens/closes tabs, renders
  YouTube, gets refused on `169.254.169.254`, and round-trips reader view.

Honest limits (see `docs/COMPARISON.md` for the full audit):

- Inside https, TLS is the platform engine's (system trust store). Lethe's
  TLS 1.3 floor, SPKI pinning and HSTS learning cover reader-mode fetches and
  the proxy's own hops, not WebKit's end-to-end connections.
- Cookies live in the engine's data store (ephemeral unless `--persistent`),
  not Lethe's RFC6265bis memory jar (which serves reader mode and the LLM
  search path).
- Linux: the multi-process WebKit engine cannot run under the engine's
  default-deny seccomp filter (children would inherit it and die); web
  content is sandboxed by WebKitGTK's own bubblewrap + seccomp instead. The
  seccomp filter still guards the reader-only build and the test suite.
- Tracker protection is a curated list of a few hundred hosts, not
  EasyList; `docs/BENCHMARKS.md` shows exactly what it removes.
- No extensions, no sync, no password manager, no bookmarks yet.
- Windows host is a single-view WebView2 window with the navigation gate;
  tabs and the rest of the shell are macOS/Linux only for now.

Prebuilt binaries (macOS DMG, Linux tarballs, Windows exe) are attached to
each GitHub release by `.github/workflows/release.yml`:
https://github.com/hotocoo/lethe/releases

## Features

### Performance
- Rendering is the platform engine's (WebKit / Chromium): hardware
  accelerated, multi-process, the same performance class as Safari/Edge
- Lethe's own stack (reader mode, DoH, proxy hops): HTTP/1.1 keep-alive
  connection reuse with transparent stale-connection retry, buffered
  response parsing, TTL cache for DNS-over-HTTPS answers (measured in
  `docs/COMPARISON.md` with `tools/fetch_bench`)
- Policy checks run off the UI thread; a slow resolver never freezes the
  window
- Small footprint: the macOS app bundle is under 3 MB (OpenSSL is the only
  bundled runtime)

### Security
- **Strict Content Security Policy (CSP)**: No eval(), no inline scripts by default
- **HSTS enforcement (RFC 6797)**: Strict-Transport-Security policy learned
  only over verified HTTPS hops; later plain-http:// requests to covered
  hosts are rewritten to https:// BEFORE any connection attempt - plaintext
  is never put on the wire and there is no insecure fallback
- **Enforced sandboxing**: macOS Seatbelt profile denies file writes outside
  temp, `~/Downloads` and Lethe's own caches; web content runs in WebKit's
  own out-of-process sandbox. Linux: WebKitGTK bubblewrap + seccomp content
  sandbox for web processes; the engine's seccomp-bpf default-deny allowlist
  (~90 syscalls, PR_SET_NO_NEW_PRIVS) guards the reader-only build and the
  whole test suite
- **Hardened build**: `-fstack-protector-strong`, `_FORTIFY_SOURCE=2`, LTO,
  PIE/ASLR from the platform toolchain
- **Secure TLS configuration**: TLS 1.3+, modern cipher suites only,
  certificate verification on by default
- **Certificate pinning**: per-host SPKI SHA-256 pins ("sha256-<base64>",
  HPKP spelling) narrow what a VERIFIED chain may contain — a pinned host
  accepts only chains in which the leaf, an intermediate, or the root
  hashes to a configured pin. Enforcement rides every handshake (direct
  TCP and TLS-over-tunnel alike, redirect hops included) and a mismatch
  fails closed before any HTTP bytes leave; pins are additive to
  verification and never weaken it
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

### Browser shell
- Native per platform: AppKit + WKWebView (macOS), GTK3 + WebKitGTK (Linux),
  WebView2 host (Windows)
- Tabs (native window tabs on macOS, notebook on Linux), address bar with
  search fallback (DuckDuckGo) and fail-closed scheme handling
  (`javascript:`/`data:`/`file:` typed into the bar become searches)
- Back/forward/reload/stop, load progress, https lock indicator, find in
  page, zoom, print, downloads to `~/Downloads`, JavaScript alert/confirm/
  prompt, file-upload chooser, HTTP Basic/Digest prompt
- `window.open` and `target=_blank` open beside the current tab; popups
  need a user gesture
- Reader view (⌘⇧R / Ctrl+Shift+R): the page fetched through lethe_core
  (DoH, HSTS, pins, partitioned cookies) and rendered as clean text with a
  script-free CSP
- Internal pages (blocked, load error, new tab) name the exact reason and
  can never run script
- Security Status panel showing DoH provider, isolation mode, transport
  enforcement, VPN state, data-store mode, sandbox, UA mode

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

- Platforms: **macOS 13+**, **Linux** (glibc, GTK3), Windows for the
  WebView2 host only
- C++20 compiler (Clang 13+ or GCC 11+), CMake >= 3.18, Ninja (recommended)
- OpenSSL >= 3.0, Zlib
- macOS: nothing else (AppKit/WebKit/Network frameworks ship with the OS)
- Linux: `libseccomp-dev`, `libgtk-3-dev`, `libwebkit2gtk-4.1-dev`
  (or `-4.0-dev`); without WebKitGTK the shell builds reader-only
- Windows: WebView2 SDK (`-DWEBVIEW2_DIR=...`), target `lethe-win`

## Building

```bash
# Using the build script (recommended)
./build.sh

# Or manually with ninja
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -G Ninja
ninja lethe lethe_core lethe_tests

# Run the browser
./build/lethe.app/Contents/MacOS/lethe https://example.com      # macOS
./build/lethe https://example.com                               # Linux

# Linux build + headless e2e in a container (no host GTK needed)
docker build -f Dockerfile.linux-build -t lethe-linux .
docker run --rm lethe-linux                                     # unit tests
docker run --rm -e LETHE_WEBKIT_SANDBOX=0 lethe-linux \
  sh -c 'xvfb-run -a ./build-linux/lethe --e2e-script tests/e2e/basic.lethe'
# (LETHE_WEBKIT_SANDBOX=0 only because bubblewrap cannot create namespaces
#  inside an unprivileged container; on a desktop the content sandbox is on)
```

Packaging: `scripts/package_mac_app.sh build` produces a self-contained,
ad-hoc signed `dist/Lethe-<ver>-macos-<arch>.dmg`; `scripts/package_linux.sh`
the Linux tarball.

## Running Tests

```bash
# Run the full test suite (230 tests)
./build/lethe_tests

# Or with ctest
cd build && ctest
```

### Benchmarks

```bash
# Lethe vs Chrome on this machine: startup, page loads, RSS/CPU, YouTube playback
node tools/bench/bench.mjs --browser lethe  --suite startup,pageload,memory,youtube --runs 3
node tools/bench/bench.mjs --browser chrome --suite startup,pageload,memory,youtube --runs 3
# Ablations: same binary, one feature off
node tools/bench/bench.mjs --browser lethe --label lethe-noblock --env LETHE_TRACKER_BLOCK=0
node tools/bench/bench.mjs --browser lethe --label lethe-nocache --env LETHE_DOH_SHARED_CACHE=0
# JS / graphics suites (long)
node tools/bench/bench.mjs --browser lethe --suite speedometer,jetstream,motionmark --runs 1
node tools/bench/report.mjs tools/bench/results        # Markdown tables
```

### End-to-End Verification

Three layers of e2e run for every change:

0. **Browser checklist** (`--e2e-script tests/e2e/basic.lethe`, docs/E2E.md):
   the shell drives itself against real sites and asserts what the user
   would see - exit code 0 means the release checklist held.

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
- **Certificate pinning** (pin spelling parse/format round trips incl.
  padded and unpadded base64, malformed rejection at configuration time,
  case-insensitive exact-host matching with strict no-match for unpinned
  hosts, multi-pin OR semantics; e2e: a correct leaf pin admits a verified
  TLS 1.3 connection while any other digest fails closed BEFORE the HTTP
  request is sent - origins count zero requests - and pins re-arm per
  redirect hop by that hop's own host name, blocking a chain whose second
  hop violates its pin even when the first hop was correctly pinned)
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
- `src/renderer/` — Reader-mode extraction, internal page templates
- `src/ui/mac/` — macOS shell (AppKit + WKWebView, ObjC++)
- `src/ui/` — Linux shell (GTK3 + WebKitGTK), Cairo reader fallback, e2e driver
- `src/win/` — Windows WebView2 host
- `browser/app/` — Entry points (`main_mac.mm`, `main.cc`) and Info.plist
- `tests/e2e/` — Scripted browser checklists
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
export LETHE_CERT_PINS="api.corp=sha256-<base64>,sha256-<base64>;vpn.corp=sha256-<base64>"
```

Environment is applied first; explicit command-line flags always win over it.

Command line:

```bash
lethe [url-or-search]            # Open URL / search (new-tab page if omitted)
lethe --persistent               # Keep cookies and site data between runs
lethe --incognito                # Ephemeral data store (default)
lethe --no-proxy                 # Navigation gate only; skip the local policy proxy
lethe --disable-sandbox          # Disable sandboxing (dangerous!)
lethe --dns-provider URL         # DNS-over-HTTPS provider URL
lethe --e2e-script FILE          # Scripted session, exit 0/1 (docs/E2E.md)
```

## License

Apache-2.0

