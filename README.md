# Lethe — Custom Browser for Aletheia Platform

Minimalist, high-performance browser with maximum security and a built-in VPN, built as the native browser for the Aletheia OS. Lethe's secure network stack is also used by the OS's LLM agent for private, encrypted web searching.

## Features

### Performance
- **Single-process architecture**: Combined browser/renderer for reduced overhead
- **Hardware-accelerated rendering**: Full GPU pipeline via Skia
- **Optimized memory management**: Custom allocator with strict limits
- **Fast startup**: Precompiled components, minimal warm-up time
- **Efficient network stack**: Connection pooling, HTTP/1.1 with keep-alive

### Security
- **Strict Content Security Policy (CSP)**: No eval(), no inline scripts by default
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

- **Structured search results**: Title, URL, snippet, relevance score
- **Readable page extraction**: HTML stripped to clean text for the LLM
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

- **Native browser control**: Open, navigate, read content
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
- **Incognito by default**: Temporary browsing session with auto-purge on exit
- **DNS over HTTPS (DoH)**: Encrypted DNS queries via Cloudflare/DNS-over-HTTPS providers
- **VPN encryption**: All traffic can be encrypted through the built-in tunnel

### Minimal UI
- Clean, distraction-free interface with focus mode
- Tab bar only when needed (auto-hide)
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
# Run the full test suite (77 tests)
./build/lethe_tests

# Or with ctest
cd build && ctest
```

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
- **DNS over HTTPS** (mock-provider end-to-end, dead-provider fail-closed, IP-literal bypass)
- **Sandbox enforcement** (workspace write denied, temp write allowed under the live profile)
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
- `include/` — Public headers by domain
- `tests/` — Test suite (lightweight framework, no external deps)

## Configuration

Environment variables:

```bash
export LETHE_SANDBOX=1          # Enable renderer sandboxing (default: 1)
export LETHE_DNS_PROVIDER="https://cloudflare-dns.com"
export LETHE_USER_AGENT_MODE="standard|stealth"
```

Command line:

```bash
lethe [url]                     # Open URL (or new window if omitted)
lethe --incognito                # Force incognito mode
lethe --disable-sandbox          # Disable sandboxing (dangerous!)
lethe --dns-provider URL         # DNS-over-HTTPS provider URL
```

## License

Apache-2.0

