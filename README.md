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
- **Process sandboxing**: Renderer isolated with seccomp-bpf (Linux) / platform sandbox (macOS)
- **Network isolation**: Per-tab network namespaces for multi-instance sessions
- **Memory protection**: ASLR, DEP, stack canaries, heap metadata separation
- **Secure TLS configuration**: TLS 1.3+, modern cipher suites only
- **Built-in VPN**: WireGuard-style encrypted tunnel for all traffic

### Built-in VPN
Lethe ships with a fully integrated VPN client, so privacy is always available without third-party apps.

- **WireGuard-style cryptography**:
  - X25519 ECDH for key exchange
  - ChaCha20-Poly1305 AEAD for packet encryption
  - HMAC-SHA256 / HKDF-SHA256 for indexing and key derivation
- **Forward secrecy**: Ephemeral keys per handshake, cleared after use
- **Tamper detection**: Every packet authenticated; tampered packets rejected
- **Flexible routing**: CIDR-based allowed IPs (split or full tunnel)
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
# Run the full test suite (37 tests)
./build/lethe_tests

# Or with ctest
cd build && ctest
```

The test suite covers:
- VPN cryptography (X25519, ChaCha20-Poly1305, HMAC, HKDF)
- VPN tunnel handshake (loopback client-server)
- VPN data path (bidirectional encryption/decryption)
- Tamper detection and MTU enforcement
- CIDR routing
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

