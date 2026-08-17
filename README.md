
# Lethe — Custom Browser for Aletheia Platform

Minimalist, high-performance browser with maximum security built on Chromium engine.

## Features

### Performance
- **Single-process architecture**: Combined browser/renderer for reduced overhead
- **Hardware-accelerated rendering**: Full GPU pipeline via Skia
- **Optimized memory management**: Custom allocator with strict limits
- **Fast startup**: Precompiled components, minimal warm-up time

### Security
- **Strict content Security Policy (CSP)**: No eval(), no inline scripts by default
- **Process sandboxing**: Renderer isolated with seccomp-bpf/pledge/unveil
- **Network isolation**: Per-tab network namespaces for multi-instance sessions
- **Memory protection**: ASLR, DEP, stack canaries, heap metadata separation
- **Secure TLS configuration**: TLS 1.3+, modern cipher suites only

### Privacy
- **No telemetry or tracking**: Zero external analytics
- **Cookie partitioning**: Isolated cookie storage per top-level origin
- **Incognito by default**: Temporary browsing session with auto-purge on exit
- **DNS over HTTPS (DoH)**: Encrypted DNS queries via Cloudflare/DNS-over-HTTPS providers

### Minimal UI
- Clean, distraction-free interface with focus mode
- Tab bar only when needed (auto-hide)
- No extensions or plugins — pure web rendering

## Build Requirements

- C++20 compiler (Clang 13+ or GCC 11+)
- CMake >= 3.18
- Chromium source tree (optional, can use prebuilt SDK)
- Ninja build system (recommended)

## Building

```bash
# Using ninja (recommended)
./build.sh -G Ninja

# Using standard make
./build.sh
```

Or manually:

```bash
mkdir -p build && cd build
cmake -DCMAKE_BUILD_TYPE=Release -G Ninja ..
ninja -j$(nproc) lethe
```

## Structure

- `src/core/` — Core engine initialization, process management
- `src/browser/` — Browser state management (tabs, windows)
- `src/security/` — Content policies, sandboxing, TLS config
- `src/network/` — Network stack (HTTP/HTTPS, DoH)
- `renderer/` — Renderer process bindings (Skia + GPU)
- `browser/app/` — Main application entry point
- `include/` — Public headers by domain

## Configuration

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
lethe --csp-policy "custom-p..."
```

## License

Apache-2.0
